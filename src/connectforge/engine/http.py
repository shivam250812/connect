"""Calling a source over HTTP (FR-1, FR-2, FR-7, FR-8): one request with credentials, the egress
allowlist, rate limiting (token bucket), and retries with backoff that honour Retry-After."""

from __future__ import annotations

import asyncio
import random
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Awaitable, Callable, Dict, List, Optional
from urllib.parse import urlsplit

import httpx

from connectforge.config.schema import ConnectorSpec
from connectforge.engine.errors import EgressBlocked, FetchError
from connectforge.security.auth import Authenticator, provider_message

Sleep = Callable[[float], Awaitable[None]]


# --- Rate limiting (FR-8) ---------------------------------------------------------------------


class TokenBucket:
    def __init__(self, rate: float, burst: int, sleep: Sleep = asyncio.sleep):
        self.rate, self.capacity = rate, float(burst)
        self.tokens, self.updated = float(burst), time.monotonic()
        self.sleep = sleep
        self._lock = asyncio.Lock()

    async def acquire(self) -> float:
        async with self._lock:
            now = time.monotonic()
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
            self.updated = now
            if self.tokens >= 1:
                self.tokens -= 1
                return 0.0
            wait = (1 - self.tokens) / self.rate
            await self.sleep(wait)
            self.tokens, self.updated = 0.0, time.monotonic()
            return wait


def retry_after_seconds(resp: httpx.Response) -> Optional[float]:
    ra = resp.headers.get("Retry-After")
    if ra:
        try:
            return max(float(ra), 0.0)
        except ValueError:
            try:
                return max((parsedate_to_datetime(ra) - datetime.now(timezone.utc)).total_seconds(), 0.0)
            except (TypeError, ValueError):
                pass
    reset = resp.headers.get("X-Rate-Limit-Reset") or resp.headers.get("X-RateLimit-Reset")
    if reset and reset.isdigit():
        return max(int(reset) - time.time(), 0.0)
    return None


@dataclass
class RunMetrics:
    pages: int = 0
    fetched: int = 0
    new: int = 0
    updated: int = 0
    unchanged: int = 0
    rejected: int = 0
    retries: int = 0
    throttled_ms: int = 0
    notes: List[str] = field(default_factory=list)
    fresh: List[dict] = field(default_factory=list)   # records seen for the first time in this run


# --- HTTP (FR-1, FR-2, FR-7) --------------------------------------------------------------------


class Fetcher:
    def __init__(self, spec: ConnectorSpec, client: httpx.AsyncClient, auth: Authenticator, bucket: TokenBucket,
                 metrics: RunMetrics, sleep: Sleep, on_block: Callable[[str], None], max_attempts: Optional[int] = None):
        self.spec, self.client, self.auth, self.bucket = spec, client, auth, bucket
        self.metrics, self.sleep, self.on_block = metrics, sleep, on_block
        self.max_attempts = max_attempts or spec.retry.max_attempts
        self.rng = random.Random()

    def check_egress(self, url: str) -> None:
        host = urlsplit(url).hostname
        if not self.spec.host_allowed(host):
            self.on_block(url)
            raise EgressBlocked(f"blocked request to '{host}' (not in allowed_hosts), credentials were not sent")

    def backoff(self, attempt: int) -> float:
        r = self.spec.retry
        delay = r.base_delay_seconds * 2 ** (attempt - 1)
        if r.jitter:
            delay *= 0.5 + self.rng.random() / 2
        return min(delay, r.max_delay_seconds)

    async def request(self, method: str, url: str, params: Dict[str, Any], body: Optional[dict]) -> httpx.Response:
        await self.auth.prepare(self.client)  # login / discovery (cached between runs)
        configured = self.spec.request.base_url.rstrip("/")
        if self.auth.base_url and url.startswith(configured):
            url = self.auth.base_url + url[len(configured):]  # discovered region-specific API host
        self.check_egress(url)
        r, last, refreshed = self.spec.retry, "", False
        for attempt in range(1, self.max_attempts + 1):
            self.metrics.throttled_ms += int(await self.bucket.acquire() * 1000)
            # secret refs inside query params / body are resolved per request (some XML APIs take credentials there)
            q = {k: self.auth.resolve(v) if isinstance(v, str) else v for k, v in params.items()} if params else None
            req = self.client.build_request(
                method, url, params=q, json=body,
                headers={k: self.auth.resolve(v) for k, v in self.spec.request.headers.items()},
                timeout=self.spec.request.timeout_seconds)
            await self.auth.apply(self.client, req)
            hint = None
            try:
                resp = await self.client.send(req, follow_redirects=False)
                self.client.cookies.clear()  # never let one connector's session cookie reach another
            except httpx.TimeoutException:
                last = "timeout"
            except httpx.TransportError as e:
                last = f"network error ({type(e).__name__}) reaching {req.url.host}"
                if re.search(r"nodename nor servname|Name or service not known|getaddrinfo|No address associated", str(e)):
                    last += ": host name not found, check base_url in the config"
                elif "refused" in str(e).lower():
                    last += ": connection refused, is the service running on that port?"
            else:
                code = resp.status_code
                if code == 401 and not refreshed and self.auth.invalidate():
                    refreshed, last = True, "HTTP 401 (token refreshed)"
                    continue
                if code in r.retry_on:
                    last, hint = f"HTTP {code}", retry_after_seconds(resp)
                elif 300 <= code < 400:
                    raise FetchError(f"HTTP {code} redirect refused, credentials are never sent to redirects")
                elif code in (401, 403):
                    hint = "invalid or expired credential" if code == 401 else \
                        "credential accepted but not allowed here (missing permission or wrong account/resource)"
                    raise FetchError(f"HTTP {code}: authentication failed ({hint}). Check the secret "
                                     f"({', '.join(self.spec.secret_names) or 'none configured'}). "
                                     f"Provider said: {provider_message(resp)}")
                elif code >= 400:
                    raise FetchError(f"HTTP {code}: {provider_message(resp)}")
                else:
                    return resp
            if attempt == self.max_attempts:
                break
            delay = min(hint, r.max_delay_seconds) if hint is not None else self.backoff(attempt)
            self.metrics.retries += 1
            why = "Retry-After" if hint is not None else "backoff"
            self.metrics.notes.append(f"{last}, retry {attempt} in {delay:g}s ({why})")
            await self.sleep(delay)
        raise FetchError(f"failed after {self.max_attempts} attempts: {last}")
