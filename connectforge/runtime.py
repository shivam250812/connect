"""The platform engine — identical behaviour for every connector:

  rate limit (token bucket) -> egress allowlist -> auth -> request -> retry with backoff
  (1 s, 2 s, 4 s; honours Retry-After on 429) -> pagination -> mapping -> quarantine bad
  records -> upsert into users/devices/events -> checkpoint -> health + alerts.
"""

from __future__ import annotations

import asyncio
import csv
import json
import os
import random
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

import httpx

from .auth import AuthError, Authenticator, make_resolver
from .mapping import MappingError, get_path, map_record, parse_cef, parse_datetime, set_path, xml_to_dict
from .mapping import preview as map_preview
from .spec import ConnectorSpec, CursorSpec, SpecError, parse_spec
from .store import Store, now_iso
from .vault import SecretAccessDenied, SecretMissing, Vault

Sleep = Callable[[float], Awaitable[None]]
ALERT_AFTER_FAILURES = 3


class FetchError(RuntimeError):
    pass


class EgressBlocked(FetchError):
    pass


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
            raise EgressBlocked(f"blocked request to '{host}' (not in allowed_hosts) — credentials were not sent")

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
                last = f"network error ({type(e).__name__})"
            else:
                code = resp.status_code
                if code == 401 and not refreshed and self.auth.invalidate():
                    refreshed, last = True, "HTTP 401 (token refreshed)"
                    continue
                if code in r.retry_on:
                    last, hint = f"HTTP {code}", retry_after_seconds(resp)
                elif 300 <= code < 400:
                    raise FetchError(f"HTTP {code} redirect refused — credentials never follow redirects")
                elif code in (401, 403):
                    hint = "invalid or expired credential" if code == 401 else \
                        "credential accepted but not allowed here (missing permission or wrong account/resource)"
                    raise FetchError(f"HTTP {code}: authentication failed — {hint}; check the secret "
                                     f"({', '.join(self.spec.secret_names) or 'none configured'}). "
                                     f"Provider said: {resp.text[:300]}")
                elif code >= 400:
                    raise FetchError(f"HTTP {code}: {resp.text[:200]}")
                else:
                    return resp
            if attempt == self.max_attempts:
                break
            delay = min(hint, r.max_delay_seconds) if hint is not None else self.backoff(attempt)
            self.metrics.retries += 1
            why = "Retry-After" if hint is not None else "backoff"
            self.metrics.notes.append(f"{last} → retry {attempt} in {delay:g}s ({why})")
            await self.sleep(delay)
        raise FetchError(f"failed after {self.max_attempts} attempts: {last}")


def format_cursor(dt: datetime, spec: CursorSpec) -> Any:
    dt = dt.astimezone(timezone.utc)
    if spec.format == "epoch":
        value: Any = int(dt.timestamp())
    elif spec.format == "epoch_ms":
        value = int(dt.timestamp() * 1000)
    elif spec.format == "date":
        value = dt.strftime("%Y-%m-%d")
    elif spec.format == "iso":
        value = dt.isoformat()
    else:
        value = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"
    return spec.template.replace("{value}", str(value)) if spec.template != "{value}" else value


def initial_cursor(spec: CursorSpec) -> datetime:
    m = re.fullmatch(r"-(\d+)([smhd])", spec.initial.strip())
    if m:
        unit = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m.group(2)]
        return datetime.now(timezone.utc) - timedelta(**{unit: int(m.group(1))})
    return parse_datetime(spec.initial)


async def fetch_pages(spec: ConnectorSpec, fetcher: Fetcher, cursor: Optional[datetime]) -> AsyncIterator[List[Any]]:
    """Pagination (FR-3): link header, next URL, next token, page number or offset."""
    req, p = spec.request, spec.pagination
    url = req.base_url.rstrip("/") + ("/" + req.path.lstrip("/") if req.path else "")
    params = dict(req.params)
    body = json.loads(json.dumps(req.body)) if req.body is not None else None  # deep copy: never mutate the spec
    if req.method == "POST" and body is None:
        body = {}

    def put(where: str, key: str, value: Any) -> None:
        if where == "body" and body is not None:
            set_path(body, key, value)  # nested paths: request_data.search_from, variables.after
        else:
            params[key] = value

    if spec.cursor and cursor is not None:
        put(spec.cursor.param_in, spec.cursor.param, format_cursor(cursor, spec.cursor))
        if spec.cursor.end_param:
            put(spec.cursor.param_in, spec.cursor.end_param, format_cursor(datetime.now(timezone.utc), spec.cursor))
    page, offset = p.start_page, 0
    if p.type == "page_number":
        put(p.params_in, p.page_param, page)
    if p.type in ("page_number", "offset", "link_header", "next_token") and p.page_size_param:
        put(p.params_in, p.page_size_param, p.page_size)
    if p.type == "offset":
        put(p.params_in, p.offset_param, 0)
        if p.offset_end_param:
            put(p.params_in, p.offset_end_param, p.page_size)
    for _ in range(p.max_pages):
        resp = await fetcher.request(req.method, url, params, body)
        try:
            data = xml_to_dict(resp.text) if req.response_format == "xml" else resp.json()
        except (ValueError, MappingError) as e:
            raise FetchError(f"response body is not valid {req.response_format.upper()}: {e}") from e
        records = get_path(data, spec.records)
        if records is None:
            records = []
        if not isinstance(records, list):
            raise FetchError(f"'records: {spec.records}' did not resolve to a list")
        yield records
        if p.type == "none":
            return
        if p.has_more_path and not get_path(data, p.has_more_path):
            return
        if p.type in ("link_header", "next_url"):
            nxt = resp.links.get("next", {}).get("url") if p.type == "link_header" else get_path(data, p.token_path)
            if not nxt:
                return
            url, params = urljoin(str(resp.url), nxt), {}
        elif p.type == "next_token":
            token = get_path(data, p.token_path)
            if not token:
                return
            put(p.token_in, p.token_param, token)
        elif p.type == "page_number":
            if len(records) < p.page_size or not records:
                return
            page += 1
            put(p.params_in, p.page_param, page)
        elif p.type == "offset":
            offset += len(records)
            total = get_path(data, p.total_path) if p.total_path else None
            if not records or (total is not None and offset >= int(total)) or \
                    (total is None and len(records) < p.page_size):
                return
            put(p.params_in, p.offset_param, offset)
            if p.offset_end_param:
                put(p.params_in, p.offset_end_param, offset + p.page_size)
    fetcher.metrics.notes.append(f"stopped at max_pages={p.max_pages}; the rest is fetched next run")


# --- Files ----------------------------------------------------------------------------------------

_KV = re.compile(r'([A-Za-z_][\w.-]*)=("(?:[^"\\]|\\.)*"|\S*)')


def parse_line(line: str, spec: ConnectorSpec) -> Tuple[Optional[dict], Optional[str]]:
    f = spec.file
    try:
        if f.format == "cef":
            return parse_cef(line), None
        if f.format == "jsonl":
            obj = json.loads(line)
            return (obj, None) if isinstance(obj, dict) else (None, "JSON line is not an object")
        if f.format == "kv":
            pairs = {k: v[1:-1] if v.startswith('"') else v for k, v in _KV.findall(line)}
            return (pairs, None) if len(pairs) >= 2 else (None, "no key=value pairs found")
        if f.format == "regex":
            m = re.match(f.pattern, line)
            return (m.groupdict(), None) if m else (None, "line does not match pattern")
        row = next(csv.reader([line], delimiter=f.delimiter))
        if len(row) != len(f.columns):
            return None, f"expected {len(f.columns)} columns, got {len(row)}"
        return dict(zip(f.columns, row)), None
    except (json.JSONDecodeError, re.error, csv.Error, MappingError) as e:
        return None, f"parse error: {e}"


def read_new_lines(path: Path, offset: int, max_bytes: int) -> Tuple[List[str], int, bool]:
    size = path.stat().st_size
    rotated = offset > size
    if rotated:
        offset = 0
    with path.open("rb") as fh:
        fh.seek(offset)
        chunk = fh.read(max_bytes)
    chunk = chunk[:chunk.rfind(b"\n") + 1]
    return chunk.decode("utf-8", "replace").splitlines(), offset + len(chunk), rotated


# --- Platform ---------------------------------------------------------------------------------------


@dataclass
class ConnectorState:
    spec: ConnectorSpec
    bucket: TokenBucket
    auth: Authenticator
    paused: bool = False
    running: bool = False
    consecutive_failures: int = 0
    next_run: float = 0.0
    last_run: Optional[dict] = None
    last_success_at: Optional[str] = None
    last_notes: List[str] = field(default_factory=list)
    alerted: bool = False
    path: Optional[Path] = None       # the YAML file this connector came from


class Platform:
    def __init__(self, connectors_dir: Path, data_dir: Path, transport: Optional[httpx.AsyncBaseTransport] = None,
                 sleep: Sleep = asyncio.sleep, file_roots: Optional[List[Path]] = None, max_concurrency: int = 8,
                 alert_transport: Optional[httpx.AsyncBaseTransport] = None):
        self.connectors_dir = Path(connectors_dir)
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.data_dir / "connectforge.db")
        self.vault = Vault(self.data_dir / "vault.json", audit=self.store.audit)
        self.transport, self.sleep, self.alert_transport = transport, sleep, alert_transport
        self.file_roots = [p.resolve() for p in (file_roots or [self.data_dir / "feeds"])]
        self.states: Dict[str, ConnectorState] = {}
        self.load_errors: Dict[str, List[str]] = {}
        self._sem = asyncio.Semaphore(max_concurrency)
        self._client: Optional[httpx.AsyncClient] = None
        self._loop_task: Optional[asyncio.Task] = None
        self._tasks: set = set()

    # --- lifecycle -------------------------------------------------------------------------------

    def _make_state(self, spec: ConnectorSpec) -> ConnectorState:
        resolve = make_resolver(lambda name: self.vault.get(name, spec.id, spec.secret_names))
        return ConnectorState(spec=spec, bucket=TokenBucket(spec.rate_limit.requests_per_second,
                                                            spec.rate_limit.burst, self.sleep),
                              auth=Authenticator(spec.auth, resolve, spec.host_allowed,
                                                 client_factory=lambda: httpx.AsyncClient(
                                                     transport=self.transport, timeout=30, follow_redirects=False)))

    def load_dir(self, extra_dirs: Optional[List[Path]] = None) -> None:
        """Load every connector file. New connectors from the UI are saved to the first directory."""
        self.connectors_dir.mkdir(parents=True, exist_ok=True)
        paths = [p for d in [self.connectors_dir, *(extra_dirs or [])] if Path(d).exists()
                 for p in sorted(Path(d).glob("*.y*ml"))]
        for path in paths:
            try:
                spec = parse_spec(path.read_text())
            except SpecError as e:
                self.load_errors[path.name] = e.errors
                continue
            self.states[spec.id] = self._make_state(spec)
            self.states[spec.id].path = path

    def add(self, text: str, actor: str = "admin", persist: bool = True) -> ConnectorSpec:
        spec = parse_spec(text)
        old = self.states.get(spec.id)
        path = None
        if persist:
            self.connectors_dir.mkdir(parents=True, exist_ok=True)
            path = old.path if old and old.path else self.connectors_dir / f"{spec.id}.yaml"
            path.write_text(text)
        self.states[spec.id] = self._make_state(spec)
        self.states[spec.id].path = path
        self.store.audit(actor, "connector.updated" if old else "connector.added", spec.id)
        return spec

    def remove(self, cid: str, actor: str = "admin") -> Optional[str]:
        """Stop the connector and archive its YAML to data/removed/ (stored records are kept)."""
        st = self.states.pop(cid, None)
        archived = None
        if st and st.path and st.path.exists():
            dest_dir = self.data_dir / "removed"
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / st.path.name
            if dest.exists():
                dest = dest_dir / f"{st.path.stem}-{int(time.time())}{st.path.suffix}"
            st.path.replace(dest)
            archived = str(dest)
        self.store.audit(actor, "connector.removed", f"{cid} (config archived to {archived})" if archived else cid)
        return archived

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(transport=self.transport, follow_redirects=False,
                                             headers={"User-Agent": "ConnectForge/0.2"})
        return self._client

    def _resolve_file(self, spec: ConnectorSpec) -> Path:
        path = Path(spec.file.path)
        path = (path if path.is_absolute() else Path.cwd() / path).resolve()
        if not any(path.is_relative_to(root) for root in self.file_roots):
            raise FetchError(f"file path outside permitted feed directories {[str(r) for r in self.file_roots]}")
        if not path.exists():
            raise FetchError(f"file not found: {spec.file.path}")
        return path

    # --- running ----------------------------------------------------------------------------------

    def _ingest(self, records: List[Any], spec: ConnectorSpec, run_id: int, m: RunMetrics) -> List[Any]:
        good_raw, rows = [], []
        for rec in records:
            row, why = map_record(rec, spec)
            if why:
                m.rejected += 1
                self.store.quarantine(spec.id, run_id, why, rec)
            else:
                good_raw.append(rec)
                rows.append(row)
        new, updated, unchanged = self.store.upsert(spec.entity, spec.id, rows)
        m.new += new
        m.updated += updated
        m.unchanged += unchanged
        return good_raw

    async def _run_http(self, st: ConnectorState, run_id: int, m: RunMetrics) -> None:
        spec = st.spec
        saved = self.store.get_cursor(spec.id)
        cursor = (parse_datetime(saved) if saved else initial_cursor(spec.cursor)) if spec.cursor else None
        newest = cursor
        fetcher = Fetcher(spec, self.client, st.auth, st.bucket, m, self.sleep,
                          on_block=lambda url: self.store.audit(spec.id, "egress.blocked", url))
        async for records in fetch_pages(spec, fetcher, cursor):
            m.pages += 1
            m.fetched += len(records)
            for rec in self._ingest(records, spec, run_id, m):
                if spec.cursor:
                    try:
                        ts = parse_datetime(get_path(rec, spec.cursor.field))
                        newest = ts if newest is None or ts > newest else newest
                    except (ValueError, TypeError):
                        pass
        if spec.cursor and newest is not None:
            self.store.set_cursor(spec.id, newest.isoformat())

    async def _run_file(self, st: ConnectorState, run_id: int, m: RunMetrics) -> None:
        spec = st.spec
        path = self._resolve_file(spec)
        offset = int(self.store.get_cursor(spec.id) or 0)
        lines, new_offset, rotated = read_new_lines(path, offset, spec.file.max_bytes_per_run)
        if rotated:
            m.notes.append("file rotated/truncated — reading from start")
        m.pages, m.fetched = (1 if lines else 0), len(lines)
        parsed = []
        line_filter = re.compile(spec.file.filter) if spec.file.filter else None
        for line in lines:
            if not line.strip() or (line_filter and not line_filter.search(line)):
                continue  # shared syslog files: other vendors' lines are not ours (and not errors)
            rec, why = parse_line(line, spec)
            if why:
                m.rejected += 1
                self.store.quarantine(spec.id, run_id, why, line)
            else:
                parsed.append(rec)
        self._ingest(parsed, spec, run_id, m)
        self.store.set_cursor(spec.id, str(new_offset))

    async def run(self, cid: str, trigger: str = "schedule") -> dict:
        st = self.states[cid]
        if st.running:
            return {"skipped": "already running"}
        st.running = True
        m = RunMetrics()
        run_id = self.store.start_run(cid, trigger)
        status, error, started = "ok", None, time.monotonic()
        try:
            async with self._sem:
                await (self._run_http(st, run_id, m) if st.spec.kind == "http" else self._run_file(st, run_id, m))
        except (FetchError, AuthError, SecretMissing, SecretAccessDenied) as e:
            status, error = "error", str(e)
        except Exception as e:  # one connector can never take the platform down
            status, error = "error", f"{type(e).__name__}: {e}"
        finally:
            error = self.vault.redact(error) if error else None
            counters = {k: v for k, v in asdict(m).items() if k != "notes"}
            st.last_notes = [self.vault.redact(n) for n in m.notes[-10:]]
            self.store.finish_run(run_id, status=status, error=error, **counters)
            st.running = False
            st.last_run = {"id": run_id, "status": status, "error": error, "trigger": trigger,
                           "finished_at": now_iso(), "duration_ms": int((time.monotonic() - started) * 1000),
                           **counters}
            if status == "ok":
                if st.alerted:
                    await self._alert(st, "recovered", f"✅ {st.spec.name} recovered after "
                                                       f"{st.consecutive_failures} failed runs")
                st.consecutive_failures, st.alerted = 0, False
                st.last_success_at = st.last_run["finished_at"]
            else:
                st.consecutive_failures += 1
                if st.consecutive_failures >= ALERT_AFTER_FAILURES and not st.alerted:
                    st.alerted = True
                    await self._alert(st, "failing", f"🔴 {st.spec.name} failed {st.consecutive_failures} runs "
                                                     f"in a row. Last error: {error}")
            st.next_run = time.monotonic() + self.next_delay(st)
        return st.last_run

    @staticmethod
    def next_delay(st: ConnectorState) -> float:
        base = st.spec.schedule.seconds
        if st.consecutive_failures >= ALERT_AFTER_FAILURES:  # circuit open: back off, keep probing
            return min(base * 2 ** min(st.consecutive_failures - 2, 6), 3600)
        return base

    # --- alerts (B-4) -------------------------------------------------------------------------------

    def _webhook_url(self) -> Optional[str]:
        url = os.environ.get("CF_ALERT_WEBHOOK")
        if url:
            return url
        try:
            return self.vault.get("alert_webhook", "alerts", ["alert_webhook"])
        except (SecretMissing, SecretAccessDenied):
            return None

    async def _alert(self, st: ConnectorState, kind: str, message: str) -> None:
        url, delivered = self._webhook_url(), "logged only (no webhook configured)"
        if url:
            try:
                async with httpx.AsyncClient(transport=self.alert_transport, timeout=5) as c:
                    r = await c.post(url, json={"text": message})  # Slack/Teams/Discord-compatible
                delivered = f"webhook HTTP {r.status_code}"
            except httpx.HTTPError as e:
                delivered = f"webhook failed ({type(e).__name__})"
        self.store.add_alert(st.spec.id, kind, message, delivered)
        self.store.audit(st.spec.id, f"alert.{kind}", delivered)

    # --- test connection (B-3) & preview -------------------------------------------------------------

    def _spec_and_state(self, cid_or_yaml: str) -> Tuple[ConnectorSpec, ConnectorState]:
        if cid_or_yaml in self.states:
            st = self.states[cid_or_yaml]
            return st.spec, st
        spec = parse_spec(cid_or_yaml)
        return spec, self._make_state(spec)

    async def test_connection(self, cid_or_yaml: str) -> dict:
        """One authenticated request, no retries, nothing stored: can we log in and read data?"""
        spec, st = self._spec_and_state(cid_or_yaml)
        started = time.monotonic()
        m = RunMetrics()
        try:
            if spec.kind == "file":
                path = self._resolve_file(spec)
                return {"ok": True, "connector": spec.id, "detail": f"file readable ({path.stat().st_size} bytes)",
                        "latency_ms": int((time.monotonic() - started) * 1000)}
            fetcher = Fetcher(spec, self.client, st.auth, st.bucket, m, self.sleep, on_block=lambda url: None,
                              max_attempts=1)
            cursor = initial_cursor(spec.cursor) if spec.cursor else None
            async for records in fetch_pages(spec, fetcher, cursor):
                return {"ok": True, "connector": spec.id, "latency_ms": int((time.monotonic() - started) * 1000),
                        "detail": ("connected (no login needed)" if spec.auth.type == "none" else "authenticated")
                                  + f" · first page returned {len(records)} record(s)",
                        "auth": spec.auth.type}
            return {"ok": True, "connector": spec.id, "detail": "no data"}
        except (FetchError, AuthError, SecretMissing, SecretAccessDenied, OSError) as e:
            return {"ok": False, "connector": spec.id, "latency_ms": int((time.monotonic() - started) * 1000),
                    "detail": self.vault.redact(str(e))}

    async def preview(self, cid_or_yaml: str, limit: int = 5) -> dict:
        spec, st = self._spec_and_state(cid_or_yaml)
        m = RunMetrics()
        if spec.kind == "file":
            path = self._resolve_file(spec)
            lines, _, _ = read_new_lines(path, max(path.stat().st_size - 6000, 0), 6000)
            records = []
            for line in lines[1:limit + 1]:
                rec, why = parse_line(line, spec)
                records.append(rec if rec is not None else {"_unparsed": line, "_error": why})
        else:
            fetcher = Fetcher(spec, self.client, st.auth, st.bucket, m, self.sleep, on_block=lambda url: None)
            cursor = initial_cursor(spec.cursor) if spec.cursor else None
            records = []
            async for page in fetch_pages(spec, fetcher, cursor):
                records = page
                break
        return {"connector": spec.id, "entity": spec.entity, "samples": map_preview(records, spec, limit),
                "notes": m.notes}

    # --- scheduler (FR-4) ---------------------------------------------------------------------------

    async def _tick(self) -> None:
        now = time.monotonic()
        for cid, st in list(self.states.items()):
            if st.spec.enabled and not st.paused and not st.running and now >= st.next_run:
                st.next_run = now + 3600
                task = asyncio.create_task(self.run(cid))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)

    async def _loop(self) -> None:
        while True:
            await self._tick()
            await asyncio.sleep(1)

    def start(self) -> None:
        self._loop_task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._loop_task:
            self._loop_task.cancel()
        for t in list(self._tasks):
            t.cancel()
        if self._client:
            await self._client.aclose()

    # --- health (FR-10) -----------------------------------------------------------------------------

    def health(self, cid: str) -> dict:
        st = self.states[cid]
        lr = st.last_run
        reasons: List[str] = []
        if not st.spec.enabled:
            status = "disabled"
        elif st.paused:
            status = "paused"
        elif not lr:
            status = "running" if st.running else "pending"
        elif st.consecutive_failures >= ALERT_AFTER_FAILURES:
            status, reasons = "failing", [f"{st.consecutive_failures} failed runs in a row — alert sent, backing off"]
        elif lr["status"] == "error":
            status, reasons = "degraded", ["last run failed"]
        else:
            status = "healthy"
            if lr["fetched"] and lr["rejected"] / lr["fetched"] > 0.2:
                status, reasons = "degraded", [f"{lr['rejected']} of {lr['fetched']} records rejected"]
        next_in = max(st.next_run - time.monotonic(), 0) if st.next_run else 0
        return {
            "id": cid, "name": st.spec.name, "description": st.spec.description, "kind": st.spec.kind,
            "entity": st.spec.entity, "source": st.spec.source_name, "status": status, "reasons": reasons,
            "running": st.running, "paused": st.paused, "last_run": lr, "last_success_at": st.last_success_at,
            "consecutive_failures": st.consecutive_failures,
            "next_run_in_s": None if st.paused or not st.spec.enabled else round(next_in),
            "every_seconds": st.spec.schedule.seconds, "notes": st.last_notes,
            "cursor": self.store.get_cursor(cid), "totals": self.store.totals(cid),
            "records_stored": self.store.count_for_connector(st.spec.entity, cid),
            "auth": st.spec.auth.type, "pagination": st.spec.pagination.type,
            "hosts": sorted(st.spec.egress_hosts()) if st.spec.kind == "http" else [],
            "secrets": st.spec.secret_names,
        }
