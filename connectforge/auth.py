"""Authentication strategies. Secret references are resolved through the vault at request time,
so plaintext credentials live only in memory for the duration of a request."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets as pysecrets
import time
from base64 import b64encode, urlsafe_b64encode
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional
from urllib.parse import parse_qsl, quote, urlsplit

import httpx

from .mapping import get_path
from .spec import SECRET_REF, AuthSpec
from .vault import SecretMissing

ENV_REF = re.compile(r"\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}")


class AuthError(RuntimeError):
    pass


Resolver = Callable[[Optional[str]], Optional[str]]  # resolves "${secret:x}" -> value


def _env(name: str) -> str:
    if name not in os.environ:
        raise SecretMissing(f"environment variable '{name}' is not set")
    return os.environ[name]


def make_resolver(get_secret: Callable[[str], str]) -> Resolver:
    """Resolve `${secret:name}` from the vault and `${env:NAME}` from the environment, at request time."""
    def resolve(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = SECRET_REF.sub(lambda m: get_secret(m.group(1)), value)
        return ENV_REF.sub(lambda m: _env(m.group(1)), value)
    return resolve


# --- AWS Signature Version 4 ---------------------------------------------------------------------


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4_headers(method: str, url: str, headers: Dict[str, str], body: bytes, access_key: str,
                  secret_key: str, region: str, service: str, now: Optional[datetime] = None) -> Dict[str, str]:
    """Return the headers to add for an AWS SigV4-signed request."""
    now = now or datetime.now(timezone.utc)
    parts = urlsplit(url)
    amz_date, datestamp = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body).hexdigest()
    to_sign = {k.lower(): str(v).strip() for k, v in headers.items()
               if k.lower() in ("content-type",) or k.lower().startswith("x-amz-")}
    to_sign.update({"host": parts.netloc, "x-amz-date": amz_date})
    signed = sorted(to_sign)
    canonical_query = "&".join(
        f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}"
        for k, v in sorted(parse_qsl(parts.query, keep_blank_values=True)))
    canonical_request = "\n".join([
        method.upper(), quote(parts.path or "/", safe="/-_.~"), canonical_query,
        "".join(f"{k}:{to_sign[k]}\n" for k in signed), ";".join(signed), payload_hash])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                                hashlib.sha256(canonical_request.encode()).hexdigest()])
    key = _hmac(_hmac(_hmac(_hmac(f"AWS4{secret_key}".encode(), datestamp), region), service), "aws4_request")
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return {
        "x-amz-date": amz_date,
        "Authorization": f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
                         f"SignedHeaders={';'.join(signed)}, Signature={signature}",
    }


# --- vendor-specific credential helpers (kept tiny and isolated) ----------------------------------------


def zscaler_obfuscated_key(api_key: str, timestamp_ms: str) -> str:
    """Zscaler ZIA requires the API key obfuscated with the login timestamp (algorithm from their docs)."""
    high = timestamp_ms[-6:]
    low = str(int(high) >> 1).zfill(6)
    return "".join(api_key[int(c)] for c in high) + "".join(api_key[int(c) + 2] for c in low)


def cortex_advanced_headers(api_key: str, key_id: str, nonce: Optional[str] = None,
                            timestamp_ms: Optional[str] = None) -> Dict[str, str]:
    """Palo Alto Cortex XDR/XSIAM 'advanced' API keys: sha256(key + nonce + timestamp), fresh per request."""
    nonce = nonce or pysecrets.token_hex(32)
    timestamp_ms = timestamp_ms or str(int(time.time() * 1000))
    digest = hashlib.sha256(f"{api_key}{nonce}{timestamp_ms}".encode()).hexdigest()
    return {"x-xdr-timestamp": timestamp_ms, "x-xdr-nonce": nonce, "x-xdr-auth-id": key_id, "Authorization": digest}


def google_jwt_assertion(key_json: str, scope: str, now: Optional[int] = None) -> tuple:
    """Sign a service-account JWT (RS256) for Google's OAuth token endpoint. Returns (assertion, token_uri)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding

    key = json.loads(key_json)
    now = now or int(time.time())
    b64 = lambda obj: urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=")  # noqa: E731
    token_uri = key.get("token_uri", "https://oauth2.googleapis.com/token")
    signing_input = b64({"alg": "RS256", "typ": "JWT", "kid": key.get("private_key_id", "")}) + b"." + b64(
        {"iss": key["client_email"], "scope": scope, "aud": token_uri, "iat": now, "exp": now + 3600})
    private_key = serialization.load_pem_private_key(key["private_key"].encode(), password=None)
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return (signing_input + b"." + urlsafe_b64encode(signature).rstrip(b"=")).decode(), token_uri


# --- Authenticator ----------------------------------------------------------------------------------


class Authenticator:
    """Attaches credentials to requests. Short-lived tokens (OAuth2, token exchange, Google JWT) are cached
    until shortly before expiry and refreshed once on a 401. Login calls use a throw-away HTTP client so
    session cookies never leak into the shared client, and they pass the same egress allowlist."""

    def __init__(self, spec: AuthSpec, resolve: Resolver,
                 host_allowed: Callable[[Optional[str]], bool] = lambda h: True,
                 client_factory: Optional[Callable[[], httpx.AsyncClient]] = None):
        self.spec = spec
        self.resolve = resolve
        self.host_allowed = host_allowed
        self.client_factory = client_factory or (lambda: httpx.AsyncClient(timeout=30))
        self._token: Optional[str] = None
        self._expiry = 0.0
        self.base_url: Optional[str] = None        # set by discovery
        self.extra_headers: Dict[str, str] = {}    # set by discovery (e.g. X-Tenant-ID)
        self._discovered = False

    def invalidate(self) -> bool:
        """Drop cached short-lived credentials; returns True if a refresh is possible."""
        if self.spec.type in ("oauth2_client_credentials", "token_exchange", "google_service_account"):
            self._token, self._discovered = None, False
            return True
        return False

    def _check(self, url: str) -> None:
        if not self.host_allowed(urlsplit(url).hostname):
            raise AuthError(f"login/discovery host '{urlsplit(url).hostname}' is not in allowed_hosts")

    def _resolve_tree(self, obj: Any, now_ms: str) -> Any:
        if isinstance(obj, str):
            obj = obj.replace("${now_ms}", now_ms)
            obj = re.sub(r"\$\{zscaler_key:([A-Za-z0-9_.-]+)\}",
                         lambda m: zscaler_obfuscated_key(self.resolve(f"${{secret:{m.group(1)}}}"), now_ms), obj)
            return self.resolve(obj)
        if isinstance(obj, dict):
            return {k: self._resolve_tree(v, now_ms) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._resolve_tree(v, now_ms) for v in obj]
        return obj

    async def _cached(self, fetch) -> str:
        if self._token and time.monotonic() < self._expiry:
            return self._token
        token, ttl = await fetch()
        self._token, self._expiry = token, time.monotonic() + max(int(ttl) - 30, 30)
        return token

    async def _oauth(self) -> tuple:
        s = self.spec
        self._check(s.token_url)
        data = {"grant_type": "client_credentials", **s.extra}
        if s.scope:
            data["scope"] = s.scope
        cid, csecret = self.resolve(s.client_id), self.resolve(s.client_secret)
        auth = None
        if s.client_auth == "body":
            data.update(client_id=cid, client_secret=csecret)
        else:
            auth = (cid, csecret)
        async with self.client_factory() as c:
            resp = await c.post(s.token_url, data=data, auth=auth)
        if resp.status_code != 200:
            raise AuthError(f"token endpoint returned HTTP {resp.status_code}")
        body = resp.json()
        return body["access_token"], body.get("expires_in", 300)

    async def _google(self) -> tuple:
        assertion, token_uri = google_jwt_assertion(self.resolve(self.spec.value), self.spec.scope)
        self._check(token_uri)
        async with self.client_factory() as c:
            resp = await c.post(token_uri, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                 "assertion": assertion})
        if resp.status_code != 200:
            raise AuthError(f"Google token endpoint returned HTTP {resp.status_code}: {resp.text[:200]}")
        body = resp.json()
        return body["access_token"], body.get("expires_in", 3600)

    async def _login(self) -> tuple:
        lg = self.spec.login
        self._check(lg.url)
        now_ms = str(int(time.time() * 1000))
        kwargs: Dict[str, Any] = {"headers": self._resolve_tree(lg.headers, now_ms)}
        if lg.json_body is not None:
            kwargs["json"] = self._resolve_tree(lg.json_body, now_ms)
        if lg.form is not None:
            kwargs["data"] = self._resolve_tree(lg.form, now_ms)
        if lg.basic_username:
            kwargs["auth"] = (self.resolve(lg.basic_username), self.resolve(lg.basic_password or ""))
        async with self.client_factory() as c:
            resp = await c.request(lg.method, lg.url, **kwargs)
        if resp.status_code >= 400:
            raise AuthError(f"login returned HTTP {resp.status_code}: {resp.text[:200]}")
        if lg.token_from == "header":
            token = resp.headers.get(lg.token_path)
        elif lg.token_from == "cookie":
            token = resp.cookies.get(lg.token_path)
        else:
            try:
                token = get_path(resp.json(), lg.token_path)
            except ValueError:
                token = None
        if not token:
            raise AuthError(f"login succeeded but no token found at {lg.token_from} '{lg.token_path}'")
        ttl = lg.ttl_seconds
        if lg.expires_in_path and lg.token_from == "body":
            ttl = int(get_path(resp.json(), lg.expires_in_path) or ttl)
        return str(token), ttl

    async def _discover(self, client: httpx.AsyncClient, auth_headers: Dict[str, str]) -> None:
        d = self.spec.discover
        self._check(d.url)
        resp = await client.get(d.url, headers=auth_headers)
        if resp.status_code != 200:
            raise AuthError(f"discovery call returned HTTP {resp.status_code}")
        data = resp.json()
        if d.base_url_path:
            base = get_path(data, d.base_url_path)
            if not base or not self.host_allowed(urlsplit(base).hostname):
                raise AuthError(f"discovered API host '{base}' is not in allowed_hosts")
            self.base_url = base.rstrip("/")
        self.extra_headers = {h: str(get_path(data, p)) for h, p in d.headers.items()}
        self._discovered = True

    async def credential_headers(self, client: httpx.AsyncClient) -> Dict[str, str]:
        """Headers carrying the (possibly freshly obtained) credential, before discovery headers."""
        s, t = self.spec, self.spec.type
        if t == "oauth2_client_credentials":
            return {"Authorization": f"Bearer {await self._cached(self._oauth)}"}
        if t == "google_service_account":
            return {"Authorization": f"Bearer {await self._cached(self._google)}"}
        if t == "token_exchange":
            token = await self._cached(self._login)
            if s.login.token_from == "cookie":
                return {"Cookie": f"{s.login.token_path}={token}"}
            prefix = f"{s.scheme} " if s.scheme and s.header.lower() == "authorization" else ""
            return {s.header: prefix + token}
        return {}

    async def prepare(self, client: httpx.AsyncClient) -> None:
        """Run login + discovery before the first request of a run (cached afterwards)."""
        if self.spec.discover and not self._discovered:
            await self._discover(client, await self.credential_headers(client))

    async def apply(self, client: httpx.AsyncClient, request: httpx.Request) -> None:
        try:
            await self._apply(client, request)
        except SecretMissing:
            if not self.spec.optional:
                raise
            # optional credential (e.g. NVD API key): call anonymously at the lower rate limit

    async def _apply(self, client: httpx.AsyncClient, request: httpx.Request) -> None:
        s, t = self.spec, self.spec.type
        request.headers.update(self.extra_headers)
        if t == "none":
            return
        if t == "api_key":
            if s.in_ == "query":
                request.url = request.url.copy_add_param(s.param, self.resolve(s.value))
            else:
                request.headers[s.header] = self.resolve(s.value)
        elif t == "bearer":
            request.headers["Authorization"] = f"{s.scheme} {self.resolve(s.token)}"
        elif t == "basic":
            raw = f"{self.resolve(s.username)}:{self.resolve(s.password)}".encode()
            request.headers["Authorization"] = "Basic " + b64encode(raw).decode()
        elif t in ("oauth2_client_credentials", "google_service_account", "token_exchange"):
            request.headers.update(await self.credential_headers(client))
        elif t == "cortex_advanced":
            request.headers.update(cortex_advanced_headers(self.resolve(s.value), s.key_id))
        elif t == "aws_sigv4":
            body = request.content or b""
            request.headers.update(sigv4_headers(
                request.method, str(request.url), dict(request.headers), body,
                self.resolve(s.access_key_id), self.resolve(s.secret_access_key), s.region, s.service or "execute-api"))
