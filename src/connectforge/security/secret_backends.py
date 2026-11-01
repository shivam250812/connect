"""External secret managers.

Connectors never change: they keep writing `${secret:name}`. The platform decides where `name` is
looked up. Choose with CF_SECRETS_BACKEND:

  local      (default) encrypted file vault in data/ — works offline, good for demos
  hashicorp  HashiCorp Vault, KV v2 engine            VAULT_ADDR, VAULT_TOKEN, CF_VAULT_MOUNT, CF_VAULT_FIELD
  aws        AWS Secrets Manager                      AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
  env        environment variables CF_SECRET_<NAME>   (e.g. github_token -> CF_SECRET_GITHUB_TOKEN)

CF_SECRETS_PREFIX (e.g. "connectforge/") is prepended to the name for hashicorp and aws.

With an external manager, values are managed (and rotated) there, not in this UI. The platform still
enforces per-connector scoping, audits every read, redacts values from errors, and caches each value
for CF_SECRETS_CACHE_SECONDS (default 300) so rotation is picked up without hammering the manager.
"""

from __future__ import annotations

import json
import os
import re
import time
from typing import Dict, Optional, Tuple

import httpx

from connectforge.security.auth import sigv4_headers


class BackendError(LookupError):
    """The manager could not return the secret (missing, no permission, unreachable)."""


class SecretBackend:
    name = "base"
    writable = False

    def fetch(self, name: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError


class EnvBackend(SecretBackend):
    name = "environment variables"

    def fetch(self, name: str) -> str:
        var = "CF_SECRET_" + re.sub(r"[^A-Za-z0-9]", "_", name).upper()
        if var not in os.environ:
            raise BackendError(f"environment variable {var} is not set")
        return os.environ[var]


class HashiCorpVaultBackend(SecretBackend):
    """HashiCorp Vault KV v2: GET {addr}/v1/{mount}/data/{prefix}{name} -> data.data[field]."""

    name = "HashiCorp Vault"

    def __init__(self, addr: str, token: str, mount: str = "secret", field: str = "value", prefix: str = "",
                 transport: Optional[httpx.BaseTransport] = None, namespace: Optional[str] = None):
        if not addr or not token:
            raise ValueError("VAULT_ADDR and VAULT_TOKEN must be set for CF_SECRETS_BACKEND=hashicorp")
        self.addr, self.token, self.mount, self.field, self.prefix = addr.rstrip("/"), token, mount, field, prefix
        self.namespace = namespace
        self.client = httpx.Client(transport=transport, timeout=5)

    def fetch(self, name: str) -> str:
        headers = {"X-Vault-Token": self.token}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        try:
            r = self.client.get(f"{self.addr}/v1/{self.mount}/data/{self.prefix}{name}", headers=headers)
        except httpx.HTTPError as e:
            raise BackendError(f"HashiCorp Vault not reachable ({type(e).__name__})") from e
        if r.status_code == 404:
            raise BackendError(f"not found in HashiCorp Vault at {self.mount}/{self.prefix}{name}")
        if r.status_code == 403:
            raise BackendError("HashiCorp Vault denied access (check the token's policy)")
        if r.status_code != 200:
            raise BackendError(f"HashiCorp Vault returned HTTP {r.status_code}")
        data = (r.json().get("data") or {}).get("data") or {}
        if self.field not in data:
            raise BackendError(f"HashiCorp Vault secret {self.prefix}{name} has no field '{self.field}'")
        return str(data[self.field])


class AwsSecretsManagerBackend(SecretBackend):
    """AWS Secrets Manager GetSecretValue, signed with SigV4 (no boto3 needed)."""

    name = "AWS Secrets Manager"

    def __init__(self, region: str, access_key: str, secret_key: str, session_token: Optional[str] = None,
                 prefix: str = "", endpoint: Optional[str] = None, transport: Optional[httpx.BaseTransport] = None):
        if not (region and access_key and secret_key):
            raise ValueError("AWS_REGION, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set for CF_SECRETS_BACKEND=aws")
        self.region, self.access_key, self.secret_key, self.session_token = region, access_key, secret_key, session_token
        self.prefix = prefix
        self.endpoint = endpoint or f"https://secretsmanager.{region}.amazonaws.com/"
        self.client = httpx.Client(transport=transport, timeout=5)

    def fetch(self, name: str) -> str:
        body = json.dumps({"SecretId": f"{self.prefix}{name}"}).encode()
        headers = {"Content-Type": "application/x-amz-json-1.1", "X-Amz-Target": "secretsmanager.GetSecretValue"}
        if self.session_token:
            headers["X-Amz-Security-Token"] = self.session_token
        headers.update(sigv4_headers("POST", self.endpoint, headers, body, self.access_key, self.secret_key,
                                     self.region, "secretsmanager"))
        try:
            r = self.client.post(self.endpoint, content=body, headers=headers)
        except httpx.HTTPError as e:
            raise BackendError(f"AWS Secrets Manager not reachable ({type(e).__name__})") from e
        if r.status_code != 200:
            kind = (r.json().get("__type", "") if r.headers.get("content-type", "").startswith("application") else "")
            if "ResourceNotFound" in kind:
                raise BackendError(f"not found in AWS Secrets Manager: {self.prefix}{name}")
            if "AccessDenied" in kind or r.status_code in (400, 403) and "Signature" in kind:
                raise BackendError("AWS Secrets Manager denied access (check the IAM policy / credentials)")
            raise BackendError(f"AWS Secrets Manager returned HTTP {r.status_code} {kind}".strip())
        value = r.json().get("SecretString")
        if value is None:
            raise BackendError(f"{self.prefix}{name} has no SecretString (binary secrets are not supported)")
        return value


class CachedBackend:
    """Short-lived in-memory cache in front of a manager."""

    def __init__(self, backend: SecretBackend, ttl: float = 300):
        self.backend, self.ttl = backend, ttl
        self._cache: Dict[str, Tuple[str, float]] = {}

    @property
    def name(self) -> str:
        return self.backend.name

    def get(self, name: str) -> str:
        hit = self._cache.get(name)
        if hit and time.monotonic() < hit[1]:
            return hit[0]
        value = self.backend.fetch(name)
        self._cache[name] = (value, time.monotonic() + self.ttl)
        return value

    def known_values(self) -> Dict[str, str]:
        return {k: v for k, (v, _) in self._cache.items()}

    def forget(self, name: Optional[str] = None) -> bool:
        """Drop cached values (one or all); True if anything was cached."""
        if name is None:
            had = bool(self._cache)
            self._cache.clear()
            return had
        return self._cache.pop(name, None) is not None


def backend_from_env() -> Optional[CachedBackend]:
    kind = os.environ.get("CF_SECRETS_BACKEND", "local").strip().lower()
    prefix = os.environ.get("CF_SECRETS_PREFIX", "")
    ttl = float(os.environ.get("CF_SECRETS_CACHE_SECONDS", "300"))
    if kind in ("", "local"):
        return None
    if kind == "env":
        backend: SecretBackend = EnvBackend()
    elif kind in ("hashicorp", "vault"):
        backend = HashiCorpVaultBackend(os.environ.get("VAULT_ADDR", ""), os.environ.get("VAULT_TOKEN", ""),
                                        os.environ.get("CF_VAULT_MOUNT", "secret"), os.environ.get("CF_VAULT_FIELD", "value"),
                                        prefix, namespace=os.environ.get("VAULT_NAMESPACE"))
    elif kind == "aws":
        backend = AwsSecretsManagerBackend(os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION", ""),
                                           os.environ.get("AWS_ACCESS_KEY_ID", ""), os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
                                           os.environ.get("AWS_SESSION_TOKEN"), prefix)
    else:
        raise ValueError(f"unknown CF_SECRETS_BACKEND '{kind}' (use local, hashicorp, aws or env)")
    return CachedBackend(backend, ttl)
