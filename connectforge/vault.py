"""Secrets vault — the INC-05 lesson: integration tokens are the crown jewels.

* Encrypted at rest (Fernet / AES-128-CBC + HMAC) with a master key kept outside the vault.
* Write-only through the API: values are never returned, logged or shown.
* Scoped: a connector can read only the secrets its spec declares; every read is audited.
* Redaction: any secret value that ends up in an error message is replaced before storage.
* Hygiene: age and last-use are tracked so stale long-lived tokens are visible.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional

from cryptography.fernet import Fernet, InvalidToken

ROTATE_AFTER_DAYS = 90


class SecretAccessDenied(PermissionError):
    pass


class SecretMissing(LookupError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Vault:
    def __init__(self, path: Path, master_key: Optional[bytes] = None,
                 audit: Optional[Callable[[str, str, str], None]] = None):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._audit = audit or (lambda actor, action, detail: None)
        self._fernet = Fernet(master_key or self._load_or_create_key())
        self._data: Dict[str, dict] = json.loads(self.path.read_text()) if self.path.exists() else {}

    def _load_or_create_key(self) -> bytes:
        env = os.environ.get("CF_MASTER_KEY")
        if env:
            return env.encode()
        key_file = self.path.with_name("master.key")  # dev only — use a KMS/HSM in production
        if not key_file.exists():
            key_file.parent.mkdir(parents=True, exist_ok=True)
            key_file.write_bytes(Fernet.generate_key())
            key_file.chmod(0o600)
        return key_file.read_bytes().strip()

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=1))
        tmp.chmod(0o600)
        tmp.replace(self.path)

    # --- write side ---------------------------------------------------------------------------

    def put(self, name: str, value: str, actor: str = "admin") -> None:
        value = (value or "").strip()  # pasted tokens often carry a trailing newline/space
        if not value:
            raise ValueError("empty secret")
        with self._lock:
            existing = self._data.get(name, {})
            self._data[name] = {
                "ciphertext": self._fernet.encrypt(value.encode()).decode(),
                "created_at": existing.get("created_at", _now()),
                "rotated_at": _now(),
                "last_used_at": existing.get("last_used_at"),
                "last_used_by": existing.get("last_used_by"),
            }
            self._save()
        self._audit(actor, "secret.put", name)

    def delete(self, name: str, actor: str = "admin") -> None:
        with self._lock:
            self._data.pop(name, None)
            self._save()
        self._audit(actor, "secret.delete", name)

    # --- read side ------------------------------------------------------------------------------

    def get(self, name: str, connector_id: str, declared: List[str]) -> str:
        if name not in declared:
            self._audit(connector_id, "secret.denied", name)
            raise SecretAccessDenied(f"connector '{connector_id}' did not declare secret '{name}'")
        with self._lock:
            entry = self._data.get(name)
            if not entry:
                raise SecretMissing(f"secret '{name}' is not set — add it on the Secrets panel")
            try:
                value = self._fernet.decrypt(entry["ciphertext"].encode()).decode()
            except InvalidToken as e:
                raise SecretMissing(f"secret '{name}' cannot be decrypted with the current master key") from e
            entry["last_used_at"], entry["last_used_by"] = _now(), connector_id
            self._save()
        self._audit(connector_id, "secret.read", name)
        return value

    def metadata(self, used_by: Dict[str, List[str]]) -> List[dict]:
        now = datetime.now(timezone.utc)
        out = []
        names = sorted(set(self._data) | {n for names in used_by.values() for n in names})
        for name in names:
            entry = self._data.get(name)
            age = (now - datetime.fromisoformat(entry["rotated_at"])).days if entry else None
            out.append({
                "name": name,
                "set": bool(entry),
                "used_by": sorted(c for c, names in used_by.items() if name in names),
                "rotated_at": entry and entry["rotated_at"],
                "age_days": age,
                "rotation_due": age is not None and age >= ROTATE_AFTER_DAYS,
                "last_used_at": entry and entry.get("last_used_at"),
                "last_used_by": entry and entry.get("last_used_by"),
            })
        return out

    def redact(self, text: str) -> str:
        """Replace any secret value (and its common encodings) found in `text`."""
        if not text:
            return text
        with self._lock:
            items = list(self._data.items())
        for name, entry in items:
            try:
                value = self._fernet.decrypt(entry["ciphertext"].encode()).decode()
            except InvalidToken:
                continue
            if len(value) >= 4 and value in text:
                text = text.replace(value, f"[REDACTED:{name}]")
        return text
