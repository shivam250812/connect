"""Accounts: sign up and log in with an email and a password.

* Passwords are stored only as scrypt hashes (salted, memory-hard); they are never logged or returned.
* A login creates a random session token kept in an HttpOnly, SameSite=Strict cookie. Only its SHA-256 is
  stored, so a copy of the database cannot be used to log in.
* 5 wrong passwords lock that email for 15 minutes.
* The registered emails are the default recipients of email notifications.
* Signup is open (set CF_SIGNUP=closed to stop new accounts once your team has signed up).
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

SESSION_DAYS = 7
MAX_FAILURES, LOCK_SECONDS = 5, 15 * 60
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (email TEXT PRIMARY KEY, name TEXT, pw_hash TEXT NOT NULL,
  created_at TEXT, last_login TEXT);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, email TEXT NOT NULL, created_at TEXT,
  expires_at TEXT NOT NULL);
"""


class AuthError(ValueError):
    pass


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, n, r, p, salt, digest = stored.split("$")
        got = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p), dklen=32)
        return hmac.compare_digest(got.hex(), digest)
    except (ValueError, TypeError):
        return False


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Accounts:
    def __init__(self, store):
        self.store = store
        store.db.executescript(SCHEMA)
        self._failures: Dict[str, List[float]] = {}

    # --- accounts ---------------------------------------------------------------------------------

    def count(self) -> int:
        return self.store._rows("SELECT COUNT(*) n FROM accounts")[0]["n"]

    def emails(self) -> List[str]:
        return [r["email"] for r in self.store._rows("SELECT email FROM accounts ORDER BY created_at")]

    def signup(self, email: str, password: str, name: str = "") -> str:
        email = (email or "").strip().lower()
        if os.environ.get("CF_SIGNUP", "open") == "closed" and self.count() > 0:
            raise AuthError("sign-up is closed; ask an existing user to add you")
        if not _EMAIL.match(email):
            raise AuthError("enter a valid email address")
        if len(password or "") < 8:
            raise AuthError("use a password of at least 8 characters")
        if password.lower() in (email, email.split("@")[0]) or password.lower() in ("password", "12345678", "qwertyui"):
            raise AuthError("that password is too easy to guess")
        if self.store._rows("SELECT 1 FROM accounts WHERE email=?", (email,)):
            raise AuthError("an account with this email already exists; log in instead")
        self.store._exec("INSERT INTO accounts VALUES (?, ?, ?, ?, NULL)",
                         (email, (name or "").strip()[:80], hash_password(password), _now().isoformat()))
        self.store.audit(email, "account.created", email)
        return email

    # --- login / sessions -------------------------------------------------------------------------

    def _locked(self, email: str) -> bool:
        recent = [t for t in self._failures.get(email, []) if time.monotonic() - t < LOCK_SECONDS]
        self._failures[email] = recent
        return len(recent) >= MAX_FAILURES

    def login(self, email: str, password: str) -> Tuple[str, str]:
        """Returns (email, session token). Same message for unknown email and wrong password."""
        email = (email or "").strip().lower()
        if self._locked(email):
            raise AuthError("too many wrong passwords; try again in 15 minutes")
        row = self.store._rows("SELECT pw_hash FROM accounts WHERE email=?", (email,))
        if not row or not verify_password(password or "", row[0]["pw_hash"]):
            if not row:
                verify_password(password or "", hash_password("timing-equaliser"))  # same cost either way
            self._failures.setdefault(email, []).append(time.monotonic())
            self.store.audit(email or "-", "login.failed", "wrong email or password")
            raise AuthError("wrong email or password")
        self._failures.pop(email, None)
        return email, self.new_session(email)

    def new_session(self, email: str) -> str:
        token = secrets.token_urlsafe(32)
        self.store._exec("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                         (hashlib.sha256(token.encode()).hexdigest(), email, _now().isoformat(),
                          (_now() + timedelta(days=SESSION_DAYS)).isoformat()))
        self.store._exec("UPDATE accounts SET last_login=? WHERE email=?", (_now().isoformat(), email))
        self.store.audit(email, "login", "new session")
        return token

    def user_for(self, token: Optional[str]) -> Optional[str]:
        if not token:
            return None
        rows = self.store._rows("SELECT email, expires_at FROM sessions WHERE token_hash=?",
                                (hashlib.sha256(token.encode()).hexdigest(),))
        if not rows or rows[0]["expires_at"] < _now().isoformat():
            return None
        return rows[0]["email"]

    def logout(self, token: Optional[str]) -> None:
        if token:
            self.store._exec("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
