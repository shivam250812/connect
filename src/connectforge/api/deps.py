"""Shared state for the API: the platform, accounts, who is calling, and access checks."""

from __future__ import annotations

import os
from typing import Optional

from fastapi import Header, HTTPException, Request

from connectforge.engine import Platform
from connectforge.security.accounts import Accounts
from connectforge.settings import DATA_DIR, DIRS

platform = Platform(DIRS[0], DATA_DIR)
accounts = Accounts(platform.store)
platform.notifier.registered = lambda: accounts.emails()   # email notices go to every registered account

COOKIE = "cf_session"
OPEN = ("/api/auth/", "/static/", "/favicon")  # reachable without logging in


def auth_enabled() -> bool:
    return os.environ.get("CF_AUTH", "on") != "off"


def current_user(request: Request) -> Optional[str]:
    token = os.environ.get("CF_ADMIN_TOKEN")
    if token and request.headers.get("x-admin-token") == token:
        return "admin-token"
    return accounts.user_for(request.cookies.get(COOKIE))


def admin(request: Request, x_admin_token: Optional[str] = Header(None)) -> str:
    """Who is acting, for the audit log: the logged-in user's email (or "admin-token" for scripts)."""
    user = getattr(request.state, "user", None)
    if user:
        return user
    expected = os.environ.get("CF_ADMIN_TOKEN")
    if expected and x_admin_token != expected:
        raise HTTPException(401, "admin token required")
    return "admin"


def connector_state(cid: str):
    """The running connector, or 404."""
    if cid not in platform.states:
        raise HTTPException(404, f"unknown connector '{cid}'")
    return platform.states[cid]
