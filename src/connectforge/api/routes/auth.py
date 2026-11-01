"""Sign up, log in, log out (sessions in an HttpOnly cookie)."""

from __future__ import annotations

import os

from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from connectforge.api import deps
from connectforge.security.accounts import AuthError

router = APIRouter()


# --- sign up / log in --------------------------------------------------------------------------


class Credentials(BaseModel):
    email: str
    password: str
    name: str = ""


def _set_session(response: Response, request: Request, token: str) -> None:
    response.set_cookie(deps.COOKIE, token, max_age=7 * 86400, httponly=True, samesite="strict",
                        secure=request.url.scheme == "https", path="/")


@router.get("/api/auth/me")
def me(request: Request):
    user = deps.current_user(request) if deps.auth_enabled() else "local"
    if not user:
        raise HTTPException(401, "log in first")
    return {"email": user, "accounts": deps.accounts.count(),
            "signup_open": os.environ.get("CF_SIGNUP", "open") != "closed" or deps.accounts.count() == 0}


@router.get("/api/auth/status")
def auth_status():
    return {"has_accounts": deps.accounts.count() > 0,
            "signup_open": os.environ.get("CF_SIGNUP", "open") != "closed" or deps.accounts.count() == 0}


@router.post("/api/auth/signup")
def signup(body: Credentials, request: Request, response: Response):
    try:
        email = deps.accounts.signup(body.email, body.password, body.name)
    except AuthError as e:
        raise HTTPException(400, str(e)) from e
    _set_session(response, request, deps.accounts.new_session(email))
    return {"email": email}


@router.post("/api/auth/login")
def login(body: Credentials, request: Request, response: Response):
    try:
        email, token = deps.accounts.login(body.email, body.password)
    except AuthError as e:
        raise HTTPException(401, str(e)) from e
    _set_session(response, request, token)
    return {"email": email}


@router.post("/api/auth/logout")
def logout(request: Request, response: Response):
    deps.accounts.logout(request.cookies.get(deps.COOKIE))
    response.delete_cookie(deps.COOKIE, path="/")
    return {"ok": True}
