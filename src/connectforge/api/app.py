"""HTTP API + health page (FR-10).

    uvicorn connectforge.api.app:app --port 8100

Every page and API call needs a logged-in user (security/accounts.py): a session cookie from /api/auth/login, or
the `X-Admin-Token` header when CF_ADMIN_TOKEN is set (for scripts). CF_AUTH=off disables this (tests only).
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from connectforge.api import deps
from connectforge.api.routes import auth, connectors, data, notifications, secrets, ui
from connectforge.settings import DATA_DIR, DIRS


@asynccontextmanager
async def lifespan(_app: FastAPI):
    deps.platform.load_dir(DIRS[1:])
    if os.environ.get("CF_SCHEDULER", "1") == "1":
        deps.platform.start()
    syslog = None
    if os.environ.get("CF_SYSLOG_PORT"):
        from connectforge.engine.syslog import start_syslog

        # bind to localhost by default; set CF_SYSLOG_HOST=0.0.0.0 to accept devices on the network
        syslog = await start_syslog(int(os.environ["CF_SYSLOG_PORT"]), DATA_DIR / "feeds",
                                    os.environ.get("CF_SYSLOG_HOST", "127.0.0.1"))
    yield
    if syslog:
        syslog.close()
    await deps.platform.stop()


app = FastAPI(title="ConnectForge", version="0.2.0", lifespan=lifespan)


@app.middleware("http")
async def require_login(request: Request, call_next):
    """Everything under /api needs a logged-in user; the page itself shows the login form when needed."""
    path = request.url.path
    if deps.auth_enabled() and path.startswith("/api/") and not path.startswith(deps.OPEN):
        user = deps.current_user(request)
        if not user:
            return JSONResponse({"detail": "log in first"}, status_code=401)
        request.state.user = user
    return await call_next(request)


# order matters only where paths overlap; the page itself (ui) goes last
for module in (auth, connectors, data, notifications, secrets, ui):
    app.include_router(module.router)
