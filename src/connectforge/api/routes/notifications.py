"""Slack and email notifications: settings, test message, and what was sent."""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException

from connectforge.api import deps
from connectforge.notifications.notifier import KINDS

router = APIRouter()


@router.get("/api/alerts")
def alerts(limit: int = 50):
    return deps.platform.store.alerts(limit)


# --- notifications: Slack and email ----------------------------------------------------------------


@router.get("/api/notifications")
def notifications():
    s = deps.platform.notifier.settings()
    have = {m["name"]: m["set"] for m in deps.platform.vault.metadata({"notifications": deps.platform.notifier.secret_names()})}
    return {"settings": s, "secrets": {"slack_webhook": have.get(s["slack"]["webhook_secret"], False) or have.get("alert_webhook", False),
                                       "smtp_password": have.get(s["email"]["password_secret"], False)},
            "kinds": KINDS, "registered": deps.accounts.emails(), "env_override": {"email": bool(os.environ.get("CF_SMTP_HOST")),
                                             "slack": bool(os.environ.get("CF_ALERT_WEBHOOK"))}}


@router.put("/api/notifications")
def save_notifications(body: dict, actor: str = Depends(deps.admin)):
    try:
        return {"settings": deps.platform.notifier.save(body, actor)}
    except ValueError as e:
        raise HTTPException(400, str(e)) from e


@router.post("/api/notifications/test")
async def test_notifications(actor: str = Depends(deps.admin)):
    return {"delivered": await deps.platform.notifier.test(actor)}
