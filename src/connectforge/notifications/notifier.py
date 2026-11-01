"""Notifications: tell people on Slack and by email when something needs a human.

What is sent (each can be switched off on the Notifications page):
  failing        a connection failed 3 runs in a row (and `recovered` when it works again)
  auth_failed    the source rejected the credential (401/403): rotate or fix the secret
  data_quality   more than 20% of a run's records were rejected (the source changed its format?)
  critical_data  new events at or above a chosen severity arrived (first run of a connection is a baseline)
  rotation_due   a secret is older than 90 days

Repeats of the same notice for the same connection are held back for `cooldown_minutes`, so a flapping
source cannot flood a channel. Slack uses an incoming webhook; email uses any SMTP server. The webhook URL
and the SMTP password are secrets (Secrets tab), never settings.
"""

from __future__ import annotations

import asyncio
import json
import os
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import Any, Callable, Dict, List, Optional

import httpx

KINDS = {
    "failing": "Connection failing",
    "recovered": "Connection recovered",
    "auth_failed": "Credential rejected",
    "data_quality": "Bad data spike",
    "critical_data": "New critical findings",
    "rotation_due": "Key due for rotation",
    "test": "Test message",
}
SEVERITY_RANK = {"info": 0, "informational": 0, "unknown": 0, "low": 1, "medium": 2, "moderate": 2, "high": 3,
                 "critical": 4}
DEFAULTS: Dict[str, Any] = {
    "slack": {"enabled": False, "webhook_secret": "slack_webhook"},
    "email": {"enabled": False, "smtp_host": "", "smtp_port": 587, "security": "starttls", "username": "",
              "password_secret": "smtp_password", "from": "", "to": [], "to_registered": True},
    "rules": {"failing": True, "recovered": True, "auth_failed": True, "data_quality": True,
              "critical_data": True, "rotation_due": True},
    "min_severity": "critical",
    "cooldown_minutes": 60,
}
ICON = {"failing": ":red_circle:", "recovered": ":large_green_circle:", "auth_failed": ":key:",
        "data_quality": ":warning:", "critical_data": ":rotating_light:", "rotation_due": ":hourglass:",
        "test": ":wave:"}


def _merge(base: dict, override: dict) -> dict:
    out = json.loads(json.dumps(base))
    for k, v in (override or {}).items():
        out[k] = _merge(out[k], v) if isinstance(out.get(k), dict) and isinstance(v, dict) else v
    return out


class Notifier:
    def __init__(self, store, vault, transport: Optional[httpx.AsyncBaseTransport] = None,
                 smtp_factory: Optional[Callable[..., Any]] = None):
        self.store, self.vault, self.transport = store, vault, transport
        self.smtp_factory = smtp_factory  # tests pass a fake; None = real smtplib
        self.registered: Callable[[], List[str]] = lambda: []  # emails of signed-up accounts (set by the server)

    def recipients(self, email_cfg: dict) -> List[str]:
        """Everyone who signed up (unless switched off) plus any extra addresses, without duplicates."""
        people = (self.registered() if email_cfg.get("to_registered", True) else []) + list(email_cfg.get("to") or [])
        return list(dict.fromkeys(a.strip().lower() for a in people if a and "@" in a))

    # --- settings ---------------------------------------------------------------------------------

    def settings(self) -> dict:
        s = _merge(DEFAULTS, self.store.get_setting("notifications") or {})
        if os.environ.get("CF_SMTP_HOST"):  # environment wins, for deployments configured outside the UI
            s["email"].update(enabled=True, smtp_host=os.environ["CF_SMTP_HOST"],
                              smtp_port=int(os.environ.get("CF_SMTP_PORT", s["email"]["smtp_port"])),
                              username=os.environ.get("CF_SMTP_USER", s["email"]["username"]),
                              **{"from": os.environ.get("CF_SMTP_FROM", s["email"]["from"])},
                              to=[a.strip() for a in os.environ.get("CF_ALERT_EMAIL_TO", "").split(",") if a.strip()]
                              or s["email"]["to"])
        return s

    def save(self, new: dict, actor: str = "admin") -> dict:
        s = _merge(DEFAULTS, new)
        email = s["email"]
        if isinstance(email.get("to"), str):
            email["to"] = [a.strip() for a in email["to"].replace(";", ",").split(",") if a.strip()]
        bad = [a for a in email["to"] + ([email["from"]] if email["from"] else []) if "@" not in a]
        if bad:
            raise ValueError(f"not an email address: {', '.join(bad)}")
        if email["enabled"] and not (email["smtp_host"] and email["from"] and (email["to"] or email["to_registered"])):
            raise ValueError("email needs an SMTP server, a From address and recipients (registered accounts or To)")
        if s["min_severity"] not in SEVERITY_RANK:
            raise ValueError(f"min_severity must be one of {', '.join(SEVERITY_RANK)}")
        self.store.set_setting("notifications", s)
        self.store.audit(actor, "notifications.updated",
                         f"slack {'on' if s['slack']['enabled'] else 'off'}, email {'on' if email['enabled'] else 'off'}")
        return s

    def secret_names(self) -> List[str]:
        s = self.settings()
        return [s["slack"]["webhook_secret"], s["email"]["password_secret"], "alert_webhook"]

    def _secret(self, name: str) -> Optional[str]:
        from connectforge.security.vault import SecretAccessDenied, SecretMissing

        try:
            return self.vault.get(name, "notifications", [name])
        except (SecretMissing, SecretAccessDenied, LookupError):
            return None

    def _webhook(self, s: dict) -> Optional[str]:
        if os.environ.get("CF_ALERT_WEBHOOK"):
            return os.environ["CF_ALERT_WEBHOOK"]
        if s["slack"]["enabled"]:
            return self._secret(s["slack"]["webhook_secret"]) or self._secret("alert_webhook")
        return self._secret("alert_webhook")  # the original single-webhook setting keeps working

    # --- sending ----------------------------------------------------------------------------------

    def _cooling(self, kind: str, connector: str, minutes: int) -> bool:
        if kind in ("recovered", "test") or minutes <= 0:
            return False
        since = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
        return self.store.recent_alert(connector, kind, since)

    async def notify(self, kind: str, connector: str, title: str, lines: List[str], force: bool = False) -> str:
        """Send one notice on every enabled channel and record it. Returns how it was delivered."""
        s = self.settings()
        if not force and kind in s["rules"] and not s["rules"][kind]:
            return "switched off"
        if not force and self._cooling(kind, connector, int(s["cooldown_minutes"])):
            return "held back (sent recently)"
        text = title + ("\n" + "\n".join(f"- {line}" for line in lines) if lines else "")
        results = []
        url = self._webhook(s)
        if url:
            results.append(await self._slack(url, kind, title, lines))
        if s["email"]["enabled"]:
            results.append(await self._email(s["email"], kind, title, lines))
        delivered = "; ".join(results) or "logged only (no channel set up)"
        self.store.add_alert(connector, kind, self.vault.redact(text), delivered)
        self.store.audit(connector, f"alert.{kind}", delivered)
        return delivered

    async def _slack(self, url: str, kind: str, title: str, lines: List[str]) -> str:
        payload = {
            "text": f"{title}\n" + "\n".join(lines),  # fallback for notifications and Teams/Mattermost
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": f"{ICON.get(kind, '')} *{title}*"}}]
            + ([{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(f"• {line}" for line in lines)[:2900]}}]
               if lines else [])
            + [{"type": "context", "elements": [{"type": "mrkdwn", "text": f"ConnectForge · {KINDS.get(kind, kind)}"}]}],
        }
        try:
            async with httpx.AsyncClient(transport=self.transport, timeout=10, follow_redirects=False) as c:
                r = await c.post(url, json=payload)
            return f"slack: HTTP {r.status_code}" + ("" if r.is_success else f" {r.text[:80]}")
        except httpx.HTTPError as e:
            return f"slack: failed ({type(e).__name__})"

    async def _email(self, cfg: dict, kind: str, title: str, lines: List[str]) -> str:
        to = self.recipients(cfg)
        msg = EmailMessage()
        msg["Subject"] = f"[ConnectForge] {title}"
        msg["From"], msg["To"] = cfg["from"], ", ".join(to)
        body = "\n".join([title, "", *[f"- {line}" for line in lines], "", f"{KINDS.get(kind, kind)} · ConnectForge"])
        msg.set_content(body)
        items = "".join(f"<li>{_html(line)}</li>" for line in lines)
        msg.add_alternative(f"<p><b>{_html(title)}</b></p><ul>{items}</ul>"
                            f"<p style='color:#777;font-size:12px'>{KINDS.get(kind, kind)} · ConnectForge</p>", subtype="html")
        password = self._secret(cfg["password_secret"]) if cfg["username"] else None

        def send() -> None:
            port, mode = int(cfg["smtp_port"]), cfg["security"]
            if self.smtp_factory:
                server = self.smtp_factory(cfg["smtp_host"], port)
            elif mode == "ssl" or port == 465:
                server = smtplib.SMTP_SSL(cfg["smtp_host"], port, timeout=15, context=ssl.create_default_context())
            else:
                server = smtplib.SMTP(cfg["smtp_host"], port, timeout=15)
            with server:
                if mode == "starttls" and not isinstance(server, smtplib.SMTP_SSL) and not self.smtp_factory:
                    server.starttls(context=ssl.create_default_context())
                if cfg["username"]:
                    if password is None:
                        raise smtplib.SMTPAuthenticationError(535, f"secret '{cfg['password_secret']}' is not set")
                    server.login(cfg["username"], password)
                if to:
                    server.send_message(msg)

        try:
            await asyncio.to_thread(send)
            if not to:
                return "email: login OK, but no recipients yet (sign up, or add addresses under To)"
            return f"email: sent to {len(to)} recipient{'s' if len(to) != 1 else ''}"
        except (smtplib.SMTPException, OSError) as e:
            return f"email: failed ({self.vault.redact(str(e))[:120]})"

    async def test(self, actor: str = "admin") -> str:
        return await self.notify("test", "notifications", "ConnectForge test message",
                                 [f"Sent by {actor} from the Notifications page. If you can read this, it works."],
                                 force=True)

    # --- checks that are not tied to one run --------------------------------------------------------

    async def check_rotation(self, used_by: Dict[str, List[str]]) -> int:
        due = [m for m in self.vault.metadata(used_by) if m.get("rotation_due")]
        for m in due:
            await self.notify("rotation_due", f"secret:{m['name']}", f"Secret {m['name']} is {m['age_days']} days old",
                              [f"Used by: {', '.join(m['used_by']) or 'nothing'}",
                               "Create a new key at the vendor, save it on the Secrets tab, then revoke the old one."])
        return len(due)


def _html(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
