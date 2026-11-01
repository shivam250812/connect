"""Slack and email notifications: when they fire, what they say, and that they are not repeated."""

import base64
import json
import socketserver
import threading
from datetime import datetime, timedelta, timezone
from email import message_from_bytes, policy

import httpx
import pytest

from connectforge.engine import Platform


class SMTPSink(socketserver.ThreadingTCPServer):
    """A tiny real SMTP server: speaks enough of the protocol for smtplib (EHLO, AUTH PLAIN, MAIL, RCPT, DATA)."""
    allow_reuse_address = True

    def __init__(self):
        self.mails, self.logins = [], []
        sink = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                self.wfile.write(b"220 sink ESMTP\r\n")
                rcpt, data_mode, buf = [], False, []
                for raw in self.rfile:
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    if data_mode:
                        if line == ".":
                            data_mode = False
                            sink.mails.append({"to": rcpt, "message": message_from_bytes("\r\n".join(buf).encode(), policy=policy.default)})
                            rcpt, buf = [], []
                            self.wfile.write(b"250 queued\r\n")
                        else:
                            buf.append(line[1:] if line.startswith("..") else line)
                        continue
                    cmd = line.split(" ", 1)[0].upper()
                    if cmd in ("EHLO", "HELO"):
                        self.wfile.write(b"250-sink\r\n250 AUTH PLAIN\r\n")
                    elif cmd == "AUTH":
                        user, pw = base64.b64decode(line.split()[-1]).split(b"\0")[1:]
                        sink.logins.append((user.decode(), pw.decode()))
                        self.wfile.write(b"235 ok\r\n" if pw == b"app-password" else b"535 bad credentials\r\n")
                    elif cmd == "MAIL":
                        self.wfile.write(b"250 ok\r\n")
                    elif cmd == "RCPT":
                        rcpt.append(line.split(":", 1)[1].strip(" <>"))
                        self.wfile.write(b"250 ok\r\n")
                    elif cmd == "DATA":
                        data_mode = True
                        self.wfile.write(b"354 go\r\n")
                    elif cmd == "QUIT":
                        self.wfile.write(b"221 bye\r\n")
                        return
                    else:
                        self.wfile.write(b"250 ok\r\n")

        super().__init__(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.serve_forever, daemon=True).start()


@pytest.fixture()
def smtp():
    s = SMTPSink()
    yield s
    s.shutdown()
    s.server_close()


class Feed:
    """A source whose answer each test controls."""

    def __init__(self):
        self.items, self.status, self.slack = [], 200, []

    def api(self, request):
        if self.status != 200:
            return httpx.Response(self.status, json={"message": "Bad credentials"})
        return httpx.Response(200, json=self.items)

    def hook(self, request):
        self.slack.append(json.loads(request.content))
        return httpx.Response(200, text="ok")


FEED = """
id: vendor-alerts
name: Vendor alerts
entity: event
auth: {type: bearer, secret: vendor_token}
request: {base_url: "https://api.vendor.example", path: /alerts}
mapping: {id: id, type: type, severity: severity, timestamp: ts, description: msg}
"""


def _alert(i, sev="critical"):
    return {"id": f"A{i}", "type": "malware", "severity": sev, "ts": "2026-11-01T10:00:00Z", "msg": f"Ransomware on host {i}"}


@pytest.fixture()
def setup(tmp_path, smtp, monkeypatch):
    monkeypatch.delenv("CF_ALERT_WEBHOOK", raising=False)
    feed = Feed()
    p = Platform(tmp_path / "c", tmp_path, transport=httpx.MockTransport(feed.api),
                 alert_transport=httpx.MockTransport(feed.hook))
    p.vault.put("vendor_token", "t")
    p.vault.put("slack_webhook", "https://hooks.slack.com/services/T0/B0/xyz")
    p.vault.put("smtp_password", "app-password")
    p.notifier.save({"slack": {"enabled": True},
                     "email": {"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": smtp.server_address[1],
                               "security": "none", "username": "alerts@acme.example", "from": "alerts@acme.example",
                               "to": "soc@acme.example, ciso@acme.example"}})
    p.add(FEED, persist=False)
    return p, feed, smtp


async def test_new_critical_findings_ping_slack_and_email_but_not_the_first_run(setup):
    p, feed, smtp = setup
    feed.items = [_alert(1), _alert(2, "high")]
    await p.run("vendor-alerts")                                          # first run: history, not news
    assert feed.slack == [] and smtp.mails == []
    feed.items = [_alert(1), _alert(2, "high"), _alert(3), _alert(4, "low")]
    await p.run("vendor-alerts")
    assert len(feed.slack) == 1 and len(smtp.mails) == 1
    msg = feed.slack[0]
    assert "1 new critical+ finding from Vendor alerts" in msg["text"] and "A3" in msg["text"] and "A4" not in msg["text"]
    assert msg["blocks"][0]["text"]["text"].startswith(":rotating_light:")
    mail = smtp.mails[0]
    assert mail["to"] == ["soc@acme.example", "ciso@acme.example"] and smtp.logins == [("alerts@acme.example", "app-password")]
    assert mail["message"]["Subject"] == "[ConnectForge] 1 new critical+ finding from Vendor alerts"
    assert "Ransomware on host 3" in mail["message"].get_body(("plain",)).get_content()
    sent = p.store.alerts()[0]
    assert sent["kind"] == "critical_data" and sent["delivered"] == "slack: HTTP 200; email: sent to 2 recipients"


async def test_rejected_credential_pings_at_once_then_failing_once_then_recovered(setup):
    p, feed, smtp = setup
    feed.status = 401
    for _ in range(4):
        await p.run("vendor-alerts")
    kinds = [a["kind"] for a in reversed(p.store.alerts())]
    assert kinds == ["auth_failed", "failing"]                            # no repeats inside the cooldown
    assert "Check or rotate the secret (vendor_token)" in feed.slack[0]["text"]
    feed.status = 200
    await p.run("vendor-alerts")
    assert p.store.alerts()[0]["kind"] == "recovered" and "recovered" in feed.slack[-1]["text"]
    assert len(smtp.mails) == 3


async def test_bad_data_spike(setup):
    p, feed, smtp = setup
    feed.items = [_alert(i) for i in range(6)] + [{"id": f"B{i}", "severity": "low"} for i in range(6)]   # no type/ts
    await p.run("vendor-alerts")
    assert p.store.alerts()[0]["kind"] == "data_quality" and "6 of 12 records rejected" in feed.slack[0]["text"]


async def test_switched_off_rules_send_nothing(setup):
    p, feed, smtp = setup
    s = p.notifier.settings()
    s["rules"]["auth_failed"] = s["rules"]["failing"] = False
    p.notifier.save(s)
    feed.status = 403
    for _ in range(3):
        await p.run("vendor-alerts")
    assert feed.slack == [] and smtp.mails == []


async def test_keys_due_for_rotation(setup):
    p, feed, smtp = setup
    p.vault._data["vendor_token"]["rotated_at"] = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
    p.vault._save()
    assert await p.check_rotation() == 1
    assert "Secret vendor_token is 120 days old" in feed.slack[0]["text"] and "vendor-alerts" in feed.slack[0]["text"]


async def test_test_message_settings_checks_and_wrong_password(setup):
    p, feed, smtp = setup
    assert await p.notifier.test("admin") == "slack: HTTP 200; email: sent to 2 recipients"
    with pytest.raises(ValueError, match="not an email address: soc-at-acme"):
        p.notifier.save({"email": {"to": "soc-at-acme"}})
    with pytest.raises(ValueError, match="needs an SMTP server"):
        p.notifier.save({"email": {"enabled": True}})
    p.vault.put("smtp_password", "wrong")
    delivered = await p.notifier.test("admin")
    assert delivered.startswith("slack: HTTP 200; email: failed (") and "wrong" not in delivered   # never echoes the secret
