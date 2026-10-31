import os
import sys
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["CF_SCHEDULER"] = "0"

from connectforge.mock import sources as mock  # noqa: E402
from connectforge.runtime import Platform  # noqa: E402


class FakeSleep:
    """Records requested sleeps instead of waiting, so backoff tests are instant and exact."""

    def __init__(self):
        self.calls = []

    async def __call__(self, seconds):
        self.calls.append(seconds)


class WebhookSink:
    """Captures alert webhooks (B-4)."""

    def __init__(self):
        self.messages = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        import json

        self.messages.append(json.loads(request.content))
        return httpx.Response(200, text="ok")


@pytest.fixture()
def sleep():
    return FakeSleep()


@pytest.fixture()
def webhook():
    return WebhookSink()


@pytest.fixture()
def platform(tmp_path, sleep, webhook, monkeypatch):
    """Platform wired to the in-process lab sources, with lab secrets and all lab connectors loaded."""
    monkeypatch.chdir(ROOT)
    monkeypatch.setenv("CF_ALERT_WEBHOOK", "https://hooks.slack.example/T000/B000/xyz")
    for k in mock.CHAOS:
        mock.CHAOS[k] = "normal"
    for k in mock.COUNTERS:
        mock.COUNTERS[k] = 0
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    p = Platform(tmp_path / "connectors", tmp_path, transport=httpx.ASGITransport(app=mock.app), sleep=sleep,
                 file_roots=[feeds], alert_transport=httpx.MockTransport(webhook.handler))
    from connectforge.mock import enterprise as ent

    for name, value in {"okta_lab_token": mock.OKTA_TOKEN, "edr_api_key": mock.EDR_KEY,
                        "aws_access_key_id": mock.AWS_KEY_ID, "aws_secret_access_key": mock.AWS_SECRET,
                        "prisma_lab_key": ent.PRISMA_KEY, "prisma_lab_secret": ent.PRISMA_SECRET,
                        "fmc_lab_password": ent.FMC_PASS, "zia_lab_api_key": ent.ZIA_KEY,
                        "zia_lab_password": ent.ZIA_PASS, "oauth_lab_client_secret": ent.OAUTH_SECRET,
                        "google_lab_service_account": ent.GOOGLE_KEY_JSON, "cortex_lab_key": ent.CORTEX_KEY,
                        "xmlfw_lab_password": "lab-fw-pass"}.items():
        p.vault.put(name, value, actor="test")
    for f in sorted((ROOT / "lab").glob("*.yaml")) + sorted((ROOT / "lab" / "enterprise").glob("*.yaml")):
        text = f.read_text().replace("data/feeds/fortigate.log", str(feeds / "fortigate.log")) \
            .replace("data/feeds/syslog.log", str(feeds / "syslog.log"))
        p.add(text, actor="test", persist=False)
    return p
