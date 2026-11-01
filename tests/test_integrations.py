"""One YAML file = one integration with several endpoints, sharing a login; every endpoint's data is
stored and framed for display (typed columns), including data outside the common schema."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from connectforge.api import deps
from connectforge.api.app import app
from connectforge.config.schema import SpecError, parse_specs
from connectforge.engine import Platform

VENDOR = """
id: acme
name: Acme Security
auth:
  type: oauth2_client_credentials
  token_url: https://api.acme.example/oauth/token
  client_id: cid
  secret: acme_secret
  client_auth: body
request: {base_url: "https://api.acme.example", headers: {Accept: application/json}}
schedule: {every: 1h}
endpoints:
  - name: devices
    entity: device
    path: /v1/devices
    records: items
  - name: alerts
    title: Detections
    entity: event
    path: /v1/alerts
    params: {status: open}
    schedule: {every: 5m}
  - name: patches
    entity: record
    path: /v1/patches
"""


class Acme:
    def __init__(self):
        self.logins = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == "/oauth/token":
            self.logins += 1
            return httpx.Response(201, json={"access_token": "t0k", "expires_in": 3600})
        assert request.headers["Authorization"] == "Bearer t0k"
        if request.url.path == "/v1/devices":
            return httpx.Response(200, json={"items": [
                {"id": f"d{i}", "hostname": f"LAPTOP-{i}", "local_ip": f"10.0.0.{i}", "os_name": "macOS",
                 "last_seen": "2026-10-31T10:00:00Z"} for i in range(3)]})
        if request.url.path == "/v1/alerts":
            assert request.url.params["status"] == "open"
            return httpx.Response(200, json={"data": [
                {"alert_id": "a1", "rule_name": "Ransomware behaviour", "severity": "Critical",
                 "created_at": "2026-10-31T09:00:00Z", "host": {"ip": "10.0.0.1"}}]})
        return httpx.Response(200, json=[
            {"patch_id": 7, "patchName": "KB5031356", "severityLabel": "Critical", "releasedOn": "2026-10-14",
             "missing_on": 4, "reboot": True, "url": "https://support.example/KB5031356"},
            {"patch_id": 8, "patchName": "KB5031455", "severityLabel": "Moderate", "releasedOn": "2026-10-20",
             "missing_on": 1, "reboot": False, "url": "https://support.example/KB5031455"}])


def test_one_file_expands_to_one_connector_per_endpoint():
    specs = parse_specs(VENDOR)
    assert [s.id for s in specs] == ["acme.devices", "acme.alerts", "acme.patches"]
    devices, alerts, patches = specs
    assert devices.integration == "acme" and devices.integration_name == "Acme Security" and devices.source == "acme"
    assert alerts.name == "Detections" and alerts.schedule.seconds == 300 and devices.schedule.seconds == 3600
    assert alerts.request.base_url == "https://api.acme.example" and alerts.request.params == {"status": "open"}
    assert alerts.request.headers == {"Accept": "application/json"}           # shared headers are inherited
    assert patches.entity == "record" and all(s.secret_names == ["acme_secret"] for s in specs)


def test_endpoint_errors_name_the_endpoint():
    bad = VENDOR.replace("    path: /v1/patches", "    path: /v1/patches\n    pagintion: {type: offset}")
    bad = bad.replace("    entity: device", "    entity: gadget")
    with pytest.raises(SpecError) as e:
        parse_specs(bad)
    assert "endpoints.patches.pagintion: unknown setting, not part of an endpoint (did you mean 'pagination'?)" in e.value.errors
    assert any(m.startswith("endpoints.devices.entity:") for m in e.value.errors)
    with pytest.raises(SpecError, match="two endpoints have this name"):
        parse_specs(VENDOR.replace("name: alerts", "name: devices"))


async def test_endpoints_share_one_login_and_every_endpoint_is_stored(tmp_path):
    acme = Acme()
    p = Platform(tmp_path / "c", tmp_path, transport=httpx.MockTransport(acme.handler))
    p.vault.put("acme_secret", "s3cret")
    p.add(VENDOR, persist=False)
    runs = {cid: await p.run(cid) for cid in ("acme.devices", "acme.alerts", "acme.patches")}
    assert all(r["status"] == "ok" for r in runs.values()), runs
    assert acme.logins == 1                                                # one session for the whole integration
    assert [d["hostname"] for d in p.store.records("device", connector="acme.devices")] == ["LAPTOP-0", "LAPTOP-1", "LAPTOP-2"]
    alert = p.store.records("event", connector="acme.alerts")[0]
    assert (alert["id"], alert["type"], alert["severity"]) == ("a1", "Ransomware behaviour", "Critical")
    patches = p.store.records("record", connector="acme.patches")
    assert {r["id"] for r in patches} == {"7", "8"} and {r["title"] for r in patches} == {"KB5031356", "KB5031455"}
    assert json.loads(patches[0]["data"])["severity_label"] in ("Critical", "Moderate")


async def test_data_api_frames_each_endpoint_for_display(tmp_path, monkeypatch):
    acme = Acme()
    p = Platform(tmp_path / "c", tmp_path, transport=httpx.MockTransport(acme.handler))
    p.vault.put("acme_secret", "s3cret")
    p.add(VENDOR)
    for cid in ("acme.devices", "acme.patches"):
        await p.run(cid)
    monkeypatch.setattr(deps, "platform", p)
    client = TestClient(app)
    dev = client.get("/api/connectors/acme.devices/data").json()
    assert [(c["key"], c["type"]) for c in dev["columns"]] == [
        ("id", "str"), ("hostname", "str"), ("ip", "ip"), ("os", "str"), ("last_seen", "datetime"), ("fetched_at", "datetime")]
    pat = client.get("/api/connectors/acme.patches/data").json()
    kinds = {c["key"]: c["type"] for c in pat["columns"]}
    assert list(kinds)[:3] == ["id", "title", "timestamp"] and kinds["timestamp"] == "datetime"
    assert kinds["missing_on"] == "number" and kinds["reboot"] == "bool" and kinds["url"] == "url"
    assert pat["total"] == 2 and pat["rows"][0]["_raw"]
    v = client.post("/api/connectors/validate", json={"yaml": VENDOR}).json()
    assert v["valid"] and v["id"] == "acme" and [e["path"] for e in v["endpoints"]] == ["/v1/devices", "/v1/alerts", "/v1/patches"]


def test_removing_an_endpoint_from_the_file_stops_it(tmp_path):
    p = Platform(tmp_path / "c", tmp_path)
    p.add(VENDOR)
    assert {"acme.devices", "acme.alerts", "acme.patches"} <= set(p.states)
    path = p.states["acme.alerts"].path
    path.write_text(VENDOR.split("  - name: patches")[0])
    r = p.reload_dir()
    assert r["removed"] == ["acme.patches"] and "acme.patches" not in p.states
    p.remove("acme.devices")                                               # removing one removes the file's integration
    assert not any(cid.startswith("acme.") for cid in p.states) and not path.exists()


async def test_record_fetched_by_two_connectors_shows_in_both(tmp_path):
    """Same source + id from two connectors: stored once, listed in each connector's Data view."""
    acme = Acme()
    p = Platform(tmp_path / "c", tmp_path, transport=httpx.MockTransport(acme.handler))
    p.vault.put("acme_secret", "s3cret")
    p.add(VENDOR, persist=False)
    p.add(VENDOR.replace("id: acme\n", "id: acme2\nsource: acme\n"), persist=False)
    for cid in ("acme.devices", "acme2.devices"):
        assert (await p.run(cid))["status"] == "ok"
    assert len(p.store.records("device")) == 3                              # no duplicates in the shared table
    for cid in ("acme.devices", "acme2.devices"):
        assert len(p.store.records("device", connector=cid)) == 3 and p.store.count_for_connector("device", cid) == 3
