"""Configs written by AI assistants: read correctly (corpus), and once corrected they fetch the right data."""

import httpx
import pytest

from connectforge.config.schema import SpecError, parse_specs_with_fixes
from connectforge.engine import Platform
from fixtures.ai_corpus import CASES


@pytest.mark.parametrize("name, text, expect, check", CASES, ids=[c[0] for c in CASES])
def test_ai_written_config(name, text, expect, check):
    if expect == "ok":
        specs, fixes = parse_specs_with_fixes(text)
        assert check is None or check(specs), f"understood differently than meant; fixes: {fixes}"
    else:
        with pytest.raises(SpecError) as e:
            parse_specs_with_fixes(text)
        assert expect.split(":", 1)[1].lower() in "; ".join(e.value.errors).lower()


def _paged(shape):
    """A two-page API whose 'next page' is expressed in one of the common shapes."""
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        q = dict(request.url.params)
        calls.append(q)
        second = any(v in ("p2", "2") for v in q.values()) or "page2" in str(request.url)
        items = [{"id": f"{'b' if second else 'a'}{i}", "type": "alert", "created_at": "2026-10-31T10:00:00Z"} for i in range(3)]
        if second:
            return httpx.Response(200, json={"data": items, "meta": {}, "_links": {}})
        nxt = {"cursor": {"data": items, "meta": {"next_cursor": "p2"}},
               "links": {"data": items, "_links": {"next": {"href": "https://api.example.com/v1/alerts?page2=1"}}},
               "odata": {"value": items, "@odata.nextLink": "https://api.example.com/v1/alerts?page2=1"},
               "crowdstrike": {"resources": items, "meta": {"pagination": {"offset": "p2", "total": 6}}}}[shape]
        return httpx.Response(200, json=nxt)
    return handler, calls


@pytest.mark.parametrize("shape, paging", [
    ("cursor", "pagination: {style: cursor, cursor_param: after}"),
    ("links", "pagination: next_link"),
    ("odata", "pagination: {type: next_url}"),
    ("crowdstrike", "pagination: {type: offset_or_cursor, cursor_param: offset}"),
])
async def test_next_page_is_found_when_the_config_does_not_say_where(tmp_path, shape, paging):
    handler, calls = _paged(shape)
    p = Platform(tmp_path / "c", tmp_path, transport=httpx.MockTransport(handler))
    spec = p.add(f"name: Paged {shape}\nurl: https://api.example.com\nendpoint: /v1/alerts\nentity: alerts\n{paging}\n",
                 persist=False)[0]
    run = await p.run(spec.id)
    assert run["status"] == "ok" and run["pages"] == 2 and run["fetched"] == 6, run
    assert {r["id"] for r in p.store.records("event", connector=spec.id)} == {"a0", "a1", "a2", "b0", "b1", "b2"}
    assert any("next page: found the" in n for n in p.states[spec.id].last_notes)


AI_INTEGRATION = '''Here's a ConnectForge integration for Acme EDR. Paste it into the Add connector dialog:

```yaml
name: Acme EDR
base_url: https://api.acme.example/
authentication:
  type: bearer_token
  token: "${ACME_API_TOKEN}"
interval: every 10 minutes
endpoints:
  hosts:
    endpoint: v1/hosts?status=active
    entity: hosts
    data_path: $.data.items[*]
    field_mappings:
      - {source: $.host_id, target: id}
      - {source: $.hostname, target: hostname}
      - {source: $.network.ip, target: ip, type: ip_address}
      - {source: $.last_seen_epoch, target: last_seen, type: timestamp}
  alerts:
    url: https://api.acme.example/v1/alerts
    entity: detections
    paging: cursor
    mapping:
      alert_id: id
      title: type
      severity: severity
      created: timestamp
```
Remember to store ACME_API_TOKEN in the secrets page.'''


async def test_a_whole_ai_written_integration_runs(tmp_path):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        assert request.headers["Authorization"] == "Bearer s3cr3t"
        if request.url.path == "/v1/hosts":
            assert request.url.params["status"] == "active"
            return httpx.Response(200, json={"data": {"items": [
                {"host_id": "h1", "hostname": "LAPTOP-1", "network": {"ip": "10.0.0.5"}, "last_seen_epoch": 1793520000},
                {"host_id": "h2", "hostname": "LAPTOP-2", "network": {"ip": "10.0.0.6"}, "last_seen_epoch": 1793520060}]}})
        cursor = request.url.params.get("cursor")
        items = [{"alert_id": f"{cursor or 'x'}-1", "title": "Ransomware", "severity": "critical", "created": "2026-10-31T09:00:00Z"}]
        return httpx.Response(200, json={"alerts": items, "next_cursor": None if cursor else "c2"})

    specs, fixes = parse_specs_with_fixes(AI_INTEGRATION)
    assert [s.id for s in specs] == ["acme-edr.hosts", "acme-edr.alerts"]
    assert any("save its value on the Secrets tab" in f for f in fixes)
    p = Platform(tmp_path / "c", tmp_path, transport=httpx.MockTransport(handler))
    p.vault.put("acme_api_token", "s3cr3t")
    p.add(AI_INTEGRATION, persist=False)
    hosts, alerts = await p.run("acme-edr.hosts"), await p.run("acme-edr.alerts")
    assert hosts["status"] == alerts["status"] == "ok", (hosts, alerts)
    devices = {d["hostname"]: d for d in p.store.records("device", connector="acme-edr.hosts")}
    assert devices["LAPTOP-1"]["ip"] == "10.0.0.5" and devices["LAPTOP-1"]["last_seen"].startswith("2026-")
    events = p.store.records("event", connector="acme-edr.alerts")
    assert {e["id"] for e in events} == {"x-1", "c2-1"} and all(e["severity"] == "critical" for e in events)
    assert p.states["acme-edr.alerts"].spec.schedule.seconds == 600
