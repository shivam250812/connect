"""FR-7..FR-11, B-1, B-3, B-4 and the PRD's failure drills, run against the lab sources in-process."""

from datetime import datetime, timezone
from pathlib import Path

import httpx

from connectforge.mock import sources as mock
from connectforge.runtime import Platform

ROOT = Path(__file__).resolve().parents[1]


async def test_users_link_paging_429_and_bad_records(platform, sleep):
    run = await platform.run("lab-okta-users")
    assert run["status"] == "ok" and run["pages"] == 3 and run["fetched"] == 140
    assert run["retries"] >= 1 and 1.0 in sleep.calls                      # FR-8: 429 -> waited Retry-After
    bad = len([i for i in range(140) if i % 29 == 7 or i % 31 == 11])
    assert run["rejected"] == bad                                          # FR-9: missing id + bad dates skipped
    reasons = {q["reason"].split(":")[0] for q in platform.store.quarantined("lab-okta-users")}
    assert reasons == {"missing required field(s)", "last_login"}
    users = platform.store.records("user", limit=500)                      # FR-11: one users table
    assert len(users) == run["new"] == 140 - bad
    assert all(u["source"] == "okta_lab" and u["fetched_at"] for u in users)
    again = await platform.run("lab-okta-users")                           # re-run updates in place
    assert again["new"] == 0 and again["unchanged"] == 140 - bad


async def test_devices_offset_paging(platform):
    run = await platform.run("lab-edr-devices")
    assert run["status"] == "ok" and run["pages"] == 3 and run["fetched"] == 230
    assert run["rejected"] == len([i for i in range(230) if i % 37 == 5])  # bad IPs quarantined
    dev = platform.store.records("device", limit=1)[0]
    assert {"id", "hostname", "ip", "os", "owner", "last_seen", "source", "fetched_at"} <= set(dev)


async def test_events_sigv4_next_token_and_incremental(platform):
    run = await platform.run("lab-aws-cloudtrail")
    assert run["status"] == "ok" and run["new"] > 40 and run["rejected"] >= 1
    assert platform.store.get_cursor("lab-aws-cloudtrail")                 # B-1 checkpoint saved
    again = await platform.run("lab-aws-cloudtrail")
    assert again["fetched"] < run["fetched"]                               # only changes since last run


async def test_retry_backoff_is_1_2_4_then_failed(platform, sleep):
    mock.CHAOS["edr"] = "outage"
    run = await platform.run("lab-edr-devices")
    assert run["status"] == "error" and "failed after 4 attempts: HTTP 503" in run["error"]
    assert sleep.calls[-3:] == [1.0, 2.0, 4.0]                             # FR-7, exactly as the PRD example


async def test_network_down_mid_run_is_retried_then_reported(platform, sleep):
    def boom(request):
        raise httpx.ConnectError("network is down")

    platform._client = httpx.AsyncClient(transport=httpx.MockTransport(boom))
    run = await platform.run("lab-edr-devices")
    assert run["status"] == "error" and "network error (ConnectError)" in run["error"] and run["retries"] == 3


async def test_wrong_key_fails_fast_with_clear_message(platform, sleep):
    platform.vault.put("edr_api_key", "expired-or-wrong-key")
    run = await platform.run("lab-edr-devices")
    assert run["status"] == "error" and run["retries"] == 0
    assert "authentication failed" in run["error"] and "edr_api_key" in run["error"]
    assert "expired-or-wrong-key" not in str(platform.store.runs("lab-edr-devices"))


async def test_alert_after_three_failures_and_on_recovery(platform, webhook):
    mock.CHAOS["edr"] = "outage"
    for _ in range(3):
        await platform.run("lab-edr-devices")
    assert platform.health("lab-edr-devices")["status"] == "failing"
    assert len(webhook.messages) == 1 and "failed 3 runs in a row" in webhook.messages[0]["text"]   # B-4
    mock.CHAOS["edr"] = "normal"
    assert (await platform.run("lab-edr-devices"))["status"] == "ok"
    assert "recovered" in webhook.messages[-1]["text"]
    assert [a["kind"] for a in platform.store.alerts()] == ["recovered", "failing"]


async def test_poisoned_next_link_never_receives_credentials(platform):
    mock.CHAOS["okta"] = "evil_link"
    run = await platform.run("lab-okta-users")
    assert run["status"] == "error" and "credentials were not sent" in run["error"]
    assert any(a["action"] == "egress.blocked" for a in platform.store.audit_log())


async def test_test_connection(platform):                                   # B-3
    ok = await platform.test_connection("lab-edr-devices")
    assert ok["ok"] and "authenticated" in ok["detail"]
    platform.vault.put("edr_api_key", "wrong")
    bad = await platform.test_connection("lab-edr-devices")
    assert not bad["ok"] and "authentication failed" in bad["detail"]
    assert platform.store.records("device") == []                            # nothing stored by a test


async def test_file_source_tails_and_quarantines(platform, tmp_path):
    log = tmp_path / "feeds" / "fortigate.log"
    lines = [mock.fortigate_line(i, datetime(2026, 10, 31, 6, 0, i, tzinfo=timezone.utc)) for i in range(25)]
    log.write_text("\n".join(lines) + "\npartial")
    run = await platform.run("lab-fortigate")
    assert run["fetched"] == 25 and run["rejected"] == 1 and run["new"] == 24
    assert (await platform.run("lab-fortigate"))["fetched"] == 0


async def test_new_source_from_config_only(platform):
    """A brand-new connector written as config lands in the same events table — no code."""
    spec = platform.add("""
id: lab-okta-as-events
name: Okta users as events
entity: event
auth: {type: bearer, scheme: SSWS, secret: okta_lab_token}
request: {base_url: "http://127.0.0.1:9100", path: /okta/api/v1/users}
pagination: {type: link_header, page_size_param: limit, page_size: 100}
mapping:
  id: id
  type: {const: user_snapshot}
  timestamp: created
  description: {template: "{profile.login} is {status}"}
""", persist=False)
    run = await platform.run(spec.id)
    assert run["status"] == "ok" and run["new"] > 100
    sources = {r["source"] for r in platform.store.records("event", limit=1000)}
    assert "lab-okta-as-events" in sources


async def test_missing_secret_is_clear(platform):
    platform.vault.delete("edr_api_key")
    run = await platform.run("lab-edr-devices")
    assert run["status"] == "error" and "edr_api_key" in run["error"] and "not set" in run["error"]


async def test_file_path_outside_feed_dir_refused(platform):
    text = (ROOT / "lab" / "fortigate_lab.yaml").read_text().replace("data/feeds/fortigate.log", "/etc/hosts")
    platform.add(text.replace("id: lab-fortigate", "id: sneaky"), persist=False)
    run = await platform.run("sneaky")
    assert run["status"] == "error" and "outside permitted feed directories" in run["error"]


def test_platform_loads_multiple_dirs(tmp_path):
    p = Platform(ROOT / "connectors", tmp_path)
    p.load_dir([ROOT / "lab"])
    assert {"github-advisories", "nvd-cves", "cisa-kev", "lab-okta-users"} <= set(p.states)


async def test_remove_archives_config_and_reupload_restores(platform, tmp_path):
    text = (ROOT / "lab" / "edr_devices_lab.yaml").read_text().replace("id: lab-edr-devices", "id: edr-upload")
    platform.add(text)                                                     # like uploading a .yaml in the UI
    saved = platform.states["edr-upload"].path
    assert saved.exists() and (await platform.run("edr-upload"))["status"] == "ok"
    archived = platform.remove("edr-upload")
    assert "edr-upload" not in platform.states and not saved.exists()
    assert Path(archived).read_text() == text                              # nothing lost
    assert platform.store.records("device", source="edr_lab")              # stored records are kept
    platform.add(Path(archived).read_text())                                # upload it again -> back and running
    again = await platform.run("edr-upload")
    assert again["status"] == "ok" and again["new"] == 0                    # same rows, no duplicates
