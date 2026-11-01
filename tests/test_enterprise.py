"""Enterprise integration patterns (token exchange, discovery, GraphQL, JWT, Cortex keys, XML, syslog/CEF),
each run end-to-end against the lab mock — the same code paths the vendor catalog configs use."""

import asyncio
import socket
from pathlib import Path

import pytest

from connectforge.config.schema import SpecError, parse_spec
from connectforge.lab import enterprise as ent
from connectforge.mapping import MappingError, parse_cef, set_path, xml_to_dict
from connectforge.security.auth import cortex_advanced_headers, zscaler_obfuscated_key

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("cid, entity, at_least", [
    ("lab-prisma-alerts", "event", 80),    # JSON login -> token in body -> custom header; next_token
    ("lab-fmc-devices", "device", 60),     # basic-auth login -> token in RESPONSE HEADER; offset + total
    ("lab-zia-users", "user", 130),        # obfuscated key login -> SESSION COOKIE; page numbers
    ("lab-sophos-alerts", "event", 95),    # OAuth (body creds) -> whoami DISCOVERY -> region host + X-Tenant-ID; has_more
    ("lab-wiz-issues", "event", 120),      # OAuth with AUDIENCE -> GraphQL, cursor at variables.after (NESTED)
    ("lab-google-scc", "event", 70),       # service-account JWT (RS256) verified by the mock
    ("lab-cortex-alerts", "event", 150),   # per-request hash headers; offsets at request_data.search_from/to
])
async def test_enterprise_patterns_end_to_end(platform, cid, entity, at_least):
    run = await platform.run(cid)
    assert run["status"] == "ok", run["error"]
    assert run["fetched"] >= at_least and run["rejected"] == 0
    assert platform.store.count_for_connector(entity, cid) >= at_least


async def test_token_is_cached_and_refreshed_on_401(platform):
    await platform.run("lab-prisma-alerts")
    st = platform.states["lab-prisma-alerts"]
    first = st.auth._token
    assert first
    await platform.run("lab-prisma-alerts")
    assert st.auth._token == first                       # reused, no second login
    ent._tokens.pop(first)                               # server-side expiry
    run = await platform.run("lab-prisma-alerts")
    assert run["status"] == "ok" and st.auth._token != first   # 401 -> re-login once -> success


async def test_xml_source_and_bad_xml_record(platform):
    run = await platform.run("lab-xml-firewall")
    assert run["status"] == "ok" and run["fetched"] == 31 and run["rejected"] == 1   # 'not-a-time' quarantined
    deny = [e for e in platform.store.records("event", source="xmlfw_lab", limit=50) if e["type"] == "firewall_deny"][0]
    assert deny["src_ip"] == "203.0.113.45" and deny["dst_port"] == 3389


async def test_syslog_cef_and_regex_share_one_file(platform, tmp_path):
    lines = [line for i in range(6) for line in ent.syslog_lines(i)] + ["<134>garbage line with CEF:0|broken"]
    (tmp_path / "feeds" / "syslog.log").write_text("\n".join(lines) + "\n")
    cp = await platform.run("lab-checkpoint-cef")
    jn = await platform.run("lab-juniper-srx")
    assert cp["status"] == jn["status"] == "ok"
    assert cp["new"] == 6 and jn["new"] == 6      # each connector picks only its own vendor's lines
    assert cp["rejected"] == 0                    # the garbage line does not match the Check Point filter
    drop = [e for e in platform.store.records("event", source="checkpoint_lab") if e["action"] == "Drop"][0]
    assert drop["src_ip"] == "203.0.113.45" and drop["dst_port"] == 3389 and drop["severity"] == "high"


async def test_syslog_receiver_writes_lines(tmp_path):
    from connectforge.engine.syslog import start_syslog

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    transport = await start_syslog(port, tmp_path, host="127.0.0.1")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"<134>Oct 31 07:00:00 fw CEF:0|V|P|1|1|n|5|src=192.0.2.1", ("127.0.0.1", port))
        for _ in range(50):
            if (tmp_path / "syslog.log").exists():
                break
            await asyncio.sleep(0.02)
        assert "CEF:0|V|P" in (tmp_path / "syslog.log").read_text()
    finally:
        transport.close()


def test_helpers():
    d = {}
    set_path(d, "request_data.filters[0].value", 5)
    set_path(d, "variables.after", "x")
    assert d == {"request_data": {"filters": [{"value": 5}]}, "variables": {"after": "x"}}
    assert xml_to_dict("<a><b>1</b><b>2</b></a>") == {"a": {"b": ["1", "2"]}}
    with pytest.raises(MappingError):
        xml_to_dict('<!DOCTYPE x [<!ENTITY e "boom">]><a>&e;</a>')         # entity tricks refused
    cef = parse_cef("CEF:0|Ven\\|dor|Prod|1|42|Name|7|src=192.0.2.1 msg=hello world cs1=a\\=b")
    assert cef["device_vendor"] == "Ven|dor" and cef["msg"] == "hello world" and cef["cs1"] == "a=b"
    # worked by hand from Zscaler's algorithm: high="000123" -> a a a b c d ; low=str(123>>1).zfill(6)="000061" -> idx+2 -> c c c c i d
    assert zscaler_obfuscated_key("abcdefghijklmnopqrstuvwxyz012345", "1730360000123") == "aaabcdccccid"
    h = cortex_advanced_headers("k", "7", nonce="n" * 64, timestamp_ms="1")
    import hashlib
    assert h["Authorization"] == hashlib.sha256(b"k" + b"n" * 64 + b"1").hexdigest() and h["x-xdr-auth-id"] == "7"


BASE = """
id: vendor
name: Vendor
entity: event
auth:
  type: token_exchange
  header: x-token
  scheme: ""
  login: {url: "https://api.vendor.example/login", json: {username: me, password: "${secret:pw}"}}
request: {base_url: "https://api.vendor.example", path: /v1/alerts}
mapping: {id: id, type: t, timestamp: ts}
"""


@pytest.mark.parametrize("patch, message", [
    (('password: "${secret:pw}"', 'password: "hunter2-plaintext"'), "must come from the vault"),
    (('login: {url: "https://api.vendor.example/login"', 'login: {url: "https://evil.example/login"'), None),
    (("  login: {url:", "  loginx: {url:"), "loginx: unknown setting"),
])
def test_token_exchange_validation(patch, message):
    text = BASE.replace(*patch)
    if message is None:   # a login host simply becomes part of the default allowlist...
        assert "evil.example" in parse_spec(text).egress_hosts()
        # ...but with an explicit allowlist it is rejected
        with pytest.raises(SpecError, match="not in allowed_hosts"):
            parse_spec(text.replace("entity: event", "entity: event\nallowed_hosts: [api.vendor.example]"))
        return
    with pytest.raises(SpecError) as exc:
        parse_spec(text)
    assert any(message in e for e in exc.value.errors), exc.value.errors


def test_wildcard_hosts():
    spec = parse_spec(BASE.replace("entity: event", "entity: event\nallowed_hosts: [api.vendor.example, '*.region.vendor.example']"))
    assert spec.host_allowed("eu01.region.vendor.example") and not spec.host_allowed("region.vendor.example.evil.io")


def test_catalog_configs_all_validate():
    files = sorted((ROOT / "integrations" / "catalog").rglob("*.yaml"))
    assert len(files) >= 34
    for f in files:
        parse_spec(f.read_text())


async def test_catalog_nested_cursor_lands_in_body():
    """AWS Security Hub's incremental window must be written at Filters.UpdatedAt[0].Start/End in the POST body."""
    from datetime import datetime, timezone

    from connectforge.engine import RunMetrics, fetch_pages

    spec = parse_spec((ROOT / "integrations" / "catalog" / "cloud" / "aws_security_hub.yaml").read_text())
    seen = []

    class FakeFetcher:
        metrics = RunMetrics()

        async def request(self, method, url, params, body):
            seen.append(body)
            import httpx
            return httpx.Response(200, json={"Findings": []}, request=httpx.Request(method, url))

    async for _ in fetch_pages(spec, FakeFetcher(), datetime(2026, 10, 30, tzinfo=timezone.utc)):
        pass
    window = seen[0]["Filters"]["UpdatedAt"][0]
    assert window["Start"] == "2026-10-30T00:00:00.000Z" and window["End"].endswith("Z")
    assert seen[0]["MaxResults"] == 100
    assert parse_spec((ROOT / "integrations" / "catalog" / "cloud" / "aws_security_hub.yaml").read_text()).request.body["Filters"]["UpdatedAt"][0]["Start"] == ""  # spec untouched


def test_catalog_cef_mapping_on_a_real_style_line():
    from connectforge.mapping import map_record

    spec = parse_spec((ROOT / "integrations" / "catalog" / "firewall" / "check_point.yaml").read_text())
    line = ("<134>Oct 31 07:00:00 cp-gw01 CEF:0|Check Point|VPN-1 & FireWall-1|R81.20|Drop|Drop|7|rt=1793433600000 "
            "src=203.0.113.45 dst=10.0.2.11 dpt=3389 act=Drop suser=svc_backup msg=blocked by rule 12")
    row, err = map_record(parse_cef(line), spec)
    assert err is None
    assert row["severity"] == "high" and row["src_ip"] == "203.0.113.45" and row["dst_port"] == 3389
    assert row["user"] == "svc_backup" and row["timestamp"].startswith("2026-10-31")
