"""FR-1..FR-5 and B-2: what a config can describe, and how it is validated before it runs."""

from pathlib import Path

import pytest

from connectforge.mapping import get_path, map_record
from connectforge.spec import SpecError, parse_spec

ROOT = Path(__file__).resolve().parents[1]

# The PRD's own example vocabulary must work as written.
PRD_STYLE = """
id: okta-users
name: Okta users
entity: user
schedule: {every: 15m}
auth: { type: api_key, header: X-API-Key, secret: okta_key }
request: {base_url: "https://acme.okta.com", path: /api/v1/users, params: {limit: 100}}
pagination: {type: link_header}
mapping:
  id: id
  name: profile.firstName
  email: profile.login
  last_login: lastLogin
"""


def test_prd_example_config_is_valid():
    spec = parse_spec(PRD_STYLE)
    assert spec.schedule.seconds == 900
    assert spec.auth.header == "X-API-Key" and spec.auth.value == "${secret:okta_key}"
    assert spec.secret_names == ["okta_key"]
    assert spec.mapping["email"].from_ == "profile.login"


def test_real_sources_differ_in_login_and_paging():
    specs = [parse_spec(p.read_text()) for p in sorted((ROOT / "connectors").glob("*.yaml"))]
    assert len(specs) >= 3
    assert len({s.auth.type for s in specs}) >= 3          # none / api_key / bearer
    assert len({s.pagination.type for s in specs}) >= 3    # none / offset / link_header
    assert all(s.request.base_url.startswith("https://") for s in specs)


@pytest.mark.parametrize("folder", ["connectors", "examples", "lab"])
def test_every_shipped_config_validates(folder):
    for path in (ROOT / folder).glob("*.yaml"):
        parse_spec(path.read_text())


@pytest.mark.parametrize("patch, message", [
    (("secret: okta_key }", 'value: "sk_live_51HxAbCdEf" }'), "must come from the vault"),
    (("email: profile.login", "mail: profile.login"), "unknown user field(s) ['mail']"),
    (("  id: id\n", ""), "required user field(s) ['id']"),
    (('request: {base_url: "https://acme.okta.com"', 'allowed_hosts: [other.example]\nrequest: {base_url: "https://acme.okta.com"'),
     "not in allowed_hosts"),
    (("{ type: api_key, header: X-API-Key, secret: okta_key }", "{ type: api_key }"), "needs `secret"),
    (("every: 15m", "every: soon"), "cannot read duration"),
    (("entity: user", "entity: user\nkind: file"), "requires a 'file' block"),
])
def test_bad_configs_get_clear_errors(patch, message):
    with pytest.raises(SpecError) as exc:
        parse_spec(PRD_STYLE.replace(*patch))
    assert any(message in e for e in exc.value.errors), exc.value.errors


def test_yaml_syntax_error():
    with pytest.raises(SpecError, match="YAML syntax"):
        parse_spec("id: [unclosed")


def test_paths():
    rec = {"a": {"b": [{"c": 1}, {"c": 2}]}, "@timestamp": 5, "k.with.dots": "x"}
    assert get_path(rec, "a.b[1].c") == 2 and get_path(rec, "@timestamp") == 5
    assert get_path(rec, "['k.with.dots']") == "x" and get_path(rec, "a.b[9].c") is None


def test_mapping_renames_picks_nested_and_converts_dates():
    spec = parse_spec(PRD_STYLE)
    row, err = map_record({"id": "00u1", "profile": {"firstName": "Priya", "login": "priya@acme.example"},
                           "lastLogin": "2026-10-30T09:15:00.000Z"}, spec)
    assert err is None
    assert row == {"id": "00u1", "name": "Priya", "email": "priya@acme.example",
                   "last_login": "2026-10-30T09:15:00+00:00", "source": "okta-users"}


def test_event_mapping_features():
    spec = parse_spec("""
id: evt
name: Events
entity: event
request: {base_url: "https://api.example.com"}
mapping:
  id: {template: "{d}-{n}"}
  type: {from: kind, map: {deny: traffic_denied}, map_default: other}
  timestamp: {template: "{d} {t}", type: datetime, format: "%Y-%m-%d %H:%M:%S"}
  src_ip: {from: detail, parse_json: true, path: ip}
  dst_port: port
  severity: {from: lvl, lower: true, default: unknown}
""")
    base = {"d": "2026-10-31", "t": "10:00:00", "n": 1, "kind": "deny", "detail": '{"ip": "203.0.113.45"}', "port": "3389"}
    row, err = map_record(base, spec)
    assert err is None and row["type"] == "traffic_denied" and row["dst_port"] == 3389
    assert row["timestamp"] == "2026-10-31T10:00:00+00:00" and row["severity"] == "unknown"
    assert map_record({**base, "detail": '{"ip": "10.0.1.999"}'}, spec)[1].startswith("src_ip:")
    assert "invalid embedded JSON" in map_record({**base, "detail": '{"ip'}, spec)[1]
    assert "out of range" in map_record({**base, "port": "70000"}, spec)[1]
    assert "missing required" in map_record({k: v for k, v in base.items() if k not in ("d", "t")}, spec)[1]
