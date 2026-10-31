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


# --- automatic mapping -----------------------------------------------------------------------------

from connectforge.mapping import MappingError, find_records, infer_mapping, mapping_yaml  # noqa: E402


def _froms(m):
    return {k: (fm.from_ if fm.from_ is not None else ("const", fm.const)) for k, fm in m.items()}


def test_auto_mapping_github_users():
    recs = [{"login": f"user{i}", "id": 1000 + i, "type": "User", "site_admin": False,
             "html_url": f"https://github.com/user{i}"} for i in range(5)]
    assert _froms(infer_mapping("user", recs)) == {"id": "id", "name": "login"}


def test_auto_mapping_nested_okta_style_users():
    recs = [{"id": f"00u{i}", "status": "ACTIVE", "lastLogin": "2026-10-30T09:00:00.000Z",
             "profile": {"login": f"u{i}@corp.com", "email": f"u{i}@corp.com", "firstName": "A",
                         "displayName": f"User {i}", "title": "Analyst", "department": "SOC"}} for i in range(3)]
    m = _froms(infer_mapping("user", recs))
    assert m == {"id": "id", "name": "profile.displayName", "email": "profile.email", "status": "status",
                 "last_login": "lastLogin", "title": "profile.title", "department": "profile.department"}


def test_auto_mapping_elastic_alerts_with_dotted_keys():
    recs = [{"_id": f"a{i}", "_source": {"@timestamp": "2026-10-31T10:00:00Z", "kibana.alert.rule.name": "Brute force",
             "kibana.alert.severity": "high", "kibana.alert.reason": "5 failed logins", "kibana.alert.risk_score": 73,
             "source.ip": "203.0.113.9", "destination.ip": "10.0.0.5", "user.name": "alice"}} for i in range(3)]
    m = infer_mapping("event", recs)
    f = _froms(m)
    assert f["id"] == "_id" and f["timestamp"] == "_source.@timestamp"
    assert f["severity"] == "_source['kibana.alert.severity']" and f["score"] == "_source['kibana.alert.risk_score']"
    assert f["src_ip"] == "_source['source.ip']" and f["dst_ip"] == "_source['destination.ip']"
    assert f["user"] == "_source['user.name']" and f["description"] == "_source['kibana.alert.reason']"
    spec = parse_spec("id: elastic\nname: e\nentity: event\nrequest: {base_url: 'https://x.example'}\n")
    row, err = map_record(recs[0], spec.model_copy(update={"mapping": m}))
    assert err is None and row["src_ip"] == "203.0.113.9" and row["score"] == 73.0
    assert "_source['kibana.alert.severity']" in mapping_yaml(m)


def test_auto_mapping_cisa_kev_and_records_detection():
    data = {"title": "CISA KEV", "count": 2, "vulnerabilities": [
        {"cveID": "CVE-2024-0001", "vendorProject": "Acme", "product": "Widget", "vulnerabilityName": "Acme RCE",
         "dateAdded": "2024-01-02", "shortDescription": "Remote code execution"},
        {"cveID": "CVE-2024-0002", "vendorProject": "Acme", "product": "Gadget", "vulnerabilityName": "Acme SQLi",
         "dateAdded": "2024-02-03", "shortDescription": "SQL injection"}]}
    recs = find_records(data)
    assert len(recs) == 2
    f = _froms(infer_mapping("event", recs, default_type="cisa_kev"))
    assert f["id"] == "cveID" and f["cve"] == "cveID" and f["timestamp"] == "dateAdded"
    assert f["type"] == "vulnerabilityName" and f["description"] == "shortDescription" and f["product"] == "product"


def test_auto_mapping_devices_and_value_checks():
    recs = [{"id": f"d{i}", "hostname": f"LAPTOP-{i}", "ipv4Addresses": [f"10.0.0.{i}"], "os": {"name": "Windows 11"},
             "lastSeenAt": "2026-10-31T08:00:00Z", "health": {"overall": "good"}, "time": "soon"} for i in range(3)]
    f = _froms(infer_mapping("device", recs))
    assert f["id"] == "id" and f["hostname"] == "hostname" and f["ip"] == "ipv4Addresses[0]"
    assert f["os"] == "os.name" and f["last_seen"] == "lastSeenAt" and f["status"] == "health.overall"


def test_auto_mapping_explains_what_is_missing():
    with pytest.raises(MappingError, match="could not find hostname.*Fields in the data: colour"):
        infer_mapping("device", [{"id": "1", "colour": "red"}, {"id": "2", "colour": "blue"}])
    with pytest.raises(MappingError, match="could not find id"):                     # non-unique values are not ids
        infer_mapping("event", [{"id": "same", "time": "2026-01-01"}, {"id": "same", "time": "2026-01-02"}])


def test_mapping_can_be_left_out_or_auto_and_unknown_settings_are_named():
    base = "id: src\nname: s\nentity: user\nrequest: {base_url: 'https://x.example'}\n"
    assert parse_spec(base).mapping is None
    assert parse_spec(base + "mapping:\n").mapping is None
    assert parse_spec(base + "mapping: auto\n").mapping is None
    with pytest.raises(SpecError, match="swaggerhub_logging: unknown setting"):
        parse_spec(base + "swaggerhub_logging: {enabled: true}\n")
