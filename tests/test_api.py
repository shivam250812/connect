import pytest
from fastapi.testclient import TestClient

from connectforge import server


@pytest.fixture()
def client(platform, monkeypatch):
    monkeypatch.setattr(server, "platform", platform)
    return TestClient(server.app)


def test_health_page_data(client):
    d = client.get("/api/overview").json()
    assert {c["id"] for c in d["connectors"]} >= {"lab-okta-users", "lab-edr-devices"}
    run = client.post("/api/connectors/lab-okta-users/run").json()
    assert run["status"] == "ok"
    c = next(c for c in client.get("/api/overview").json()["connectors"] if c["id"] == "lab-okta-users")
    assert c["status"] in ("healthy", "degraded") and c["last_run"]["fetched"] == 140 and c["records_stored"] == 140 - len([i for i in range(140) if i % 29 == 7 or i % 31 == 11])
    detail = client.get("/api/connectors/lab-okta-users").json()
    assert detail["spec"]["auth"]["token"] == "${secret:okta_lab_token}"  # config shows the secret's name only


def test_records_tables(client):
    client.post("/api/connectors/lab-okta-users/run")
    users = client.get("/api/records/users?limit=5").json()
    assert len(users) == 5 and all(u["source"] == "okta_lab" for u in users)
    assert client.get("/api/records/users?q=finance").status_code == 200
    assert client.get("/api/records/nope").status_code == 404


def test_validate_test_and_save(client):
    text = open("lab/edr_devices_lab.yaml").read().replace("id: lab-edr-devices", "id: edr-copy")
    v = client.post("/api/connectors/validate", json={"yaml": text}).json()
    assert v["valid"] and v["summary"]["table"] == "devices"
    t = client.post("/api/test", json={"yaml": text}).json()
    assert t["ok"]
    assert client.post("/api/connectors", json={"yaml": text}).json()["id"] == "edr-copy"
    bad = client.post("/api/connectors/validate", json={"yaml": "id: x\nname: y\nmapping: {}"}).json()
    assert not bad["valid"] and bad["errors"]


def test_schema_endpoint_for_web_form(client):
    s = client.get("/api/schema").json()
    assert s["user"]["table"] == "users" and "last_login" in s["user"]["fields"] and s["event"]["required"]


def test_secrets_are_write_only(client):
    assert client.put("/api/secrets/okta_lab_token", json={"value": "rotated-value-123"}).status_code == 200
    assert "rotated-value-123" not in client.get("/api/secrets").text


def test_admin_token(client, monkeypatch):
    monkeypatch.setenv("CF_ADMIN_TOKEN", "letmein")
    assert client.post("/api/connectors/lab-okta-users/pause").status_code == 401
    assert client.post("/api/connectors/lab-okta-users/pause", headers={"X-Admin-Token": "letmein"}).json()["paused"]


def test_static_traversal_blocked(client):
    assert client.get("/static/..%2Fserver.py").status_code == 404
    assert client.get("/").status_code == 200
