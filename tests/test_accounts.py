"""Sign up / log in: the whole API is behind a login, passwords are hashed, sessions are cookies."""

import pytest
from fastapi.testclient import TestClient

from connectforge.api import deps
from connectforge.api.app import app
from connectforge.security.accounts import Accounts, verify_password
from connectforge.storage.store import Store


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CF_AUTH", "on")
    monkeypatch.delenv("CF_ADMIN_TOKEN", raising=False)
    store = Store(tmp_path / "db.sqlite")
    monkeypatch.setattr(deps, "accounts", Accounts(store))
    return TestClient(app)


def test_everything_needs_a_login(client):
    assert client.get("/api/overview").status_code == 401
    assert client.get("/api/secrets").status_code == 401
    assert client.post("/api/connectors/validate", json={"yaml": "x"}).status_code == 401
    assert client.get("/").status_code == 200                      # the page loads and shows the sign-in form
    assert client.get("/api/auth/status").json() == {"has_accounts": False, "signup_open": True}


def test_signup_logs_in_and_password_is_hashed(client):
    r = client.post("/api/auth/signup", json={"email": "Abhivir2005@Gmail.com", "password": "correct horse 9"})
    assert r.status_code == 200 and r.json()["email"] == "abhivir2005@gmail.com"
    cookie = r.headers["set-cookie"]
    assert "cf_session=" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert client.get("/api/overview").status_code == 200          # the cookie is the session
    assert client.get("/api/auth/me").json()["email"] == "abhivir2005@gmail.com"
    row = deps.accounts.store._rows("SELECT pw_hash FROM accounts")[0]["pw_hash"]
    assert row.startswith("scrypt$") and "correct horse" not in row and verify_password("correct horse 9", row)
    token_rows = deps.accounts.store._rows("SELECT token_hash FROM sessions")
    assert client.cookies.get("cf_session") not in [t["token_hash"] for t in token_rows]   # only the hash is kept


def test_login_logout_and_bad_input(client):
    client.post("/api/auth/signup", json={"email": "a@acme.example", "password": "long enough 1"})
    client.post("/api/auth/logout")
    assert client.get("/api/overview").status_code == 401
    assert client.post("/api/auth/login", json={"email": "a@acme.example", "password": "nope"}).json()["detail"] == "wrong email or password"
    assert client.post("/api/auth/login", json={"email": "who@x.example", "password": "nope"}).json()["detail"] == "wrong email or password"
    assert client.post("/api/auth/login", json={"email": "A@acme.example", "password": "long enough 1"}).status_code == 200
    assert client.get("/api/overview").status_code == 200
    for bad, why in [({"email": "not-an-email", "password": "long enough 1"}, "valid email"),
                     ({"email": "b@acme.example", "password": "short"}, "at least 8"),
                     ({"email": "a@acme.example", "password": "long enough 1"}, "already exists"),
                     ({"email": "c@acme.example", "password": "password"}, "too easy")]:
        r = client.post("/api/auth/signup", json=bad)
        assert r.status_code == 400 and why in r.json()["detail"]


def test_five_wrong_passwords_lock_the_account(client):
    client.post("/api/auth/signup", json={"email": "a@acme.example", "password": "long enough 1"})
    client.post("/api/auth/logout")
    for _ in range(5):
        client.post("/api/auth/login", json={"email": "a@acme.example", "password": "guess"})
    r = client.post("/api/auth/login", json={"email": "a@acme.example", "password": "long enough 1"})
    assert r.status_code == 401 and "15 minutes" in r.json()["detail"]


def test_actions_are_audited_under_the_users_email_and_signup_can_be_closed(client, monkeypatch):
    client.post("/api/auth/signup", json={"email": "a@acme.example", "password": "long enough 1"})
    client.put("/api/secrets/demo", json={"value": "v"})
    assert any(e["actor"] == "a@acme.example" and e["action"] == "secret.put" for e in client.get("/api/audit").json())
    monkeypatch.setenv("CF_SIGNUP", "closed")
    r = client.post("/api/auth/signup", json={"email": "b@acme.example", "password": "long enough 1"})
    assert r.status_code == 400 and "closed" in r.json()["detail"]


def test_registered_emails_receive_notifications(client):
    client.post("/api/auth/signup", json={"email": "a@acme.example", "password": "long enough 1"})
    n = deps.platform.notifier
    assert "a@acme.example" in n.recipients({"to_registered": True, "to": ["soc@acme.example"]})
    assert n.recipients({"to_registered": False, "to": ["soc@acme.example"]}) == ["soc@acme.example"]
