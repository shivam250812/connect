"""FR-6: secrets are encrypted or in the environment — never in config, logs or Git."""

import json
from datetime import datetime, timezone

import pytest

from connectforge.auth import make_resolver, sigv4_headers
from connectforge.vault import SecretAccessDenied, SecretMissing, Vault


def test_vault_encrypts_scopes_audits_and_redacts(tmp_path):
    log = []
    v = Vault(tmp_path / "vault.json", audit=lambda *a: log.append(a))
    v.put("okta_key", "super-secret-okta-value")
    assert "super-secret-okta-value" not in (tmp_path / "vault.json").read_text()
    assert v.get("okta_key", "okta", ["okta_key"]) == "super-secret-okta-value"
    with pytest.raises(SecretAccessDenied):
        v.get("okta_key", "github", ["github_token"])
    with pytest.raises(SecretMissing):
        v.get("nope", "okta", ["nope"])
    assert ("github", "secret.denied", "okta_key") in log and ("okta", "secret.read", "okta_key") in log
    assert v.redact("401 for super-secret-okta-value") == "401 for [REDACTED:okta_key]"
    assert "super-secret" not in str(v.metadata({"okta": ["okta_key"]}))


def test_wrong_master_key_cannot_decrypt(tmp_path):
    from cryptography.fernet import Fernet

    Vault(tmp_path / "vault.json").put("a", "value-1234")
    with pytest.raises(SecretMissing, match="cannot be decrypted"):
        Vault(tmp_path / "vault.json", master_key=Fernet.generate_key()).get("a", "c", ["a"])


def test_env_references(monkeypatch):
    resolve = make_resolver(lambda name: f"vault:{name}")
    monkeypatch.setenv("NVD_KEY", "from-env")
    assert resolve("${env:NVD_KEY}") == "from-env"
    assert resolve("${secret:x}") == "vault:x"
    with pytest.raises(SecretMissing):
        resolve("${env:NOT_SET_ANYWHERE}")


def test_gitignore_keeps_secrets_out_of_git():
    from pathlib import Path

    rules = (Path(__file__).resolve().parents[1] / ".gitignore").read_text()
    assert "data/" in rules  # vault.json + master.key live in data/


def test_sigv4_matches_botocore(monkeypatch):
    pytest.importorskip("botocore")
    import botocore.auth
    from botocore.auth import SigV4Auth
    from botocore.awsrequest import AWSRequest
    from botocore.credentials import Credentials

    url = "https://cloudtrail.ap-south-1.amazonaws.com/?b=2&a=1"
    body = b'{"MaxResults": 50}'
    headers = {"Content-Type": "application/x-amz-json-1.1",
               "X-Amz-Target": "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents"}
    when = datetime(2026, 10, 31, 6, 0, 0, tzinfo=timezone.utc)
    ours = sigv4_headers("POST", url, headers, body, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG", "ap-south-1",
                         "cloudtrail", now=when)
    monkeypatch.setattr(botocore.auth, "get_current_datetime", lambda *a, **k: when.replace(tzinfo=None))
    req = AWSRequest(method="POST", url=url, data=body, headers=dict(headers))
    SigV4Auth(Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG"), "cloudtrail", "ap-south-1").add_auth(req)
    assert ours["Authorization"].split("Signature=")[1] == req.headers["Authorization"].split("Signature=")[1]


BASE_YAML = """
id: leak-check
name: Leak check
entity: event
request: {base_url: "https://api.example.com", path: /v1/alerts, REQ}
mapping: {id: id, type: {const: alert}, timestamp: ts}
"""


import pytest as _pytest  # noqa: E402

from connectforge.spec import SpecError, parse_spec  # noqa: E402


@_pytest.mark.parametrize("req, expect", [
    ('headers: {X-API-Key: "sk_live_51HxAbCdEfGhIjKl"}', "request.headers.X-API-Key"),
    ('headers: {Authorization: "Bearer abc123def456"}', "request.headers.Authorization"),
    ('params: {api_key: "plain-text-key-1234"}', "request.params.api_key"),
    ('body: {auth: {password: "hunter2hunter2"}}', "request.body.auth.password"),
    ('params: {q: "ghp_ABCDEFabcdef1234567890ABCDEFabcdef12"}', "request.params.q"),
])
def test_plaintext_credentials_anywhere_are_rejected(req, expect):
    with _pytest.raises(SpecError) as exc:
        parse_spec(BASE_YAML.replace("REQ", req))
    assert any(expect in e for e in exc.value.errors), exc.value.errors


@_pytest.mark.parametrize("req", [
    'headers: {X-API-Key: "${secret:example_key}", Accept: application/json}',
    'headers: {Authorization: "Bearer ${env:EXAMPLE_TOKEN}"}',
    'params: {limit: 100, token_type: "${secret:t}"}',
    'headers: {kbn-xsrf: "true"}',
])
def test_references_and_harmless_headers_are_allowed(req):
    spec = parse_spec(BASE_YAML.replace("REQ", req))
    assert spec.id == "leak-check"


def test_token_pasted_in_a_description_is_rejected():
    with _pytest.raises(SpecError, match="real-looking token"):
        parse_spec(BASE_YAML.replace("REQ", "path2: x").replace(", path2: x", "")
                   .replace("name: Leak check", "name: Leak check\ndescription: 'key AKIAIOSFODNN7EXAMPLE'"))


# --- external secret managers -------------------------------------------------------------------------

import httpx as _httpx  # noqa: E402

from connectforge.secret_backends import (AwsSecretsManagerBackend, CachedBackend, EnvBackend,  # noqa: E402
                                          HashiCorpVaultBackend)


def _hashicorp(store, calls):
    def handler(request: _httpx.Request) -> _httpx.Response:
        calls.append(request)
        if request.headers.get("X-Vault-Token") != "s.root":
            return _httpx.Response(403, json={"errors": ["permission denied"]})
        name = request.url.path.split("/data/", 1)[1]
        if name not in store:
            return _httpx.Response(404, json={"errors": []})
        return _httpx.Response(200, json={"data": {"data": {"value": store[name]}, "metadata": {"version": 3}}})
    return _httpx.MockTransport(handler)


def test_hashicorp_vault_backend_scoping_cache_and_redaction(tmp_path):
    calls = []
    hv = HashiCorpVaultBackend("https://vault.example:8200", "s.root", prefix="connectforge/",
                               transport=_hashicorp({"connectforge/github_token": "ghp_fromVault123"}, calls))
    log = []
    v = Vault(tmp_path / "vault.json", audit=lambda *a: log.append(a), backend=CachedBackend(hv, ttl=300))
    assert v.backend_name == "HashiCorp Vault"
    assert v.get("github_token", "github-advisories", ["github_token"]) == "ghp_fromVault123"
    assert calls[0].url.path == "/v1/secret/data/connectforge/github_token"
    v.get("github_token", "github-advisories", ["github_token"])
    assert len(calls) == 1                                                  # second read served from cache
    with pytest.raises(SecretAccessDenied):                                 # scoping still enforced by the platform
        v.get("github_token", "other-connector", ["other_secret"])
    with pytest.raises(SecretMissing, match="not found in HashiCorp Vault"):
        v.get("missing_one", "c", ["missing_one"])
    with pytest.raises(ValueError, match="managed in HashiCorp Vault"):     # values are set in the manager
        v.put("github_token", "x")
    assert v.redact("echo ghp_fromVault123") == "echo [REDACTED:github_token]"
    assert ("github-advisories", "secret.read", "github_token (HashiCorp Vault)") in log
    meta = {m["name"]: m for m in v.metadata({"github-advisories": ["github_token"], "x": ["missing_one"]})}
    assert meta["github_token"]["set"] and not meta["missing_one"]["set"]
    assert "ghp_fromVault123" not in str(meta)


def test_hashicorp_wrong_token_is_a_clear_error(tmp_path):
    hv = HashiCorpVaultBackend("https://vault.example:8200", "wrong", transport=_hashicorp({}, []))
    v = Vault(tmp_path / "v.json", backend=CachedBackend(hv))
    with pytest.raises(SecretMissing, match="denied access"):
        v.get("a", "c", ["a"])


def test_aws_secrets_manager_backend_signs_requests(tmp_path):
    seen = []

    def handler(request: _httpx.Request) -> _httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        if body["SecretId"] == "prod/github_token":
            return _httpx.Response(200, json={"Name": "prod/github_token", "SecretString": "ghp_fromAws456"})
        return _httpx.Response(400, json={"__type": "ResourceNotFoundException", "Message": "not found"})

    aws = AwsSecretsManagerBackend("ap-south-1", "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG", session_token="tok",
                                   prefix="prod/", transport=_httpx.MockTransport(handler))
    v = Vault(tmp_path / "v.json", backend=CachedBackend(aws))
    assert v.get("github_token", "gh", ["github_token"]) == "ghp_fromAws456"
    req = seen[0]
    assert req.headers["X-Amz-Target"] == "secretsmanager.GetSecretValue"
    assert req.headers["Authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    assert "/ap-south-1/secretsmanager/aws4_request" in req.headers["Authorization"]
    assert "x-amz-security-token" in req.headers["Authorization"]          # session token is signed too
    with pytest.raises(SecretMissing, match="not found in AWS Secrets Manager"):
        v.get("nope", "gh", ["nope"])


def test_env_backend(tmp_path, monkeypatch):
    monkeypatch.setenv("CF_SECRET_GITHUB_TOKEN", "ghp_fromEnv789")
    v = Vault(tmp_path / "v.json", backend=CachedBackend(EnvBackend()))
    assert v.get("github_token", "gh", ["github_token"]) == "ghp_fromEnv789"
    with pytest.raises(SecretMissing, match="CF_SECRET_NOPE"):
        v.get("nope", "gh", ["nope"])


def test_backend_selected_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("CF_SECRETS_BACKEND", "env")
    assert Vault(tmp_path / "v.json").backend_name == "environment variables"
    monkeypatch.setenv("CF_SECRETS_BACKEND", "hashicorp")
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    with pytest.raises(ValueError, match="VAULT_ADDR"):
        Vault(tmp_path / "v.json")
