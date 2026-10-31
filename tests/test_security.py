"""FR-6: secrets are encrypted or in the environment — never in config, logs or Git."""

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
