"""Command line helpers.

    python -m connectforge.cli seed-demo          # load the lab (mock) credentials into the vault
    python -m connectforge.cli remove-lab         # delete lab credentials and everything lab connectors stored
    python -m connectforge.cli test FILE|ID        # B-3: test the connection (one authenticated request)
    python -m connectforge.cli set-secret NAME    # prompt for a value (never echoed, never in shell history)
    python -m connectforge.cli validate FILE...   # lint connector files without starting the platform
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

from .mock import sources as mock
from .spec import SpecError, parse_spec
from .store import Store
from .vault import Vault

DATA = Path("data")


def _vault() -> Vault:
    DATA.mkdir(exist_ok=True)
    store = Store(DATA / "state.db")
    return Vault(DATA / "vault.json", audit=store.audit)


def _lab_secrets() -> dict:
    from .mock import enterprise as ent

    return {"prisma_lab_key": ent.PRISMA_KEY, "prisma_lab_secret": ent.PRISMA_SECRET,
            "fmc_lab_password": ent.FMC_PASS, "zia_lab_api_key": ent.ZIA_KEY,
            "zia_lab_password": ent.ZIA_PASS, "oauth_lab_client_secret": ent.OAUTH_SECRET,
            "google_lab_service_account": ent.GOOGLE_KEY_JSON, "cortex_lab_key": ent.CORTEX_KEY,
            "xmlfw_lab_password": "lab-fw-pass", "okta_lab_token": mock.OKTA_TOKEN, "aws_access_key_id": mock.AWS_KEY_ID,
            "aws_secret_access_key": mock.AWS_SECRET, "edr_api_key": mock.EDR_KEY}


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 1
    cmd, *rest = argv
    if cmd == "seed-demo":
        v = _vault()
        if v.backend:
            print(f"secrets are managed in {v.backend.name}; store the lab secrets there to use lab connectors")
            return 0
        for name, value in _lab_secrets().items():
            v.put(name, value, actor="cli")  # lab-only names; your real secrets are never touched
        print("lab secrets refreshed (encrypted) in data/vault.json — real API keys: use set-secret")
        return 0
    if cmd == "remove-lab":
        v = _vault()
        if not v.backend:
            for name in _lab_secrets():
                v.delete(name, actor="cli")
        store = Store(DATA / "connectforge.db")
        ids = {r["connector"] for t in ("runs", "users", "devices", "events")
               for r in store._rows(f"SELECT DISTINCT connector FROM {t}") if (r["connector"] or "").startswith("lab-")}
        rows = sum(store.purge(cid) for cid in sorted(ids))
        print(f"removed lab secrets and {rows} rows from {len(ids)} lab connectors; restart without CF_LAB=1")
        return 0
    if cmd == "set-secret" and len(rest) == 1:
        v = _vault()
        if v.backend:
            print(f"secrets are managed in {v.backend.name}; set '{rest[0]}' there")
            return 1
        v.put(rest[0], getpass.getpass(f"value for {rest[0]}: "), actor="cli")
        print(f"stored {rest[0]}")
        return 0
    if cmd == "test" and len(rest) == 1:
        import asyncio
        import os
        from .runtime import Platform

        p = Platform(Path(os.environ.get("CF_CONNECTORS_DIR", "connectors")), DATA)
        p.load_dir()
        target = Path(rest[0]).read_text() if Path(rest[0]).exists() else rest[0]
        result = asyncio.run(p.test_connection(target))
        print(("PASS " if result["ok"] else "FAIL ") + f"{result['connector']}: {result['detail']} "
              f"({result.get('latency_ms', '?')} ms)")
        return 0 if result["ok"] else 1
    if cmd == "validate" and rest:
        bad = 0
        for f in rest:
            try:
                spec = parse_spec(Path(f).read_text())
                print(f"OK    {f}  ({spec.id}: {spec.entity}s via {spec.kind}, auth={spec.auth.type}, "
                      f"pagination={spec.pagination.type}, every {spec.schedule.seconds}s)")
            except SpecError as e:
                bad += 1
                print(f"FAIL  {f}")
                for err in e.errors:
                    print(f"      - {err}")
        return 1 if bad else 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
