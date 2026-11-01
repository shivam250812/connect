"""Secrets: write-only values, metadata, rotation reload, which backend is in use."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from connectforge.api import deps

router = APIRouter()


# --- secrets (write-only) & audit --------------------------------------------------------------


class SecretValue(BaseModel):
    value: str


@router.get("/api/secrets")
def secrets():
    used = {cid: st.spec.secret_names for cid, st in deps.platform.states.items()}
    used["notifications"] = deps.platform.notifier.secret_names()
    return deps.platform.vault.metadata(used)


@router.put("/api/secrets/{name}")
def put_secret(name: str, body: SecretValue, actor: str = Depends(deps.admin)):
    try:
        deps.platform.vault.put(name, body.value, actor=actor)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    return {"stored": name, "refreshed": deps.platform.secret_changed(name)}


@router.post("/api/secrets/{name}/refresh")
def refresh_secret(name: str, actor: str = Depends(deps.admin)):
    """Rotated in the secret manager? Pick up the new value now instead of after the cache expires."""
    affected = deps.platform.secret_changed(name)
    deps.platform.store.audit(actor, "secret.refresh", name)
    return {"refreshed": affected}


@router.get("/api/secrets/backend")
def secrets_backend():
    return {"backend": deps.platform.vault.backend_name, "writable": deps.platform.vault.backend is None}
