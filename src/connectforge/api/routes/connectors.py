"""Connections: health overview, validate / add / edit / remove configs, run, test and preview."""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from connectforge.api import deps
from connectforge.config.intake import corrected_yaml
from connectforge.config.schema import (
    ENTITY_FIELDS,
    REQUIRED,
    TABLES,
    SpecError,
    masked,
    parse_specs_with_fixes,
)
from connectforge.engine import FetchError
from connectforge.security.vault import SecretAccessDenied, SecretMissing
from connectforge.settings import DIRS, EXAMPLE_DIRS

router = APIRouter()


class ConnectorText(BaseModel):
    yaml: str
    endpoint: Optional[str] = None   # multi-endpoint file: which endpoint to test / preview


# --- health ------------------------------------------------------------------------------------


@router.get("/api/overview")
def overview():
    conns = [deps.platform.health(cid) for cid in sorted(deps.platform.states, key=lambda c: (c.startswith("lab-"), c))]
    counts = deps.platform.store.counts()
    return {
        "connectors": conns,
        "load_errors": deps.platform.load_errors,
        "tables": {t: sum(v.values()) for t, v in counts.items()},
        "by_source": counts,
        "totals": {
            "connectors": len(conns),
            "healthy": sum(c["status"] == "healthy" for c in conns),
            "attention": sum(c["status"] in ("degraded", "failing") for c in conns),
            "quarantined": deps.platform.store.quarantine_count(),
            "alerts": len(deps.platform.store.alerts(1000)),
        },
    }


@router.get("/api/connectors/{cid}")
def connector(cid: str):
    st = deps.connector_state(cid)
    return {"health": deps.platform.health(cid), "spec": masked(st.spec), "runs": deps.platform.store.runs(cid, 25),
            "quarantined": deps.platform.store.quarantined(cid, 25)}


# --- config, not code ----------------------------------------------------------------------------


@router.get("/api/schema")
def schema():
    """The common schema — used by the web form (B-5) to offer target fields."""
    return {e: {"table": TABLES[e], "fields": ENTITY_FIELDS[e], "required": REQUIRED[e]} for e in ENTITY_FIELDS}


@router.post("/api/connectors/validate")
def validate(body: ConnectorText):
    try:
        specs, fixes = parse_specs_with_fixes(body.yaml)
    except SpecError as e:
        return {"valid": False, "errors": e.errors}
    endpoints = [{
        "id": s.id, "endpoint": s.endpoint, "name": s.name, "entity": s.entity, "table": TABLES[s.entity],
        "kind": s.kind, "auth": s.auth.type, "pagination": s.pagination.type, "every_seconds": s.schedule.seconds,
        "path": s.request.path if s.request else (s.file.path if s.file else ""),
        "fields": sorted(s.mapping) if s.mapping is not None else ["automatic"], "secrets": s.secret_names,
        "hosts": sorted(s.egress_hosts()) if s.kind == "http" else []} for s in specs]
    return {"valid": True, "errors": [], "id": specs[0].integration or specs[0].id,
            "name": specs[0].integration_name or specs[0].name, "endpoints": endpoints, "summary": endpoints[0],
            "fixes": fixes, "corrected": corrected_yaml(body.yaml) if fixes else None}


@router.post("/api/connectors")
def add_connector(body: ConnectorText, actor: str = Depends(deps.admin)):
    try:
        specs = deps.platform.add(body.yaml, actor=actor)
    except SpecError as e:
        raise HTTPException(400, {"errors": e.errors}) from e
    return {**deps.platform.health(specs[0].id), "ids": [s.id for s in specs]}


@router.get("/api/connectors/{cid}/yaml", response_class=PlainTextResponse)
def connector_yaml(cid: str):
    """Current YAML for editing in the page (contains only secret *names*, never values)."""
    deps.connector_state(cid)
    return deps.platform.yaml_text(cid)


@router.post("/api/reload")
def reload_configs(actor: str = Depends(deps.admin)):
    """Re-read connector files edited on disk — no restart needed."""
    return deps.platform.reload_dir(DIRS[1:], actor=actor)


@router.delete("/api/connectors/{cid}")
def delete_connector(cid: str, actor: str = Depends(deps.admin)):
    deps.connector_state(cid)
    return {"removed": cid, "archived_to": deps.platform.remove(cid, actor)}


@router.post("/api/connectors/{cid}/run")
async def run_now(cid: str, actor: str = Depends(deps.admin)):
    deps.connector_state(cid)
    return await deps.platform.run(cid, trigger=f"manual:{actor}")


@router.post("/api/connectors/{cid}/{action}")
def connector_action(cid: str, action: str, actor: str = Depends(deps.admin)):
    st = deps.connector_state(cid)
    if action not in ("pause", "resume", "reset-cursor"):
        raise HTTPException(404)
    if action == "reset-cursor":
        deps.platform.store.reset_cursor(cid)
    else:
        st.paused = action == "pause"
    deps.platform.store.audit(actor, f"connector.{action}", cid)
    return deps.platform.health(cid)


@router.post("/api/test")
async def test_connection(body: ConnectorText):
    """B-3: test a saved connector (pass its id) or an unsaved YAML — one request, nothing stored."""
    try:
        return await deps.platform.test_connection(body.yaml, body.endpoint)
    except SpecError as e:
        raise HTTPException(400, {"errors": e.errors}) from e


@router.post("/api/preview")
async def preview(body: ConnectorText):
    try:
        return await deps.platform.preview(body.yaml, endpoint=body.endpoint)
    except SpecError as e:
        raise HTTPException(400, {"errors": e.errors}) from e
    except (FetchError, SecretMissing, SecretAccessDenied, OSError) as e:
        raise HTTPException(502, deps.platform.vault.redact(str(e))) from e


@router.get("/api/examples")
def examples():
    out = {}
    for folder in EXAMPLE_DIRS:
        if folder.exists():
            out.update({str(p.relative_to(folder.parent).with_suffix("")): p.read_text()
                        for p in sorted(folder.rglob("*.y*ml"))})
    return out
