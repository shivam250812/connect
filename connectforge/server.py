"""HTTP API + health page (FR-10).

    uvicorn connectforge.server:app --port 8100

Mutating endpoints require `X-Admin-Token` when CF_ADMIN_TOKEN is set.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from .runtime import FetchError, Platform
from .spec import ENTITY_FIELDS, REQUIRED, TABLES, SpecError, masked, parse_spec
from .vault import SecretAccessDenied, SecretMissing

STATIC = Path(__file__).parent / "static"
DIRS = [Path(d) for d in os.environ.get("CF_CONNECTORS_DIRS", "connectors:lab:lab/enterprise").split(":") if d]
DATA_DIR = Path(os.environ.get("CF_DATA_DIR", "data"))
EXAMPLE_DIRS = [Path("examples"), Path("catalog"), Path("lab"), Path("connectors")]

platform = Platform(DIRS[0], DATA_DIR)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    platform.load_dir(DIRS[1:])
    if os.environ.get("CF_SCHEDULER", "1") == "1":
        platform.start()
    syslog = None
    if os.environ.get("CF_SYSLOG_PORT"):
        from .syslog import start_syslog

        # bind to localhost by default; set CF_SYSLOG_HOST=0.0.0.0 to accept devices on the network
        syslog = await start_syslog(int(os.environ["CF_SYSLOG_PORT"]), DATA_DIR / "feeds",
                                    os.environ.get("CF_SYSLOG_HOST", "127.0.0.1"))
    yield
    if syslog:
        syslog.close()
    await platform.stop()


app = FastAPI(title="ConnectForge", version="0.2.0", lifespan=lifespan)


def admin(x_admin_token: Optional[str] = Header(None)) -> str:
    expected = os.environ.get("CF_ADMIN_TOKEN")
    if expected and x_admin_token != expected:
        raise HTTPException(401, "admin token required")
    return "admin"


def _state(cid: str):
    if cid not in platform.states:
        raise HTTPException(404, f"unknown connector '{cid}'")
    return platform.states[cid]


class ConnectorText(BaseModel):
    yaml: str


# --- health ------------------------------------------------------------------------------------


@app.get("/api/overview")
def overview():
    conns = [platform.health(cid) for cid in sorted(platform.states, key=lambda c: (c.startswith("lab-"), c))]
    counts = platform.store.counts()
    return {
        "connectors": conns,
        "load_errors": platform.load_errors,
        "tables": {t: sum(v.values()) for t, v in counts.items()},
        "by_source": counts,
        "totals": {
            "connectors": len(conns),
            "healthy": sum(c["status"] == "healthy" for c in conns),
            "attention": sum(c["status"] in ("degraded", "failing") for c in conns),
            "quarantined": platform.store.quarantine_count(),
            "alerts": len(platform.store.alerts(1000)),
        },
    }


@app.get("/api/connectors/{cid}")
def connector(cid: str):
    st = _state(cid)
    return {"health": platform.health(cid), "spec": masked(st.spec), "runs": platform.store.runs(cid, 25),
            "quarantined": platform.store.quarantined(cid, 25)}


# --- config, not code ----------------------------------------------------------------------------


@app.get("/api/schema")
def schema():
    """The common schema — used by the web form (B-5) to offer target fields."""
    return {e: {"table": TABLES[e], "fields": ENTITY_FIELDS[e], "required": REQUIRED[e]} for e in ENTITY_FIELDS}


@app.post("/api/connectors/validate")
def validate(body: ConnectorText):
    try:
        spec = parse_spec(body.yaml)
    except SpecError as e:
        return {"valid": False, "errors": e.errors}
    return {"valid": True, "errors": [], "id": spec.id, "summary": {
        "entity": spec.entity, "table": TABLES[spec.entity], "kind": spec.kind, "auth": spec.auth.type,
        "pagination": spec.pagination.type, "every_seconds": spec.schedule.seconds,
        "fields": sorted(spec.mapping), "secrets": spec.secret_names,
        "hosts": sorted(spec.egress_hosts()) if spec.kind == "http" else []}}


@app.post("/api/connectors")
def add_connector(body: ConnectorText, actor: str = Depends(admin)):
    try:
        spec = platform.add(body.yaml, actor=actor)
    except SpecError as e:
        raise HTTPException(400, {"errors": e.errors}) from e
    return platform.health(spec.id)


@app.delete("/api/connectors/{cid}")
def delete_connector(cid: str, actor: str = Depends(admin)):
    _state(cid)
    return {"removed": cid, "archived_to": platform.remove(cid, actor)}


@app.post("/api/connectors/{cid}/run")
async def run_now(cid: str, actor: str = Depends(admin)):
    _state(cid)
    return await platform.run(cid, trigger=f"manual:{actor}")


@app.post("/api/connectors/{cid}/{action}")
def connector_action(cid: str, action: str, actor: str = Depends(admin)):
    st = _state(cid)
    if action not in ("pause", "resume", "reset-cursor"):
        raise HTTPException(404)
    if action == "reset-cursor":
        platform.store.reset_cursor(cid)
    else:
        st.paused = action == "pause"
    platform.store.audit(actor, f"connector.{action}", cid)
    return platform.health(cid)


@app.post("/api/test")
async def test_connection(body: ConnectorText):
    """B-3: test a saved connector (pass its id) or an unsaved YAML — one request, nothing stored."""
    try:
        return await platform.test_connection(body.yaml)
    except SpecError as e:
        raise HTTPException(400, {"errors": e.errors}) from e


@app.post("/api/preview")
async def preview(body: ConnectorText):
    try:
        return await platform.preview(body.yaml)
    except SpecError as e:
        raise HTTPException(400, {"errors": e.errors}) from e
    except (FetchError, SecretMissing, SecretAccessDenied, OSError) as e:
        raise HTTPException(502, platform.vault.redact(str(e))) from e


# --- data (FR-11) ---------------------------------------------------------------------------------


@app.get("/api/records/{table}")
def records(table: str, source: Optional[str] = None, q: Optional[str] = None, limit: int = 100):
    entity = {v: k for k, v in TABLES.items()}.get(table)
    if not entity:
        raise HTTPException(404, "table must be users, devices or events")
    return platform.store.records(entity, source, min(limit, 1000), q)


@app.get("/api/records/{table}.jsonl", response_class=PlainTextResponse)
def records_jsonl(table: str, source: Optional[str] = None):
    return "\n".join(json.dumps(r) for r in records(table, source, None, 100_000)) + "\n"


@app.get("/api/quarantine")
def quarantine(connector: Optional[str] = None, limit: int = 100):
    return platform.store.quarantined(connector, min(limit, 1000))


@app.get("/api/alerts")
def alerts(limit: int = 50):
    return platform.store.alerts(limit)


# --- secrets (write-only) & audit --------------------------------------------------------------


class SecretValue(BaseModel):
    value: str


@app.get("/api/secrets")
def secrets():
    used = {cid: st.spec.secret_names for cid, st in platform.states.items()}
    used["alerts"] = ["alert_webhook"]
    return platform.vault.metadata(used)


@app.put("/api/secrets/{name}")
def put_secret(name: str, body: SecretValue, actor: str = Depends(admin)):
    platform.vault.put(name, body.value, actor=actor)
    return {"stored": name}


@app.get("/api/audit")
def audit(limit: int = 100):
    return platform.store.audit_log(min(limit, 500))


@app.get("/api/examples")
def examples():
    out = {}
    for folder in EXAMPLE_DIRS:
        if folder.exists():
            out.update({str(p.relative_to(folder.parent).with_suffix("")): p.read_text()
                        for p in sorted(folder.rglob("*.y*ml"))})
    return out


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")


@app.get("/static/{name}")
def static(name: str):
    path = (STATIC / name).resolve()
    if path.parent != STATIC.resolve() or not path.exists():
        raise HTTPException(404)
    return FileResponse(path)
