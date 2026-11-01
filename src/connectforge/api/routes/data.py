"""Stored data (FR-11): per-connection data views with typed columns, tables, quarantine, audit log."""

from __future__ import annotations

import json
import re
from typing import Any, List, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse

from connectforge.api import deps
from connectforge.config.schema import ENTITY_FIELDS, TABLES

router = APIRouter()


# --- data (FR-11) ---------------------------------------------------------------------------------

_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2})?")


def _kind(key: str, values: List[Any]) -> str:
    """Display type of a column, for formatting in the page."""
    present = [v for v in values if v not in (None, "")]
    if not present:
        return "str"
    if all(isinstance(v, bool) for v in present):
        return "bool"
    if all(isinstance(v, (int, float)) and not isinstance(v, bool) for v in present):
        return "number"
    if all(isinstance(v, str) and _ISO.match(v) for v in present):
        return "datetime"
    if all(isinstance(v, str) and v.startswith(("http://", "https://")) for v in present):
        return "url"
    if all(isinstance(v, (dict, list)) for v in present):
        return "json"
    return "str"


def _label(key: str) -> str:
    known = {"id": "ID", "ip": "IP", "src_ip": "Source IP", "dst_ip": "Destination IP", "dst_port": "Port",
             "os": "OS", "mac": "MAC", "url": "Link", "html_url": "Link", "web_url": "Link", "cve": "CVE",
             "mfa_enabled": "MFA", "fetched_at": "Fetched", "stargazers_count": "Stars"}
    if key in known:
        return known[key]
    words = key.replace("_", " ").strip()
    return re.sub(r"\b(ip|os|id|url|mac|cve|api)\b", lambda m: m.group(1).upper(), words.capitalize())


def data_view(spec, rows: List[dict]) -> dict:
    """Rows of one endpoint, framed for display: the columns that matter, in order, each with a type."""
    if spec.entity == "record":
        for r in rows:
            try:
                extra = json.loads(r.pop("data") or "{}")
            except ValueError:
                extra = {}
            r.update({k: v for k, v in extra.items() if k not in r})
    fixed = ["id"]
    if spec.columns:
        order = fixed + [c for c in spec.columns if c != "id"]
    elif spec.entity == "record":
        keys = list(dict.fromkeys(k for r in rows for k in r))
        order = fixed + [k for k in ("title", "timestamp") if k in keys] + \
            [k for k in keys if k not in ("id", "title", "timestamp", "source", "fetched_at", "connector")]
    else:
        mapped = list(spec.mapping or {}) or list(ENTITY_FIELDS[spec.entity])
        order = fixed + [f for f in ENTITY_FIELDS[spec.entity] if f in mapped and f != "id"]
    order = [c for c in order if any(r.get(c) not in (None, "") for r in rows)] or fixed
    order.append("fetched_at")
    types = ENTITY_FIELDS.get(spec.entity, {})
    columns = []
    for c in order:
        declared = types.get(c) if spec.entity != "record" or c in ("id", "title", "timestamp") else None
        kind = {"datetime": "datetime", "int": "number", "float": "number", "bool": "bool", "ip": "ip"}.get(
            declared or "", None) or ("datetime" if c == "fetched_at" else _kind(c, [r.get(c) for r in rows]))
        columns.append({"key": c, "label": _label(c), "type": kind})
    return {"entity": spec.entity, "table": TABLES[spec.entity], "columns": columns,
            "rows": [{c["key"]: r.get(c["key"]) for c in columns} | {"_raw": r} for r in rows]}


@router.get("/api/connectors/{cid}/data")
def connector_data(cid: str, q: Optional[str] = None, limit: int = 200):
    """What this endpoint has stored, ready for display."""
    st = deps.connector_state(cid)
    spec = st.spec if st.spec.mapping is not None or not st.learned else st.spec.model_copy(update={"mapping": st.learned})
    rows = deps.platform.store.records(spec.entity, None, min(limit, 1000), q, connector=cid)
    total = deps.platform.store.count_for_connector(spec.entity, cid)
    return {**data_view(spec, rows), "total": total, "connector": cid, "name": spec.name, "last_run": st.last_run}


# the .jsonl route must come first, or {table} would capture "events.jsonl"
@router.get("/api/records/{table}.jsonl", response_class=PlainTextResponse)
def records_jsonl(table: str, source: Optional[str] = None):
    return "\n".join(json.dumps(r) for r in records(table, source, None, 100_000)) + "\n"


@router.get("/api/records/{table}")
def records(table: str, source: Optional[str] = None, q: Optional[str] = None, limit: int = 100):
    entity = {v: k for k, v in TABLES.items()}.get(table)
    if not entity:
        raise HTTPException(404, "table must be users, devices, events or records")
    return deps.platform.store.records(entity, source, min(limit, 1000), q)


@router.get("/api/quarantine")
def quarantine(connector: Optional[str] = None, limit: int = 100):
    return deps.platform.store.quarantined(connector, min(limit, 1000))


@router.get("/api/audit")
def audit(limit: int = 100):
    return deps.platform.store.audit_log(min(limit, 500))
