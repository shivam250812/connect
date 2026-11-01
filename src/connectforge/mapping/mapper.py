"""Mapping engine (FR-5): rename fields, pick nested values, convert dates and types.

Paths: `a.b.c`, `a.b[0].c`, `a['key.with.dots']`. Each target field runs:
from/const/template -> parse_json -> path -> regex -> lower -> map -> type.
A record that cannot be mapped is rejected with a precise reason (FR-9) — it never stops the run.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from connectforge.config.schema import ENTITY_FIELDS, REQUIRED, ConnectorSpec, FieldMap
from connectforge.mapping.paths import TEMPLATE, MappingError, get_path, parse_datetime


def cast_value(value: Any, kind: str, fmt: Optional[str]) -> Any:
    if kind == "str":
        return value if isinstance(value, str) else json.dumps(value) if isinstance(value, (dict, list)) else str(value)
    if kind == "int":
        return int(float(value))
    if kind == "float":
        return float(value)
    if kind == "bool":
        return value if isinstance(value, bool) else str(value).strip().lower() in ("1", "true", "yes", "y", "active")
    if kind == "datetime":
        return parse_datetime(value, fmt).isoformat()
    if kind == "ip":
        return str(ipaddress.ip_address(str(value).strip()))
    raise MappingError(f"unknown type {kind}")


def map_field(record: Any, fm: FieldMap) -> Any:
    if fm.const is not None:
        value = fm.const
    elif fm.template is not None:
        value = TEMPLATE.sub(lambda m: "" if get_path(record, m.group(1)) is None
                              else str(get_path(record, m.group(1))), fm.template).strip()
    else:
        value = get_path(record, fm.from_)
    if value is not None and fm.parse_json:
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except json.JSONDecodeError as e:
                raise MappingError(f"invalid embedded JSON: {e.msg}") from e
        value = get_path(value, fm.path)
    elif value is not None and fm.path:
        value = get_path(value, fm.path)
    if value is not None and fm.regex:
        m = re.search(fm.regex, str(value))
        value = None if not m else (m.groupdict().get("value") or (m.group(1) if m.groups() else m.group(0)))
    if isinstance(value, str) and fm.lower:
        value = value.lower()
    if fm.map is not None and value is not None:
        value = fm.map.get(str(value), fm.map_default if fm.map_default is not None else value)
    if value in (None, ""):
        value = fm.default
    return value


def _map_generic(record: Any, spec: ConnectorSpec) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """`record` entity: id, title and timestamp are columns; every other mapped field goes into `data`."""
    row: Dict[str, Any] = {}
    extra: Dict[str, Any] = {}
    for target, fm in spec.mapping.items():
        try:
            value = map_field(record, fm)
            kind = fm.type or {"id": "str", "title": "str", "timestamp": "datetime"}.get(target)
            if value is not None and kind:
                value = cast_value(value, kind, fm.format)
        except (MappingError, ValueError, TypeError) as e:
            return None, f"{target}: {e}"
        if value is not None:
            (row if target in ("id", "title", "timestamp") else extra)[target] = value
    if not row.get("id"):  # nothing id-like in the data: the record's content is its identity
        row["id"] = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()[:16]
    row["data"] = json.dumps(extra, default=str)
    row["source"] = spec.source_name
    return row, None


def map_record(record: Any, spec: ConnectorSpec) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return (row, None) or (None, reason). The row is one user, device, event or record."""
    if spec.entity == "record":
        return _map_generic(record, spec)
    types = ENTITY_FIELDS[spec.entity]
    row: Dict[str, Any] = {}
    for target, fm in spec.mapping.items():
        try:
            value = map_field(record, fm)
            if value is not None:
                value = cast_value(value, fm.type or types[target], fm.format)
                if target == "dst_port" and not 0 <= value <= 65535:
                    raise MappingError(f"port {value} out of range")
        except (MappingError, ValueError, TypeError) as e:
            return None, f"{target}: {e}"
        if value is not None:
            row[target] = value
    missing = [f for f in REQUIRED[spec.entity] if row.get(f) in (None, "")]
    if missing:
        return None, f"missing required field(s): {', '.join(missing)}"
    row["source"] = spec.source_name
    return row, None


def preview(records: List[Any], spec: ConnectorSpec, limit: int = 5) -> List[dict]:
    out = []
    for rec in records[:limit]:
        row, error = map_record(rec, spec)
        out.append({"raw": rec, "record": row, "error": error})
    return out
