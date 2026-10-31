"""Mapping engine (FR-5): rename fields, pick nested values, convert dates and types.

Paths: `a.b.c`, `a.b[0].c`, `a['key.with.dots']`. Each target field runs:
from/const/template -> parse_json -> path -> regex -> lower -> map -> type.
A record that cannot be mapped is rejected with a precise reason (FR-9) — it never stops the run.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .spec import ENTITY_FIELDS, REQUIRED, ConnectorSpec, FieldMap

_TOKEN = re.compile(r"\[(\d+)\]|\['([^']*)'\]|([^.\[\]]+)")
_TEMPLATE = re.compile(r"\{([^{}]+)\}")


class MappingError(ValueError):
    pass


def get_path(obj: Any, path: Optional[str]) -> Any:
    if path is None or path in ("", "$"):
        return obj
    cur = obj
    for idx, key, name in _TOKEN.findall(path):
        if cur is None:
            return None
        if idx:
            cur = cur[int(idx)] if isinstance(cur, list) and int(idx) < len(cur) else None
        else:
            cur = cur.get(key or name) if isinstance(cur, dict) else None
    return cur


def set_path(obj: dict, path: str, value: Any) -> None:
    """Set a nested value, creating dicts/lists as needed: `request_data.filters[0].value`."""
    tokens = [(int(i) if i else (k or n)) for i, k, n in _TOKEN.findall(path)]
    cur: Any = obj
    for tok, nxt in zip(tokens, tokens[1:]):
        empty = [] if isinstance(nxt, int) else {}
        if isinstance(tok, int):
            while len(cur) <= tok:
                cur.append(None)
            if not isinstance(cur[tok], (dict, list)):
                cur[tok] = empty
            cur = cur[tok]
        else:
            if not isinstance(cur.get(tok), (dict, list)):
                cur[tok] = empty
            cur = cur[tok]
    last = tokens[-1]
    if isinstance(last, int):
        while len(cur) <= last:
            cur.append(None)
    cur[last] = value


def xml_to_dict(text: str) -> Any:
    """Parse an XML API response into dicts/lists. DOCTYPE/entities are refused (XXE / entity bombs)."""
    import xml.etree.ElementTree as ET

    if re.search(r"<!DOCTYPE|<!ENTITY", text[:2000], re.I):
        raise MappingError("XML with DOCTYPE/ENTITY declarations is refused")

    def convert(el) -> Any:
        node: Dict[str, Any] = {f"@{k}": v for k, v in el.attrib.items()}
        for child in el:
            tag = child.tag.split("}")[-1]
            val = convert(child)
            if tag in node:
                node[tag] = node[tag] if isinstance(node[tag], list) else [node[tag]]
                node[tag].append(val)
            else:
                node[tag] = val
        text = (el.text or "").strip()
        if not node:
            return text
        if text:
            node["#text"] = text
        return node

    root = ET.fromstring(text)
    return {root.tag.split("}")[-1]: convert(root)}


_CEF_EXT = re.compile(r"(\w[\w.\[\]-]*)=((?:\\=|[^=])*?)(?=\s+\w[\w.\[\]-]*=|$)")


def parse_cef(line: str) -> Dict[str, Any]:
    """ArcSight Common Event Format: `CEF:0|Vendor|Product|Version|SigID|Name|Severity|k=v k=v`."""
    start = line.find("CEF:")
    if start < 0:
        raise MappingError("not a CEF line")
    parts, buf, i, body = [], "", 0, line[start + 4:]
    while i < len(body) and len(parts) < 7:
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            buf += body[i + 1]
            i += 2
            continue
        if ch == "|":
            parts.append(buf)
            buf = ""
        else:
            buf += ch
        i += 1
    if len(parts) < 7:
        raise MappingError("CEF header needs 7 pipe-separated fields")
    names = ["cef_version", "device_vendor", "device_product", "device_version", "signature_id", "name", "severity"]
    out: Dict[str, Any] = dict(zip(names, parts))
    out["syslog_prefix"] = line[:start].strip()
    for key, val in _CEF_EXT.findall(body[i:].strip()):
        out[key] = val.replace("\\=", "=").replace("\\\\", "\\").strip()
    return out


def parse_datetime(value: Any, fmt: Optional[str] = None) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, date):
        dt = datetime(value.year, value.month, value.day)
    elif isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", value)):
        num = float(value)
        dt = datetime.fromtimestamp(num / 1000 if num > 1e11 else num, tz=timezone.utc)
    elif isinstance(value, str) and fmt:
        dt = datetime.strptime(value, fmt)
        if "%Y" not in fmt and "%y" not in fmt:
            dt = dt.replace(year=datetime.now(timezone.utc).year)
    elif isinstance(value, str):
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    else:
        raise MappingError(f"cannot parse a date from {type(value).__name__}")
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _cast(value: Any, kind: str, fmt: Optional[str]) -> Any:
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
        value = _TEMPLATE.sub(lambda m: "" if get_path(record, m.group(1)) is None
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


def map_record(record: Any, spec: ConnectorSpec) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Return (row, None) or (None, reason). The row is one user, device or event."""
    types = ENTITY_FIELDS[spec.entity]
    row: Dict[str, Any] = {}
    for target, fm in spec.mapping.items():
        try:
            value = map_field(record, fm)
            if value is not None:
                value = _cast(value, fm.type or types[target], fm.format)
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
