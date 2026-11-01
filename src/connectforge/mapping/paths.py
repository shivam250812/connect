"""Reading values out of records: nested paths (`a.b[0].c`, `a['key.with.dots']`), XML and CEF
parsing, and date parsing (FR-5)."""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from typing import Any, Dict, Optional

_TOKEN = re.compile(r"\[(\d+)\]|\['([^']*)'\]|([^.\[\]]+)")


TEMPLATE = re.compile(r"\{([^{}]+)\}")


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
    for tok, nxt in zip(tokens, tokens[1:], strict=False):
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

    root = ET.fromstring(text)  # noqa: S314 - DOCTYPE/ENTITY refused above, so no entity expansion or XXE
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
    out: Dict[str, Any] = dict(zip(names, parts, strict=False))
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
