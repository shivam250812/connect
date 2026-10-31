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


# --- automatic mapping ----------------------------------------------------------------------------
# Used when a config leaves out `mapping` (or says `mapping: auto`). Field names in the data are matched
# against common vendor spellings, in priority order, and every candidate is checked against the sample
# values: a "time" field that does not parse as a date is never used for `timestamp`, an `id` must be
# unique across the sample, an `ip` must be an IP address.

SYNONYMS: Dict[str, Dict[str, List[str]]] = {
    "user": {
        "id": ["id", "user_id", "uid", "uuid", "guid", "_id", "object_id", "account_id", "external_id"],
        "name": ["display_name", "full_name", "name", "username", "user_name", "login", "preferred_username",
                 "user_principal_name", "samaccountname"],
        "email": ["email", "mail", "email_address", "primary_email", "work_email", "user_principal_name", "upn"],
        "status": ["status", "state", "account_status", "user_status", "active", "enabled", "account_enabled"],
        "last_login": ["last_login", "last_login_at", "last_login_time", "last_sign_in", "last_sign_in_at",
                       "last_sign_in_date_time", "last_logon", "last_logon_timestamp", "last_active", "last_activity"],
        "title": ["title", "job_title", "position", "designation", "role"],
        "department": ["department", "dept", "team", "division", "org_unit", "business_unit"],
        "mfa_enabled": ["mfa_enabled", "mfa", "two_factor_enabled", "two_factor_authentication", "is_mfa_registered"],
    },
    "device": {
        "id": ["id", "device_id", "resource_id", "uuid", "guid", "_id", "asset_id", "agent_id", "endpoint_id", "machine_id",
               "sensor_id", "aid", "serial_number", "serial"],
        "hostname": ["hostname", "host_name", "computer_name", "resource_name", "device_name", "machine_name", "fqdn", "dns_name",
                     "host", "name"],
        "ip": ["ip", "ip_address", "local_ip", "ipv4", "ipv4_address", "ipv4_addresses", "ip_addresses",
               "private_ip", "primary_ip", "last_ip", "external_ip", "public_ip"],
        "os": ["os", "os_name", "operating_system", "os_type", "platform", "platform_name", "os_version"],
        "owner": ["owner", "assigned_user", "last_logged_in_user", "last_login_user", "primary_user",
                  "logged_in_user", "agent_logged_on_users", "last_user", "username", "user_name", "user", "owner_email", "assigned_to"],
        "last_seen": ["last_seen", "last_seen_at", "last_seen_time", "last_contact", "last_contact_time",
                      "agent_last_contact_time",
                      "last_check_in", "last_checkin", "last_checked_in", "last_activity", "last_sync", "updated_at"],
        "mac": ["mac", "mac_address", "mac_addresses"],
        "status": ["status", "state", "health", "health_overall", "agent_status", "computer_live_status", "connection_status",
                   "online"],
    },
    "event": {
        "id": ["id", "event_id", "alert_id", "uuid", "guid", "_id", "uid", "ghsa_id", "finding_id", "issue_id",
               "incident_id", "cve_id", "cve", "key", "number"],
        "timestamp": ["timestamp", "event_time", "time", "created_at", "created", "creation_time", "detected_at",
                      "detection_time", "occurred_at", "date", "datetime", "published_at", "published",
                      "published_date", "date_added", "first_seen", "raised_at", "generated_at", "ts", "when",
                      "updated_at"],
        "type": ["event_type", "alert_type", "type", "category", "event_name", "rule_name", "signature",
                 "threat_name", "vulnerability_name", "name", "title", "action"],
        "severity": ["severity", "severity_label", "base_severity", "level", "priority", "risk_level", "risk",
                     "criticality", "threat_level"],
        "description": ["description", "message", "msg", "summary", "short_description", "details", "reason",
                        "title", "name", "text"],
        "dst_ip": ["dst_ip", "destination_ip", "dest_ip", "server_ip", "target_ip"],
        "src_ip": ["src_ip", "source_ip", "source_ip_address", "client_ip", "remote_ip", "ip_address", "ip"],
        "dst_port": ["dst_port", "destination_port", "dest_port", "port"],
        "user": ["user", "username", "user_name", "actor", "actor_login", "principal", "account", "user_email",
                 "login"],
        "action": ["action", "disposition", "verdict", "event_action"],
        "outcome": ["outcome", "result", "event_outcome"],
        "cve": ["cve", "cve_id"],
        "product": ["product", "product_name", "package", "package_name"],
        "url": ["html_url", "web_url", "permalink", "reference_url", "link", "url"],
        "country": ["country", "country_code", "geo_country", "src_country"],
        "score": ["score", "risk_score", "cvss", "cvss_score", "base_score", "epss"],
    },
}
_REUSABLE = {"cve", "description"}  # may share a source field with another target (e.g. id and cve both = cveID)


def _norm(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _leaves(obj: Any, prefix: str = "", parent: str = "", depth: int = 0):
    """Yield (path, names-to-match, value) for every scalar in a record, up to 4 levels deep."""
    if not isinstance(obj, dict) or depth > 3:
        return
    for key, value in obj.items():
        if not isinstance(key, str) or "'" in key or not key:
            continue
        plain = re.fullmatch(r"[A-Za-z0-9_@$-]+", key)
        path = (f"{prefix}.{key}" if prefix else key) if plain else f"{prefix}['{key}']"
        last = key.rsplit(".", 1)[-1]
        names = {_norm(key), _norm(last), _norm("_".join(key.split(".")[-2:])),  # kibana.alert.rule.name -> rule_name
                 _norm(parent + "_" + last) if parent else ""} - {""}
        if isinstance(value, dict):
            yield from _leaves(value, path, last, depth + 1)
        elif isinstance(value, list):
            if value and not isinstance(value[0], (dict, list)):
                yield f"{path}[0]", names, value[0]  # e.g. ipv4Addresses: ["10.0.0.5"]
        else:
            yield path, names, value


def _fits(values: List[Any], kind: str, unique: bool) -> bool:
    present = [v for v in values if v not in (None, "")]
    if not present:
        return False
    if unique and len(present) > 1 and len({json.dumps(v, default=str) for v in present}) < len(present):
        return False
    ok = 0
    for v in present:
        try:
            if kind == "datetime":
                if isinstance(v, bool) or not 1990 <= parse_datetime(v).year <= 2100:
                    continue
            elif kind == "bool" and not isinstance(v, bool) and str(v).lower() not in ("true", "false"):
                continue
            elif kind in ("int", "float") and (isinstance(v, bool) or not re.fullmatch(r"-?\d+(\.\d+)?", str(v))):
                continue
            _cast(v, kind, None)
            ok += 1
        except (MappingError, ValueError, TypeError, OverflowError, OSError):
            pass
    return ok >= max(1, int(0.8 * len(present)))


def infer_mapping(entity: str, records: List[Any], default_type: str = "event") -> Dict[str, FieldMap]:
    """Learn a mapping from sample records. Raises MappingError if a required field cannot be found."""
    sample = [r for r in records[:50] if isinstance(r, dict)]
    if not sample:
        raise MappingError("no records to learn a mapping from")
    seen: Dict[str, Tuple[set, List[Any]]] = {}
    for rec in sample:
        for path, names, value in _leaves(rec):
            entry = seen.setdefault(path, (set(), []))
            entry[0].update(names)
            entry[1].append(value)
    types, used, out = ENTITY_FIELDS[entity], set(), {}
    for target, spellings in SYNONYMS[entity].items():
        for spelling in spellings:
            hits = [p for p, (names, values) in seen.items()
                    if _norm(spelling) in names and (target in _REUSABLE or p not in used)
                    and _fits(values, types[target], unique=target == "id")]
            if hits:
                path = min(hits, key=lambda p: (p.count(".") + p.count("["), len(p)))
                out[target] = FieldMap.model_validate({"from": path})
                used.add(path)
                break
    if entity == "event" and "type" not in out:
        out["type"] = FieldMap.model_validate({"const": default_type})
    if entity == "user" and "name" not in out and "email" in out:
        out["name"] = out["email"]
    missing = [f for f in REQUIRED[entity] if f not in out]
    if missing:
        raise MappingError(f"automatic mapping could not find {', '.join(missing)}. Fields in the data: "
                           f"{', '.join(sorted(seen)[:40])}. Add a `mapping:` block for these fields")
    return out


def mapping_yaml(mapping: Dict[str, FieldMap]) -> str:
    """The learned mapping as a `mapping:` block, ready to paste into the config to pin it."""
    lines = ["mapping:"]
    for target, fm in mapping.items():
        value = fm.from_ if fm.from_ is not None else fm.const
        text = str(value)
        if fm.from_ is None or not re.fullmatch(r"[A-Za-z0-9_.\[\]-]+", text):
            text = json.dumps(text) if fm.from_ is not None else "{const: " + json.dumps(text) + "}"
        lines.append(f"  {target}: {text}")
    return "\n".join(lines)


def find_records(data: Any) -> List[Any]:
    """`records` left out and the response is an object: use its largest list of objects (data, items, hits.hits...)."""
    best: List[Any] = []

    def walk(obj: Any, depth: int) -> None:
        nonlocal best
        if depth > 3 or not isinstance(obj, dict):
            return
        for v in obj.values():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v[:5]):
                best = v if len(v) > len(best) else best
            elif isinstance(v, dict):
                walk(v, depth + 1)

    walk(data, 0)
    return best
