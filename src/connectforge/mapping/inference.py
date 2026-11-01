"""Automatic mapping: learn which source field goes into which common-schema field from real records,
find the list of records in a response, and find where the next page is."""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Tuple

from connectforge.config.schema import ENTITY_FIELDS, REQUIRED, FieldMap
from connectforge.mapping.mapper import cast_value
from connectforge.mapping.paths import MappingError, parse_datetime

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
            cast_value(v, kind, None)
            ok += 1
        except (MappingError, ValueError, TypeError, OverflowError, OSError):
            pass
    return ok >= max(1, int(0.8 * len(present)))


_RECORD_SYNONYMS = {
    "id": sorted({*SYNONYMS["event"]["id"], *SYNONYMS["device"]["id"], *SYNONYMS["user"]["id"]},
                 key=lambda s: (s != "id", s)),
    "title": ["title", "name", "display_name", "summary", "subject", "hostname", "label", "description"],
    "timestamp": SYNONYMS["event"]["timestamp"],
}


def _column_name(path: str) -> str:
    """`os.name` -> `os_name`, `_source['kibana.alert.severity']` -> `kibana_alert_severity`."""
    name = re.sub(r"\[\d+\]", "", path.split("['")[-1] if "['" in path else path)
    name = re.sub(r"(?<=[a-z0-9])([A-Z])", r"_\1", name).lower()
    return re.sub(r"[^a-z0-9]+", "_", name).strip("_")[:60] or "field"


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
    if entity == "record":
        return _infer_generic(seen)
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


def _infer_generic(seen: Dict[str, Tuple[set, List[Any]]]) -> Dict[str, FieldMap]:
    """`record` entity: pick id / title / timestamp, then keep every other field that has a value."""
    kinds = {"id": "str", "title": "str", "timestamp": "datetime"}
    # when no known spelling matches: names shaped like an id / a title / a time (patch_id, patchName, releasedOn)
    shapes = {"id": re.compile(r"(^|_)id$|Id$|^uuid$|^guid$"),
              "title": re.compile(r"(?i)(name|title|summary|subject)$"),
              "timestamp": re.compile(r"(?i)(time|date|timestamp)|(_at|At|_on|On|seen|created|updated|modified)$")}
    depth = lambda p: (p.count(".") + p.count("["), len(p))  # noqa: E731 - shallow, short paths first
    out: Dict[str, FieldMap] = {}
    used = set()
    for target, spellings in _RECORD_SYNONYMS.items():
        ok = {p for p, (_, values) in seen.items() if p not in used and _fits(values, kinds[target], unique=target == "id")}
        top = {p for p in ok if depth(p)[0] == 0}
        known = lambda pool, sp_list=spellings: [p for sp in sp_list for p in pool if _norm(sp) in seen[p][0]]  # noqa: E731
        shaped = lambda pool, rx=shapes[target]: [p for p in pool if rx.search(re.split(r"[.\[']", p.rstrip("]'"))[-1] or p)]  # noqa: E731
        hits = known(top) or shaped(top) or known(ok) or shaped(ok)
        if hits:
            path = min(hits, key=depth)
            out[target] = FieldMap.model_validate({"from": path})
            used.add(path)
    if "id" not in out and "title" in out and _fits(seen[out["title"].from_][1], "str", unique=True):
        out = {"id": out["title"], **out}  # a unique name is a steadier id than a content hash
    def noise(path: str, values: List[Any]) -> bool:
        """API plumbing nobody reads in a table: links to other API calls, URL templates, node ids, avatars."""
        name = _column_name(path)
        texts = [v for v in values if isinstance(v, str)]
        if re.search(r"(^|_)(node_id|gravatar_id|avatar_url|etag|self|href|links?)$", name):
            return True
        if texts and all("{" in v or re.match(r"https?://api[.-]", v) or "/api/" in v or "/v1/" in v
                         for v in texts if v.startswith(("http://", "https://")) or "{" in v) and \
                any(v.startswith(("http://", "https://")) for v in texts):
            return True
        return False

    # top-level fields first, then one level of nesting; at most 30 extra columns
    candidates = sorted((p for p in seen if p not in used), key=lambda p: (depth(p)[0], p.endswith("url"), 0))
    for path in candidates:
        values = seen[path][1]
        name = _column_name(path)
        if len(out) >= 33 or depth(path)[0] > 1:
            continue
        if name in out or name in ("data", "source", "connector") or all(v in (None, "") for v in values) \
                or noise(path, values):
            continue
        out[name] = FieldMap.model_validate({"from": path})
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


# --- where is the next page? (pagination without token_path) ---------------------------------------

_TOKEN_NAMES = ["nextpagetoken", "nexttoken", "nextcursor", "nextpagecursor", "endcursor", "continuationtoken",
                "continuation", "scrollid", "pagetoken", "cursor", "after"]


_URL_NAMES = ["odatanextlink", "nextlink", "nexturl", "nextpageurl", "nextpage", "next"]


def find_next(data: Any, kind: str) -> Optional[str]:
    """Path of the next-page token (kind="token") or link (kind="url") in a response, or None.
    Used when a config says `next_token` / `next_url` paging but not where the token or link is."""
    names = _TOKEN_NAMES if kind == "token" else _URL_NAMES
    found: List[Tuple[int, int, str]] = []

    def walk(obj: Any, prefix: str, parent: str, depth: int) -> None:
        if not isinstance(obj, dict) or depth > 3:
            return
        for key, value in obj.items():
            if not isinstance(key, str):
                continue
            plain = re.fullmatch(r"[A-Za-z0-9_$-]+", key)
            path = (f"{prefix}.{key}" if prefix else key) if plain else f"{prefix}['{key}']"
            norm = re.sub(r"[^a-z0-9]", "", key.lower())
            if isinstance(value, dict):
                if kind == "url" and norm == "next" and isinstance(value.get("href"), str):
                    found.append((0, depth, f"{path}.href"))
                walk(value, path, norm, depth + 1)
                continue
            if isinstance(value, bool) or value in (None, ""):
                continue
            rank = names.index(norm) if norm in names else None
            if kind == "token" and rank is None and norm == "offset" and "pagin" in parent and isinstance(value, str):
                rank = len(names)  # CrowdStrike-style meta.pagination.offset token
            if kind == "url" and (not isinstance(value, str) or not value.startswith(("http://", "https://", "/", "?"))):
                rank = None
            if kind == "token" and isinstance(value, str) and value.startswith(("http://", "https://")):
                rank = None
            if rank is not None:
                found.append((rank, depth, path))

    walk(data, "", "", 0)
    return min(found)[2] if found else None
