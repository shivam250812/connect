"""Forgiving intake for connector files written by people or AI assistants.

Before a file is validated, this module turns the ways people commonly write a connector into the
canonical form: other key names (`url`, `endpoint`, `interval`, `style: cursor`, `field_mappings`...),
JSONPath (`$.data.items[*]`), schedules in words ("every 15 minutes", 300, "hourly"), secrets written as
`${GITHUB_TOKEN}` or `{{ secrets.X }}`, mappings written as lists or the wrong way round, YAML inside a
markdown ``` block, several configs in one file.

Rules it follows:
* every change is reported back as a plain sentence, so nothing is changed silently;
* it only rewrites what has one clear meaning; anything ambiguous is left for validation to reject
  with a "did you mean" hint;
* it never relaxes security: a credential written in plain text is still refused, and secrets always
  end up as names in the secret store, never as values in the file.
"""

from __future__ import annotations

import difflib
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlsplit

import yaml

MAX_BYTES = 256 * 1024
MAX_ALIASES = 50

ENTITY_WORDS = {
    "user": "user", "users": "user", "account": "user", "accounts": "user", "identity": "user", "identities": "user",
    "people": "user", "person": "user", "members": "user", "member": "user",
    "device": "device", "devices": "device", "host": "device", "hosts": "device", "asset": "device", "assets": "device",
    "machine": "device", "machines": "device", "computer": "device", "computers": "device", "endpoints": "device",
    "event": "event", "events": "event", "alert": "event", "alerts": "event", "detection": "event",
    "detections": "event", "incident": "event", "incidents": "event", "log": "event", "logs": "event",
    "audit": "event", "audit_log": "event", "audit_logs": "event", "finding": "event", "findings": "event",
    "vulnerability": "event", "vulnerabilities": "event", "vulns": "event", "cve": "event", "cves": "event",
    "threat": "event", "threats": "event", "indicator": "event", "indicators": "event", "ioc": "event", "iocs": "event",
    "record": "record", "records": "record", "other": "record", "generic": "record", "raw": "record",
    "ticket": "record", "tickets": "record", "issue": "record", "issues": "record", "project": "record",
    "projects": "record", "repository": "record", "repositories": "record", "repos": "record", "software": "record",
    "applications": "record", "apps": "record", "patch": "record", "patches": "record", "packages": "record",
}
WRAPPERS = {"connector", "config", "configuration", "integration", "spec", "connectorforge", "datasource",
            "data_source", "source", "settings", "definition", "connection"}
AUTH_TYPES = {
    "none": "none", "no": "none", "noauth": "none", "no_auth": "none", "anonymous": "none", "public": "none",
    "api_key": "api_key", "apikey": "api_key", "api-key": "api_key", "key": "api_key", "header": "api_key",
    "api_key_header": "api_key", "x-api-key": "api_key", "header_key": "api_key",
    "bearer": "bearer", "bearer_token": "bearer", "token": "bearer", "jwt": "bearer", "access_token": "bearer",
    "pat": "bearer", "personal_access_token": "bearer",
    "basic": "basic", "basic_auth": "basic", "http_basic": "basic", "username_password": "basic",
    "oauth": "oauth2_client_credentials", "oauth2": "oauth2_client_credentials", "oauth_2": "oauth2_client_credentials",
    "oauth2_client": "oauth2_client_credentials", "client_credentials": "oauth2_client_credentials",
    "oauth2_client_credentials": "oauth2_client_credentials", "oauth2_cc": "oauth2_client_credentials",
    "aws": "aws_sigv4", "sigv4": "aws_sigv4", "aws_sigv4": "aws_sigv4", "aws_signature": "aws_sigv4",
}
PAGING_TYPES = {
    "none": "none", "no": "none", "off": "none", "disabled": "none", "false": "none", "single": "none",
    "link": "link_header", "links": "link_header", "link_header": "link_header", "rfc5988": "link_header",
    "header_link": "link_header",
    "cursor": "next_token", "token": "next_token", "next_token": "next_token", "cursor_based": "next_token",
    "continuation": "next_token", "continuation_token": "next_token", "page_token": "next_token",
    "next_page_token": "next_token", "scroll": "next_token",
    "page": "page_number", "pages": "page_number", "page_number": "page_number", "page_based": "page_number",
    "paged": "page_number", "page_num": "page_number",
    "offset": "offset", "offset_limit": "offset", "limit_offset": "offset", "offset_based": "offset", "skip": "offset",
    "next_url": "next_url", "next_link": "next_url", "next": "next_url", "next_page_url": "next_url",
    "url": "next_url", "next_href": "next_url", "hateoas": "next_url",
}
# section -> {alias: canonical key}
KEY_ALIASES: Dict[str, Dict[str, str]] = {
    "request": {"url": "base_url", "baseurl": "base_url", "base": "base_url", "api_url": "base_url", "host": "base_url",
                "endpoint_url": "base_url", "full_url": "base_url", "http_verb": "method", "request_method": "method",
                "query_string": "params", "query_parameters": "params", "request_headers": "headers",
                "endpoint": "path", "resource": "path", "route": "path", "uri": "path",
                "query": "params", "query_params": "params", "parameters": "params", "querystring": "params",
                "http_method": "method", "verb": "method", "timeout": "timeout_seconds", "timeout_s": "timeout_seconds",
                "payload": "body", "json": "body", "format": "response_format"},
    "auth": {"method": "type", "kind": "type", "mode": "type", "strategy": "type", "auth_type": "type", "scheme_type": "type",
             "key_name": "header", "header_value": "value", "key_value": "value", "api_token": "value", "token_value": "value",
             "secret_value": "value", "api_secret": "value", "header_name": "header", "key_header": "header", "header_key": "header", "api_key_header": "header",
             "location": "in", "placement": "in", "send_in": "in", "add_to": "in",
             "query_param": "param", "param_name": "param", "query_parameter": "param", "key_param": "param",
             "secret_name": "secret", "secret_ref": "secret", "secret_key": "secret", "credential": "secret",
             "credential_name": "secret", "vault_key": "secret", "secret_id": "secret",
             "api_key": "value", "apikey": "value", "key": "value", "access_token": "token", "bearer_token": "token",
             "token_endpoint": "token_url", "token_uri": "token_url", "auth_url": "token_url",
             "access_token_url": "token_url", "oauth_url": "token_url",
             "scopes": "scope", "user": "username", "email": "username", "login_name": "username",
             "prefix": "scheme", "token_prefix": "scheme", "pass": "password"},
    "pagination": {"style": "type", "strategy": "type", "kind": "type", "method": "type", "mode": "type",
                   "cursor_param": "token_param", "next_param": "token_param", "continuation_param": "token_param",
                   "page_token_param": "token_param", "after_param": "token_param",
                   "cursor_path": "token_path", "next_cursor_path": "token_path", "next_token_path": "token_path",
                   "cursor_field": "token_path", "next_cursor_field": "token_path", "token_field": "token_path",
                   "continuation_path": "token_path", "next_page_token_path": "token_path",
                   "next_url_path": "token_path", "next_link_path": "token_path", "next_path": "token_path",
                   "next_field": "token_path", "next_url_field": "token_path", "next_link_field": "token_path",
                   "limit_param": "page_size_param", "per_page_param": "page_size_param", "size_param": "page_size_param",
                   "limit_parameter": "page_size_param", "count_param": "page_size_param",
                   "max_results_param": "page_size_param", "page_size_parameter": "page_size_param",
                   "limit": "page_size", "per_page": "page_size", "size": "page_size", "count": "page_size",
                   "batch_size": "page_size", "max_results": "page_size",
                   "page_parameter": "page_param", "page_number_param": "page_param",
                   "skip_param": "offset_param", "start_param": "offset_param", "start_at_param": "offset_param",
                   "total_field": "total_path", "total_count_path": "total_path", "total_key": "total_path",
                   "total": "total_path", "page_limit": "max_pages", "has_more": "has_more_path",
                   "has_more_field": "has_more_path", "more_path": "has_more_path", "first_page": "start_page"},
    "cursor": {"timestamp_field": "field", "cursor_field": "field", "updated_field": "field", "since_field": "field",
               "query_param": "param", "since_param": "param", "filter_param": "param",
               "start": "initial", "initial_value": "initial", "lookback": "initial", "start_from": "initial"},
    "retry": {"max_retries": "max_attempts", "retries": "max_attempts", "attempts": "max_attempts",
              "initial_delay": "base_delay_seconds", "backoff_seconds": "base_delay_seconds", "base_delay": "base_delay_seconds",
              "delay": "base_delay_seconds", "backoff_factor": "base_delay_seconds", "delay_seconds": "base_delay_seconds",
              "max_delay": "max_delay_seconds", "retry_on_status": "retry_on", "status_codes": "retry_on",
              "retry_status_codes": "retry_on", "backoff": "base_delay_seconds", "wait": "base_delay_seconds"},
    "field": {"field": "from", "path": "from", "source": "from", "src": "from", "json_path": "from", "jsonpath": "from",
              "key": "from", "attribute": "from", "input": "from", "source_field": "from",
              "default_value": "default", "fallback": "default", "constant": "const", "static": "const",
              "date_format": "format", "datetime_format": "format", "data_type": "type", "value_type": "type",
              "field_type": "type", "cast": "type", "as": "type"},
}
TOP_ALIASES = {
    "url": "request.base_url", "base_url": "request.base_url", "baseurl": "request.base_url", "base": "request.base_url",
    "api_url": "request.base_url", "host": "request.base_url", "endpoint_url": "request.base_url",
    "path": "request.path", "resource": "request.path", "route": "request.path",
    "method": "request.method", "http_method": "request.method", "headers": "request.headers",
    "params": "request.params", "query": "request.params", "query_params": "request.params",
    "parameters": "request.params", "body": "request.body", "payload": "request.body",
    "timeout": "request.timeout_seconds", "timeout_seconds": "request.timeout_seconds",
    "interval": "schedule", "frequency": "schedule", "poll_interval": "schedule", "polling_interval": "schedule",
    "schedule_interval": "schedule", "every": "schedule", "cadence": "schedule", "sync_interval": "schedule",
    "data_path": "records", "items_path": "records", "results_path": "records", "records_path": "records",
    "root": "records", "root_path": "records", "list_path": "records", "array_path": "records",
    "json_path": "records", "jsonpath": "records", "response_path": "records", "record_path": "records",
    "field_mappings": "mapping", "field_mapping": "mapping", "fields": "mapping", "field_map": "mapping",
    "mappings": "mapping", "transform": "mapping", "transformations": "mapping", "schema_mapping": "mapping",
    "entity_type": "entity", "data_type": "entity", "target": "entity", "table": "entity", "output_table": "entity",
    "authentication": "auth", "credentials": "auth", "auth_config": "auth",
    "paging": "pagination", "page": "pagination", "pager": "pagination",
    "ratelimit": "rate_limit", "rate_limiting": "rate_limit", "throttle": "rate_limit", "throttling": "rate_limit",
    "retries": "retry", "retry_policy": "retry", "retry_config": "retry", "max_retries": "retry",
    "incremental": "cursor", "checkpoint": "cursor", "watermark": "cursor", "since": "cursor",
    "title": "name", "display_name": "name", "label": "name",
}
# keys an assistant adds that ConnectForge has no use for: dropped with a note
IGNORED = {"version", "author", "authors", "tags", "labels", "metadata", "owner", "owners", "notes", "note",
           "comment", "comments", "logging", "log_level", "logs", "output", "outputs", "destination", "sink",
           "generated_by", "created_by", "created", "updated", "license", "docs", "documentation", "contact",
           "category", "vendor", "product_name", "provider", "$schema", "schema_version", "apiversion", "api_version",
           "openapi", "swagger", "info", "components", "externaldocs", "security"}
FIELD_TYPES = {"string": "str", "str": "str", "text": "str", "keyword": "str", "integer": "int", "int": "int",
               "long": "int", "number": "float", "float": "float", "double": "float", "decimal": "float",
               "boolean": "bool", "bool": "bool", "timestamp": "datetime", "datetime": "datetime", "date": "datetime",
               "time": "datetime", "date-time": "datetime", "date_time": "datetime", "iso8601": "datetime",
               "ip": "ip", "ip_address": "ip", "ipv4": "ip", "ipv6": "ip", "inet": "ip"}
_CRED_SLOTS = ("token", "value", "password", "client_secret", "secret_access_key")
_ENV_STYLE = re.compile(r"^\s*(?:\$\{\s*(?:env[.:])?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}|\$([A-Z_][A-Z0-9_]*)|"
                        r"\{\{\s*(?:secrets?|env|vars?)?\.?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}|"
                        r"<\s*([A-Za-z][A-Za-z0-9_ -]*)\s*>)\s*$")
_PLACEHOLDER = re.compile(r"^(YOUR|MY|INSERT|REPLACE|PUT)?_?[A-Z][A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD|PASS)(_HERE)?$")
_INLINE_ENV = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}|\{\{\s*(?:(?:secrets?|env|vars?)\.)?([A-Za-z_][A-Za-z0-9_]*)\s*\}\}|"
                         r"\$([A-Z_][A-Z0-9_]{2,})\b")


class IntakeError(ValueError):
    """The file cannot be read at all (not YAML, too large, hostile)."""


# --- reading the text -------------------------------------------------------------------------------


class _Loader(yaml.SafeLoader):
    """Safe YAML that refuses duplicate keys and alias bombs."""

    def __init__(self, stream):
        super().__init__(stream)
        self.aliases = 0

    def compose_node(self, parent, index):
        if self.check_event(yaml.AliasEvent):
            self.aliases += 1
            if self.aliases > MAX_ALIASES:
                raise IntakeError(f"too many YAML aliases (more than {MAX_ALIASES} uses of *name); "
                                  "write the values out instead")
        return super().compose_node(parent, index)

    def construct_mapping(self, node, deep=False):
        seen = {}
        for key_node, _ in node.value:
            key = self.construct_object(key_node, deep=True)
            if not isinstance(key, (str, int, float, bool, type(None))):
                raise IntakeError(f"line {key_node.start_mark.line + 1}: a setting name must be plain text, "
                                  "not a list or block")
            if key in seen:
                raise IntakeError(f"key '{key}' appears twice (lines {seen[key] + 1} and {key_node.start_mark.line + 1}); "
                                  "keep only one")
            seen[key] = key_node.start_mark.line
        return super().construct_mapping(node, deep)


def read_documents(text: str) -> Tuple[List[dict], List[str]]:
    """Text -> list of config dicts, plus notes about how the text was read."""
    notes: List[str] = []
    if len(text.encode("utf-8", "ignore")) > MAX_BYTES:
        raise IntakeError(f"file is too large ({len(text) // 1024} KB; a connector file is at most {MAX_BYTES // 1024} KB)")
    fence = re.search(r"```[ \t]*(?:ya?ml|json|YAML|JSON)?[ \t]*\n(.*?)```", text, re.S)
    if fence:
        if text[:fence.start()].strip() or text[fence.end():].strip():
            notes.append("took the config out of the ``` block; the text around it was ignored")
        text = fence.group(1)
    if re.search(r"^\t", text, re.M):
        text = re.sub(r"^\t+", lambda m: "  " * len(m.group(0)), text, flags=re.M)
        notes.append("replaced tab indentation with spaces (YAML does not allow tabs)")
    try:
        docs = [d for d in yaml.load_all(text, Loader=_Loader) if d is not None]
    except IntakeError:
        raise
    except yaml.YAMLError as e:
        raise IntakeError(f"YAML syntax: {e}") from e
    out: List[dict] = []
    for doc in docs:
        if isinstance(doc, list) and doc and all(isinstance(d, dict) for d in doc):
            out += doc
        elif isinstance(doc, dict):
            out.append(doc)
        else:
            raise IntakeError("this is not a connector file: expected YAML (or JSON) settings such as "
                              "`id:`, `name:` and `request:`")
    if not out:
        raise IntakeError("this is not a connector file: it is empty")
    return out, notes


# --- small helpers ----------------------------------------------------------------------------------


def jsonpath(path: Any) -> Any:
    """`$.data.items[*]`, `.data.items[]` (jq), `{{ item.data.id }}` (Jinja), `$['profile']['email']` -> plain paths."""
    if not isinstance(path, str):
        return path
    p = path.strip()
    jinja = re.fullmatch(r"\{\{\s*(.+?)\s*\}\}", p)
    if jinja:
        p = re.sub(r"^(item|record|row|this|x|r|entry|obj|result|it)\.", "", jinja.group(1).strip())
    if p.startswith(".") and not p.startswith(".."):
        p = p[1:]
    p = p.replace("[]", "")
    if p == path.strip() and not p.startswith(("$", "[")) and "[*]" not in p:
        return path
    p = re.sub(r"^\$\.?", "", p)
    p = re.sub(r"^\.", "", p)
    p = p.replace("[*]", "")
    p = re.sub(r"\[['\"]([^'\".\]]+)['\"]\]", r".\1", p)   # ['plain'] -> .plain (dotted keys keep brackets)
    p = re.sub(r"\[\"([^\"]+)\"\]", r"['\1']", p)
    return p.strip(".")


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9_-]+", "-", str(text).strip().lower()).strip("-_")
    s = re.sub(r"-{2,}", "-", s)
    if not s or not s[0].isalpha():
        s = "src-" + s
    return (s + "-src")[:41] if len(s) < 3 else s[:41].rstrip("-_")


def secret_name(raw: str) -> str:
    return re.sub(r"[^a-z0-9_]+", "_", raw.strip().lower()).strip("_")[:60]


def duration(value: Any) -> Optional[str]:
    """'every 15 minutes', 300, 'hourly', 'PT15M', '5 min' -> '15m' etc. None if not understood."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return f"{int(value)}s"
    v = str(value).strip().lower()
    words = {"hourly": "1h", "daily": "1d", "nightly": "1d", "weekly": "7d", "every minute": "1m",
             "minutely": "1m", "every hour": "1h", "every day": "1d", "every week": "7d"}
    if v in words:
        return words[v]
    iso = re.fullmatch(r"p(?:(\d+)d)?(?:t(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?)?", v)
    if iso and any(iso.groups()):
        d, h, m, s = (int(x or 0) for x in iso.groups())
        return f"{d * 86400 + h * 3600 + m * 60 + s}s"
    m = re.fullmatch(r"(?:every\s+)?(\d+(?:\.\d+)?)\s*(s|sec|secs|second|seconds|m|min|mins|minute|minutes|h|hr|hrs|hour|"
                     r"hours|d|day|days|w|week|weeks)", v)
    if m:
        seconds = float(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}[m.group(2)[0]]
        return f"{int(seconds)}s" if seconds % 60 or "." in m.group(1) else (
            f"{int(seconds // 86400)}d" if seconds % 86400 == 0 else
            f"{int(seconds // 3600)}h" if seconds % 3600 == 0 else f"{int(seconds // 60)}m")
    return None


def date_format(fmt: Any) -> Any:
    """Moment/Java style date patterns -> strptime (`YYYY-MM-DD HH:mm:ss` -> `%Y-%m-%d %H:%M:%S`)."""
    if not isinstance(fmt, str) or "%" in fmt or not re.search(r"YY|DD|HH|mm|ss", fmt):
        return fmt
    out = fmt
    for a, b in (("YYYY", "%Y"), ("yyyy", "%Y"), ("YY", "%y"), ("MM", "%m"), ("DD", "%d"), ("dd", "%d"),
                 ("HH", "%H"), ("hh", "%I"), ("mm", "%M"), ("SSS", "%f"), ("ss", "%S"), ("A", "%p")):
        out = out.replace(a, b)
    return out.replace("'T'", "T").replace("Z", "%z") if "Z" in out and "%z" not in out else out.replace("'T'", "T")


class _Fixer:
    def __init__(self, where: str = ""):
        self.notes: List[str] = []
        self.where = where

    def note(self, msg: str) -> None:
        self.notes.append(f"{self.where}{msg}")

    def rename(self, block: dict, aliases: Dict[str, str], section: str, kind: str = "") -> dict:
        """Resolve key names ignoring case and separators (`baseUrl`, `base-url`, `BASE_URL`), against the
        aliases and the real setting names; `*_ms` keys are converted to seconds."""
        table = {_n(a): c for a, c in aliases.items()}
        table.update({_n(c): c for c in _canonical(kind)})
        out = {}
        for k, v in block.items():
            key = str(k)
            canon = table.get(_n(key))
            if canon is None and _n(key).endswith("ms") and str(table.get(_n(key)[:-2], "")).endswith("_seconds") \
                    and isinstance(v, (int, float)):
                canon, v = table[_n(key)[:-2]], v / 1000
            if canon is None and kind == "pagination":
                canon = _paging_word(key)
            if canon and canon != key and canon not in block and canon not in out:
                self.note(f"`{section}{key}` -> `{section}{canon}`")
                out[canon] = v
            else:
                out[key] = v
        return out


def _n(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def _canonical(kind: str) -> List[str]:
    """The real setting names of a section, so `baseUrl` or `tokenUrl` resolve without an alias."""
    if not kind:
        return []
    from connectforge.config import (
        schema as s,  # late import: schema imports this module
    )

    model = {"request": s.RequestSpec, "auth": s.AuthSpec, "pagination": s.PaginationSpec, "cursor": s.CursorSpec,
             "retry": s.RetrySpec, "field": s.FieldMap, "top": s.ConnectorSpec, "rate_limit": s.RateLimitSpec}[kind]
    return [f.alias or name for name, f in model.model_fields.items()]


def _paging_word(key: str) -> Optional[str]:
    """Paging keys come in endless spellings; read them by the words they contain."""
    words = set(re.findall(r"[a-z]+", re.sub(r"([a-z])([A-Z])", r"\1_\2", key).lower()))
    token = {"cursor", "token", "continuation", "next", "after", "marker", "scroll"}
    as_path = {"path", "jsonpath", "field", "pointer", "selector", "location", "key", "attr", "attribute", "expr", "expression"}
    as_param = {"param", "parameter", "query", "arg", "argument", "qs", "name"}
    if words & token and words & as_path:
        return "token_path"
    if words & token and words & as_param:
        return "token_param"
    if words & {"limit", "size", "per", "count", "results"} and words & as_param:
        return "page_size_param"
    if "total" in words:
        return "total_path"
    if "more" in words:
        return "has_more_path"
    if "offset" in words and words & as_param:
        return "offset_param"
    if "page" in words and words & as_param:
        return "page_param"
    return None


# --- one config -------------------------------------------------------------------------------------


def normalize(doc: dict, where: str = "") -> Tuple[dict, List[str]]:
    """Return the canonical form of one config dict and the list of changes made."""
    fx = _Fixer(where)
    d: Dict[str, Any] = dict(doc)
    top_known = {_n(k) for k in _canonical("top")} | {"endpoints"}
    for _ in range(2):  # `connector: {...}`, `integration: {config: {...}}`
        wrappers = [k for k, v in d.items() if isinstance(v, dict) and _n(k) in {_n(w) for w in WRAPPERS}
                    and (len(d) == 1 or not isinstance(v.get("name", v.get("id")), type(None)) or "url" in v
                         or "base_url" in v or "request" in v or "endpoints" in v or "auth" in v)]
        if len(wrappers) != 1:
            break
        inner = d.pop(wrappers[0])
        fx.note(f"read the settings inside `{wrappers[0]}:`")
        d = {**inner, **{k: v for k, v in d.items() if k not in inner}}
    if isinstance(d.get("servers"), list) and isinstance(d.get("paths"), dict):  # an OpenAPI snippet
        server = next((s.get("url") for s in d.pop("servers") if isinstance(s, dict) and s.get("url")), None)
        paths = d.pop("paths")
        if server:
            d.setdefault("request", {}).setdefault("base_url", server)
        ops = [(p, m.upper()) for p, spec in paths.items() for m in (spec or {"get": {}})
               if str(m).lower() in ("get", "post")] or [(p, "GET") for p in paths]
        if len(ops) == 1:
            d.setdefault("request", {})["path"], method = ops[0]
            if method == "POST":
                d["request"]["method"] = "POST"
        else:
            d.setdefault("endpoints", [{"name": p.rstrip("/").rsplit("/", 1)[-1] or "root", "path": p,
                                        **({"method": m} if m == "POST" else {})} for p, m in ops])
        fx.note(f"read an OpenAPI snippet: base URL from `servers`, {len(ops)} endpoint(s) from `paths`")
    shared = _shared_values(d)
    for key in [k for k in d if id(d[k]) in shared and _n(k) not in {_n(c) for c in _canonical("top")} | {"endpoints"}]:
        fx.note(f"ignored `{key}` (it only holds a YAML anchor used elsewhere)")
        del d[key]
    if isinstance(d.get("response"), dict):
        resp = d.pop("response")
        for k, v in resp.items():
            n = _n(k)
            if n in ("records", "recordspath", "datapath", "itemspath", "root", "rootpath", "path", "jsonpath",
                     "resultspath", "listpath", "items", "data", "results"):
                d.setdefault("records", v)
            elif n in ("format", "type", "contenttype", "responseformat"):
                d.setdefault("request", {}).setdefault("response_format", "xml" if "xml" in str(v).lower() else "json")
            elif n in ("pagination", "paging"):
                d.setdefault("pagination", v)
            elif n in ("mapping", "fields", "fieldmappings"):
                d.setdefault("mapping", v)
        fx.note("read `records` / format / paging from the `response:` block")
    for key in list(d):
        canon = next((c for c in top_known if c == _n(key)), None)
        real = next((k for k in _canonical("top") + ["endpoints"] if _n(k) == canon), None)
        if real and real != key and real not in d:
            d[real] = d.pop(key)
            fx.note(f"`{key}` -> `{real}`")

    for key in list(d):
        k = str(key)
        if k.lower() in IGNORED or k.lower().startswith(("x-", "x_", "swaggerhub")) or \
                (k == "kind" and d[k] not in ("http", "file")):
            fx.note(f"ignored `{k}` (not used by ConnectForge)")
            del d[key]

    if "type" in d and isinstance(d["type"], str):
        word = d["type"].lower()
        if word in ENTITY_WORDS and "entity" not in d:
            d["entity"] = d.pop("type")
            fx.note("`type` -> `entity`")
        elif word in ("rest", "rest_api", "http", "https", "api", "json", "polling", "pull", "connector", "source"):
            del d["type"]
            fx.note(f"ignored `type: {word}` (every connector calls an HTTP API unless `kind: file`)")

    if "request" in d and not isinstance(d["request"], dict):
        return d, fx.notes  # nothing sensible to rewrite: validation explains what `request` must look like
    req = d.get("request") if isinstance(d.get("request"), dict) else {}
    top_aliases = {_n(a): t for a, t in TOP_ALIASES.items()}
    for key in list(d):  # schedule written with a unit in its name: interval_seconds: 300, poll_minutes: 5
        m = re.fullmatch(r"(?:poll|polling|sync|run|fetch|refresh|schedule)?_?(?:interval|frequency|every|cadence|period)?_?"
                         r"(?:in_)?(seconds|secs|minutes|mins|hours|hrs|days)", str(key).lower())
        if m and "schedule" not in d and isinstance(d[key], (int, float)) and not isinstance(d[key], bool) and \
                re.search(r"interval|frequency|every|cadence|period|poll|sync|schedule", str(key).lower()):
            unit = m.group(1)[0]
            d["schedule"] = {"every": f"{int(d.pop(key))}{unit}"}
            fx.note(f"`{key}` -> `schedule: {{every: {d['schedule']['every']}}}`")
    for key in list(d):
        target = top_aliases.get(_n(key))
        if not target:
            continue
        if target.startswith("request."):
            sub = target.split(".", 1)[1]
            if sub not in req:
                req[sub] = d.pop(key)
                fx.note(f"`{key}` -> `request.{sub}`")
        elif target not in d:
            d[target] = d.pop(key)
            fx.note(f"`{key}` -> `{target}`")
    if req:
        d["request"] = req
    if "endpoint" in d and isinstance(d["endpoint"], str) and "path" not in d.get("request", {}):
        d.setdefault("request", {})["path"] = d.pop("endpoint")
        fx.note("`endpoint` -> `request.path`")

    if isinstance(d.get("request"), dict):
        d["request"] = _request(d["request"], fx, "request.")

    if "id" not in d or not re.fullmatch(r"[a-z][a-z0-9_-]{2,40}", str(d.get("id", ""))):
        base = d.get("id") or d.get("name") or (urlsplit(str(d.get("request", {}).get("base_url", ""))).hostname or "source")
        new = slug(base)
        fx.note(f"id `{d['id']}` -> `{new}` (lowercase letters, digits, - and _)" if "id" in d
                else f"added id `{new}` (from the {'name' if d.get('name') else 'address'})")
        d["id"] = new
    if not d.get("name"):
        d["name"] = str(d["id"]).replace("-", " ").replace("_", " ").title()
        fx.note(f"added name `{d['name']}`")

    if "entity" in d:
        d["entity"] = _entity(d["entity"], fx, "entity")
    if "schedule" in d:
        d["schedule"] = _schedule(d["schedule"], fx, "schedule")
    if "auth" in d:
        d["auth"] = _auth(d["auth"], fx)
    if "pagination" in d:
        d["pagination"] = _pagination(d["pagination"], fx, "pagination.")
    if "records" in d:
        d["records"] = _records(d["records"], fx, "records")
    if "mapping" in d:
        d["mapping"] = _mapping(d["mapping"], d.get("entity", "event"), fx, "mapping")
    if "rate_limit" in d:
        d["rate_limit"] = _rate_limit(d["rate_limit"], fx)
    if "retry" in d:
        d["retry"] = _retry(d["retry"], fx)
    if "cursor" in d and isinstance(d["cursor"], dict):
        d["cursor"] = _cursor(d["cursor"], fx)
    if "endpoints" in d:
        d["endpoints"] = _endpoints(d, fx)
    _secrets_in_request(d, fx)
    _check_paths(d)
    return d, fx.notes


_NOT_A_PATH = re.compile(r"\{\{|\}\}|\{%|^\$|\[\]|\[\*\]|^\.\w")


def _check_paths(d: dict) -> None:
    """A path still holding template syntax would be read as a literal key and silently match nothing."""
    def check(where: str, value: Any) -> None:
        if isinstance(value, str) and _NOT_A_PATH.search(value.strip()):
            raise IntakeError(f"{where}: `{value}` is not a field path ConnectForge can read; write it as a plain "
                              "path such as `data.items` or `profile.email`")

    blocks = [("", d)] + [(f"endpoints.{e.get('name', i)}.", e) for i, e in enumerate(d.get("endpoints") or [])
                          if isinstance(e, dict)]
    for prefix, b in blocks:
        check(f"{prefix}records", b.get("records"))
        for k in ("token_path", "total_path", "has_more_path"):
            check(f"{prefix}pagination.{k}", (b.get("pagination") or {}).get(k) if isinstance(b.get("pagination"), dict) else None)
        for target, fm in (b.get("mapping") or {}).items() if isinstance(b.get("mapping"), dict) else []:
            check(f"{prefix}mapping.{target}", fm if isinstance(fm, str) else (fm or {}).get("from") if isinstance(fm, dict) else None)


def _entity(value: Any, fx: _Fixer, label: str) -> Any:
    if isinstance(value, str) and value.lower() in ENTITY_WORDS and ENTITY_WORDS[value.lower()] != value:
        fx.note(f"`{label}: {value}` -> `{ENTITY_WORDS[value.lower()]}`")
        return ENTITY_WORDS[value.lower()]
    return value


def _pairs(value: Any) -> Any:
    """[{name: Accept, value: x}] or [{key: a, value: b}] -> {Accept: x}."""
    if isinstance(value, list) and value and all(isinstance(i, dict) for i in value):
        out = {}
        for item in value:
            k = next((item[x] for x in ("name", "key", "header", "param", "field") if x in item), None)
            if k is None or "value" not in item:
                return value
            out[str(k)] = item["value"]
        return out
    if isinstance(value, list) and value and all(isinstance(i, str) and ":" in i for i in value):
        return {i.split(":", 1)[0].strip(): i.split(":", 1)[1].strip() for i in value}
    return value


def _request(req: dict, fx: _Fixer, label: str) -> dict:
    req = fx.rename(req, KEY_ALIASES["request"], label, "request")
    for key in ("base_url", "path"):
        if isinstance(req.get(key), dict) and isinstance(req[key].get("raw"), str):  # Postman: url: {raw: ...}
            req[key] = req[key]["raw"]
            fx.note(f"`{label}{key}` was a Postman URL object; used its `raw` value")
    for block in ("headers", "params"):
        new = _pairs(req.get(block))
        if new is not req.get(block):
            req[block] = new
            fx.note(f"`{label}{block}` written as a list -> name: value pairs")
    if isinstance(req.get("method"), str) and req["method"] != req["method"].upper():
        req["method"] = req["method"].upper()
    if isinstance(req.get("response_format"), str):
        req["response_format"] = req["response_format"].lower()
    base, path = req.get("base_url"), req.get("path")
    if not base and isinstance(path, str) and path.startswith(("http://", "https://")):
        parts = urlsplit(path)
        req["base_url"], req["path"] = f"{parts.scheme}://{parts.netloc}", parts.path + (f"?{parts.query}" if parts.query else "")
        fx.note(f"split the full URL in `{label}path` into base_url and path")
    elif isinstance(base, str) and isinstance(path, str) and path.startswith(base):
        req["path"] = path[len(base):] or ""
        fx.note(f"`{label}path` repeated the base URL; kept only the path")
    if isinstance(req.get("base_url"), str) and "?" in req["base_url"]:
        b, q = req["base_url"].split("?", 1)
        req["base_url"] = b
        req["params"] = {**dict(parse_qsl(q)), **(req.get("params") or {})}
        fx.note(f"moved the query string out of `{label}base_url` into `{label}params`")
    path = req.get("path")
    if isinstance(path, str) and "?" in path and not path.startswith("http"):
        p, q = path.split("?", 1)
        req["path"] = p
        req["params"] = {**dict(parse_qsl(q)), **(req.get("params") or {})}
        fx.note(f"moved the query string out of `{label}path` into `{label}params`")
    if isinstance(req.get("path"), str) and req["path"] and not req["path"].startswith("/"):
        req["path"] = "/" + req["path"]
    if isinstance(req.get("base_url"), str) and req.get("path") and req["base_url"].endswith("/"):
        req["base_url"] = req["base_url"].rstrip("/")
    if isinstance(req.get("timeout_seconds"), str):
        sec = duration(req["timeout_seconds"])
        if sec:
            req["timeout_seconds"] = float(sec[:-1]) if sec.endswith("s") else req["timeout_seconds"]
    return req


def _schedule(value: Any, fx: _Fixer, label: str) -> Any:
    if isinstance(value, dict):
        if any(k in value for k in ("cron", "crontab", "cron_expression")):
            raise IntakeError(f"{label}: cron schedules are not supported; use an interval such as `every: 5m`")
        for k in ("interval", "interval_seconds", "frequency", "period", "poll_interval", "every_seconds", "seconds",
                  "minutes", "hours", "days", "value"):
            if k in value and "every" not in value:
                raw = value.pop(k)
                every = {"minutes": f"{raw}m", "hours": f"{raw}h", "days": f"{raw}d"}.get(k) or duration(raw) or raw
                value["every"] = every
                fx.note(f"`{label}.{k}: {raw}` -> `{label}.every: {every}`")
        if "every" in value and not re.fullmatch(r"\d+[smhd]", str(value["every"])):
            parsed = duration(value["every"])
            if parsed:
                value["every"] = parsed
        return value
    if isinstance(value, str) and re.fullmatch(r"(\S+\s+){4}\S+", value.strip()) and not duration(value):
        raise IntakeError(f"{label}: cron schedules are not supported; use an interval such as `every: 5m`")
    parsed = duration(value)
    if parsed:
        fx.note(f"`{label}: {value}` -> `{label}: {{every: {parsed}}}`")
        return {"every": parsed}
    return value


def _cred_ref(value: Any, fx: _Fixer, label: str) -> Any:
    """`${GITHUB_TOKEN}`, `$TOKEN`, `{{ secrets.X }}`, `<your api key>`, `YOUR_API_KEY` -> `${secret:x}`."""
    if not isinstance(value, str):
        return value
    v = value.strip()
    m = re.fullmatch(r"\$\{\s*env:\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}", v)
    raw = m.group(1) if m else None
    if not raw:
        m = _ENV_STYLE.match(v)
        raw = next((g for g in m.groups() if g), None) if m and not v.startswith("${secret:") else None
    if not raw and _PLACEHOLDER.fullmatch(v):
        raw = re.sub(r"^(YOUR|MY|INSERT|REPLACE|PUT)_|_HERE$", "", v)
    if not raw:
        return value
    name = secret_name(raw)
    fx.note(f"`{label}: {value}` -> secret `{name}` (save its value on the Secrets tab)")
    return f"${{secret:{name}}}"


def _auth(value: Any, fx: _Fixer) -> Any:
    if value in (None, False) or (isinstance(value, str) and value.lower() in AUTH_TYPES and AUTH_TYPES[value.lower()] == "none"):
        fx.note(f"`auth: {value}` -> `auth: {{type: none}}`")
        return {"type": "none"}
    if not isinstance(value, dict):
        return value
    if len(value) == 1:
        (only, inner), = value.items()
        kind = AUTH_TYPES.get(str(only).lower().replace(" ", "_"))
        if kind and isinstance(inner, dict):
            value = {"type": kind, **inner}
            fx.note(f"`auth.{only}: {{...}}` -> `auth.type: {kind}` with its settings")
    a = fx.rename(value, KEY_ALIASES["auth"], "auth.", "auth")
    t = str(a.get("type", "")).lower().replace(" ", "_")
    if t in AUTH_TYPES and AUTH_TYPES[t] != a.get("type"):
        fx.note(f"`auth.type: {a['type']}` -> `{AUTH_TYPES[t]}`")
        a["type"] = AUTH_TYPES[t]
    if "type" not in a:
        guess = ("oauth2_client_credentials" if a.get("token_url") and a.get("client_id") else
                 "basic" if a.get("username") else "api_key" if a.get("header") or a.get("param") else
                 "bearer" if a.get("token") or a.get("secret") else None)
        if guess:
            a["type"] = guess
            fx.note(f"added `auth.type: {guess}`")
    grant = a.pop("grant_type", None)
    if grant and str(grant).lower() not in ("client_credentials", "client-credentials"):
        raise IntakeError(f"auth.grant_type: {grant} is not supported; only the client_credentials flow is "
                          "(server-to-server, no browser login)")
    if grant:
        fx.note("dropped `auth.grant_type: client_credentials` (it is the only flow, so it is implied)")
    for k in ("client_id_env_var", "client_id_env", "client_id_variable"):
        if k in a:
            var = a.pop(k)
            a.setdefault("client_id", f"${{env:{var}}}")
            fx.note(f"`auth.{k}: {var}` -> `auth.client_id: ${{env:{var}}}` (a client id is not secret)")
    for k in ("client_secret_env_var", "client_secret_env", "token_env", "token_env_var", "api_key_env",
              "api_key_env_var", "password_env", "password_env_var", "secret_env", "secret_env_var", "key_env"):
        if k in a:
            var = a.pop(k)
            name = secret_name(var)
            a.setdefault("secret", name)
            fx.note(f"`auth.{k}: {var}` -> `auth.secret: {name}` (credentials live in the secret store: save "
                    f"the value of {var} on the Secrets tab as {name})")
    if a.get("type") == "bearer" and "value" in a and "token" not in a:
        a["token"] = a.pop("value")
    if isinstance(a.get("scope"), list):
        a["scope"] = " ".join(map(str, a["scope"]))
    if "audience" in a:
        a.setdefault("extra", {})["audience"] = a.pop("audience")
        fx.note("`auth.audience` -> `auth.extra.audience`")
    if isinstance(a.get("in"), str):
        loc = a["in"].lower()
        a["in"] = "query" if "query" in loc or loc in ("url", "param", "params") else "header" if "header" in loc else a["in"]
    if a.get("type") in ("bearer", "oauth2_client_credentials") and str(a.get("header", "")).lower() == "authorization":
        a.pop("header")
        fx.note("dropped `auth.header: Authorization` (bearer/OAuth2 always use it)")
    if a.get("type") == "api_key" and a.get("in") == "query" and a.get("header") and not a.get("param"):
        a["param"] = a.pop("header")
    if isinstance(a.get("secret"), str):
        ref = re.fullmatch(r"\$\{\s*secret:\s*([A-Za-z0-9_.-]+)\s*\}", a["secret"].strip())
        if ref:
            a["secret"] = ref.group(1)
            fx.note(f"`auth.secret` takes the secret's name: `{ref.group(1)}`")
        else:
            conv = _cred_ref(a["secret"], _Fixer(), "")
            if conv != a["secret"]:
                a["secret"] = conv[len("${secret:"):-1]
                fx.note(f"`auth.secret` -> `{a['secret']}` (save its value on the Secrets tab)")
    for slot in _CRED_SLOTS:
        if slot in a:
            a[slot] = _cred_ref(a[slot], fx, f"auth.{slot}")
    if a.get("type") == "api_key" and isinstance(a.get("value"), str) and "secret" not in a and \
            not a["value"].startswith("${"):
        pass  # a literal key: left for validation to refuse as plain text
    return a


def _pagination(value: Any, fx: _Fixer, label: str) -> Any:
    if value in (None, False):
        return {"type": "none"}
    if isinstance(value, str):
        t = PAGING_TYPES.get(value.lower().replace("-", "_"))
        if t:
            fx.note(f"`{label[:-1]}: {value}` -> `{{type: {t}}}`")
            return {"type": t}
        return value
    if not isinstance(value, dict):
        return value
    p = fx.rename(value, KEY_ALIASES["pagination"], label, "pagination")
    raw = str(p.get("type", "")).lower().replace("-", "_")
    if raw and raw not in PAGING_TYPES.values():
        if raw in PAGING_TYPES:
            t = PAGING_TYPES[raw]
        elif "cursor" in raw or "token" in raw:
            t = "next_token" if any(k in p for k in ("token_param", "token_path")) or "offset" not in raw else "offset"
        elif "offset" in raw:
            t = "offset"
        else:
            t = None
        if t:
            fx.note(f"`{label}type: {p['type']}` -> `{t}`")
            p["type"] = t
    for k in ("token_path", "total_path", "has_more_path"):
        if k in p:
            p[k] = jsonpath(p[k])
    if "type" not in p:
        nexts = [k for k in value if _paging_word(k) == "token_path" or _n(k) in ("next", "nextpage", "nexturl", "nextlink")]
        if "token_path" not in p and nexts:
            p["token_path"] = jsonpath(p.pop(nexts[0]))
        is_url = any(w in _n(k) for k in value for w in ("url", "link", "href", "nextpage")) or \
            str(p.get("token_path", "")).split(".")[-1] in ("next", "href", "url", "link")
        t = ("next_url" if is_url else "next_token") if "token_path" in p or "token_param" in p else \
            "offset" if "offset_param" in p else "page_number" if "page_param" in p else None
        if t:
            p["type"] = t
            fx.note(f"added `{label}type: {t}` (from the paging settings given)")
    return p


def _records(value: Any, fx: _Fixer, label: str) -> Any:
    new = jsonpath(value)
    if new != value:
        fx.note(f"`{label}: {value}` -> `{new}` (JSONPath -> path)")
    return new


def _field(value: Any, fx: _Fixer, label: str) -> Any:
    if isinstance(value, str):
        new = jsonpath(value)
        if new != value:
            fx.note(f"`{label}: {value}` -> `{new}`")
        return new
    if not isinstance(value, dict):
        return value
    f = fx.rename(value, KEY_ALIASES["field"], f"{label}.", "field")
    if "from" in f:
        f["from"] = jsonpath(f["from"])
    if "path" in f:
        f["path"] = jsonpath(f["path"])
    if isinstance(f.get("type"), str) and f["type"].lower() in FIELD_TYPES and FIELD_TYPES[f["type"].lower()] != f["type"]:
        fx.note(f"`{label}.type: {f['type']}` -> `{FIELD_TYPES[f['type'].lower()]}`")
        f["type"] = FIELD_TYPES[f["type"].lower()]
    if "format" in f:
        new = date_format(f["format"])
        if new != f["format"]:
            fx.note(f"`{label}.format: {f['format']}` -> `{new}`")
            f["format"] = new
    for k in ("required", "nullable", "description", "comment"):
        f.pop(k, None)
    for k in [k for k in f if _n(k) in ("transform", "transforms", "transformation", "filter", "filters")]:
        steps = f.pop(k)
        for step in steps if isinstance(steps, list) else [steps]:
            s = _n(step)
            if s in ("lowercase", "lower", "tolower", "downcase"):
                f["lower"] = True
            elif s in ("int", "integer", "toint", "parseint"):
                f["type"] = "int"
            elif s in ("float", "number", "tofloat", "parsefloat"):
                f["type"] = "float"
            elif s in ("datetime", "date", "timestamp", "todatetime", "parsedate", "parsedatetime", "iso8601"):
                f["type"] = "datetime"
            elif s in ("trim", "strip", "string", "str", "tostring"):
                pass  # values are already trimmed strings
            else:
                raise IntakeError(f"{label}.{k}: `{step}` is not a supported transform; use lowercase, int, float, "
                                  "datetime, or the mapping options map / regex / template / const")
        fx.note(f"`{label}.{k}: {steps}` -> mapping options")
    return f


def _mapping(value: Any, entity: Any, fx: _Fixer, label: str) -> Any:
    from connectforge.config.schema import (
        ENTITY_FIELDS,  # late import: spec imports this module
    )

    if value in (None, "", "auto", "automatic", "AUTO"):
        return value
    if isinstance(value, list):
        out = {}
        for item in value:
            if not isinstance(item, dict):
                return value
            item = dict(item)
            target = next((item.pop(k) for k in ("target", "to", "dest", "destination", "name", "field_name", "output")
                           if k in item), None)
            if target is None:
                return value
            out[str(target)] = item if len(item) > 1 or "from" not in item else item
        fx.note(f"`{label}` written as a list -> one entry per target field")
        value = out
    if not isinstance(value, dict):
        return value
    allowed = set(ENTITY_FIELDS.get(entity, {})) if entity in ENTITY_FIELDS and entity != "record" else set()
    if allowed:
        unknown_keys = [k for k in value if k not in allowed]
        flips = [k for k in unknown_keys if isinstance(value[k], str) and value[k] in allowed]
        if unknown_keys and len(flips) == len(unknown_keys) and \
                sum(isinstance(v, str) and v in allowed for v in value.values()) > sum(k in allowed for k in value):
            fx.note(f"`{label}` was written source: target; turned round to target: source")
            value = {v: k for k, v in value.items()}
    return {k: _field(v, fx, f"{label}.{k}") for k, v in value.items()}


def _rate_limit(value: Any, fx: _Fixer) -> Any:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        fx.note(f"`rate_limit: {value}` -> `{{requests_per_second: {value}}}`")
        return {"requests_per_second": value}
    if not isinstance(value, dict):
        return value
    r = dict(value)
    for key, div in (("requests_per_minute", 60), ("rpm", 60), ("per_minute", 60), ("calls_per_minute", 60),
                     ("requests_per_hour", 3600), ("per_hour", 3600), ("rps", 1), ("per_second", 1),
                     ("calls_per_second", 1), ("max_requests_per_second", 1)):
        if key in r and "requests_per_second" not in r:
            n = r.pop(key)
            r["requests_per_second"] = round(float(n) / div, 4)
            fx.note(f"`rate_limit.{key}: {n}` -> `requests_per_second: {r['requests_per_second']}`")
    for key in ("max_burst", "burst_size"):
        if key in r and "burst" not in r:
            r["burst"] = r.pop(key)
    return r


def _retry(value: Any, fx: _Fixer) -> Any:
    if isinstance(value, int) and not isinstance(value, bool):
        fx.note(f"`retry: {value}` -> {value} retries after the first try (`max_attempts: {value + 1}`)")
        return {"max_attempts": value + 1}
    if not isinstance(value, dict):
        return value
    raw = dict(value)
    for k in [k for k in raw if _n(k) in ("backoff", "backoffstrategy", "strategy", "backofftype") and isinstance(raw[k], str)]:
        fx.note(f"dropped `retry.{k}: {raw.pop(k)}` (retries always back off exponentially: 1 s, 2 s, 4 s...)")
    retries = raw.pop("max_retries", None) if "max_retries" in raw else raw.pop("retries", None)
    r = fx.rename(raw, KEY_ALIASES["retry"], "retry.", "retry")
    if retries is not None and "max_attempts" not in r:
        r["max_attempts"] = int(retries) + 1
        fx.note(f"`retry.max_retries: {retries}` -> `max_attempts: {int(retries) + 1}` (retries plus the first try)")
    return r


def _cursor(value: dict, fx: _Fixer) -> dict:
    c = fx.rename(value, KEY_ALIASES["cursor"], "cursor.", "cursor")
    if "field" in c:
        c["field"] = jsonpath(c["field"])
    return c


def _endpoints(d: dict, fx: _Fixer) -> Any:
    eps = d["endpoints"]
    if isinstance(eps, dict):
        eps = [{"name": k, **(v if isinstance(v, dict) else {"path": v})} for k, v in eps.items()]
        fx.note("`endpoints` written as a map -> a list with one entry per endpoint")
    if not isinstance(eps, list):
        return eps
    base = d.get("request", {}).get("base_url")
    if isinstance(base, str) and base.endswith("/"):
        base = d["request"]["base_url"] = base.rstrip("/")
    out = []
    for i, ep in enumerate(eps):
        if not isinstance(ep, dict):
            out.append(ep)
            continue
        e = dict(ep)
        label = f"endpoints.{e.get('name', i)}."
        for k in list(e):
            if str(k).lower() in IGNORED:
                fx.note(f"ignored `{label}{k}`")
                del e[k]
        if isinstance(e.get("request"), dict):  # endpoint written with its own `request:` block
            inner = _request(dict(e.pop("request")), fx, f"{label}request.")
            for k, v in inner.items():
                e.setdefault("path" if k == "base_url" else k, v)
        for k in [k for k in e if _n(k) in ("url", "uri", "endpointurl") and "path" not in e]:
            e["path"] = e.pop(k)  # reported below, once it is known what part of the URL is the path
        e = fx.rename(e, _endpoint_aliases(e), label)
        path = e.get("path")
        if isinstance(path, str) and path.startswith(("http://", "https://")):
            parts = urlsplit(path)
            origin = f"{parts.scheme}://{parts.netloc}"
            if not base:
                base = origin
                d.setdefault("request", {})["base_url"] = origin
                fx.note(f"set `request.base_url: {origin}` from the endpoint URLs")
            if path.startswith(base):
                e["path"] = path[len(base):] or "/"
            elif origin == f"{urlsplit(base).scheme}://{urlsplit(base).netloc}":
                e["path"] = parts.path
            else:
                raise IntakeError(f"{label}path: {path} is on a different host than {base}; put it in its own file")
            if parts.query:
                e["path"] = e["path"].split("?", 1)[0]
                e["params"] = {**dict(parse_qsl(parts.query)), **(e.get("params") or {})}
            fx.note(f"`{label}url: {path}` -> `{label}path: {'/' + e['path'].lstrip('/')}`")
        if isinstance(e.get("path"), str) and "?" in e["path"]:
            p, q = e["path"].split("?", 1)
            e["path"], e["params"] = p, {**dict(parse_qsl(q)), **(e.get("params") or {})}
            fx.note(f"moved the query string out of `{label}path` into `{label}params`")
        if isinstance(e.get("path"), str) and e["path"] and not e["path"].startswith("/"):
            e["path"] = "/" + e["path"]
        if isinstance(e.get("method"), str):
            e["method"] = e["method"].upper()
        if "name" not in e or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,40}", str(e["name"])):
            src = e.get("name") or e.get("title") or (str(e.get("path", "")).rstrip("/").rsplit("/", 1)[-1]) or f"endpoint{i + 1}"
            new = re.sub(r"[^a-z0-9_-]+", "-", str(src).lower()).strip("-_")[:40] or f"endpoint{i + 1}"
            if e.get("name") != new:
                fx.note(f"endpoint name `{e.get('name', '')}` -> `{new}`")
            e.setdefault("title", e.get("name") or None)
            if e["title"] is None:
                e.pop("title")
            e["name"] = new
        if "entity" in e:
            e["entity"] = _entity(e["entity"], fx, f"{label}entity")
        if "schedule" in e:
            e["schedule"] = _schedule(e["schedule"], fx, f"{label}schedule")
        if "pagination" in e:
            e["pagination"] = _pagination(e["pagination"], fx, f"{label}pagination.")
        if "records" in e:
            e["records"] = _records(e["records"], fx, f"{label}records")
        if "mapping" in e:
            e["mapping"] = _mapping(e["mapping"], e.get("entity", d.get("entity", "event")), fx, f"{label}mapping")
        out.append(e)
    return out


def _shared_values(d: dict) -> set:
    """ids of objects that appear more than once (YAML anchors and aliases share one object)."""
    counts: Dict[int, int] = {}

    def walk(obj: Any) -> None:
        if isinstance(obj, (dict, list)):
            counts[id(obj)] = counts.get(id(obj), 0) + 1
            if counts[id(obj)] > 1:
                return
            for v in obj.values() if isinstance(obj, dict) else obj:
                walk(v)

    walk(d)
    return {i for i, n in counts.items() if n > 1}


def _endpoint_aliases(e: dict) -> Dict[str, str]:
    """An endpoint takes the same alternative names as the top level (`data_path`, `interval`...) and
    the request ones (`endpoint`, `query`...), mapped onto endpoint settings."""
    from connectforge.config.schema import ENDPOINT_KEYS

    table = {k: k for k in ENDPOINT_KEYS}
    for alias, target in TOP_ALIASES.items():
        if target.startswith("request."):
            table[alias] = target.split(".", 1)[1]
        elif target in ("records", "mapping", "schedule", "pagination", "entity"):
            table[alias] = target
    for alias, target in KEY_ALIASES["request"].items():
        if target in ENDPOINT_KEYS:
            table[alias] = target
    table.update({"endpoint": "path", "url": "path", "uri": "path", "endpoint_url": "path", "name_id": "name",
                  "display_name": "title", "label": "title", "response_path": "records", "result_path": "records"})
    table["type"] = "entity" if isinstance(e.get("type"), str) and e["type"].lower() in ENTITY_WORDS else "_type"
    return table


def _secrets_in_request(d: dict, fx: _Fixer) -> None:
    """`Authorization: Bearer ${API_TOKEN}` in headers -> `${secret:api_token}`."""
    req = d.get("request")
    if not isinstance(req, dict):
        return
    for block in ("headers", "params"):
        values = req.get(block)
        if not isinstance(values, dict):
            continue
        for k, v in values.items():
            if isinstance(v, str) and _INLINE_ENV.search(v):
                new = _INLINE_ENV.sub(lambda m: f"${{secret:{secret_name(m.group(1) or m.group(2) or m.group(3))}}}", v)
                fx.note(f"`request.{block}.{k}`: `{v}` -> `{new}` (save the value on the Secrets tab)")
                values[k] = new


def suggest(key: str, choices: List[str]) -> Optional[str]:
    """`schedual` -> `schedule`."""
    hit = difflib.get_close_matches(str(key), choices, n=1, cutoff=0.75)
    return hit[0] if hit else None


def corrected_yaml(text: str) -> str:
    """The file rewritten in the canonical form (what ConnectForge understood), for the user to keep."""
    docs, _ = read_documents(text)
    out = []
    for doc in docs:
        clean, _ = normalize(doc)
        order = ["id", "name", "description", "source", "entity", "kind", "enabled", "schedule", "auth", "request",
                 "allowed_hosts", "pagination", "cursor", "records", "rate_limit", "retry", "mapping", "endpoints"]
        ordered = {k: clean[k] for k in order if k in clean}
        ordered.update({k: v for k, v in clean.items() if k not in ordered})
        out.append(yaml.safe_dump(ordered, sort_keys=False, allow_unicode=True, default_flow_style=False, width=120))
    return "---\n".join(out)


_PER_ENDPOINT_KEYS = ("entity", "records", "pagination", "cursor", "mapping", "columns", "description", "schedule")


def to_integration(text: str) -> Optional[str]:
    """Rewrite a single-endpoint connector file as an integration with an `endpoints:` list (same settings,
    same source, header comments kept). None if it already has endpoints or is a file-tailing connector."""
    docs, _ = read_documents(text)
    if len(docs) != 1:
        return None
    doc = docs[0]
    if "endpoints" in doc or doc.get("kind") == "file" or not isinstance(doc.get("request"), dict):
        return None
    req = dict(doc["request"])
    path = req.pop("path", "")
    seg = [p for p in re.split(r"[/?]", path) if p and not re.fullmatch(r"v\d+(\.\d+)?|api|rest|json|\{.*\}", p)]
    name = re.sub(r"[^a-z0-9_-]+", "-", (seg[-1] if seg else doc.get("entity", "data")).lower()).strip("-_")[:40] or "data"
    ep: Dict[str, Any] = {"name": name, "title": doc.get("name", name)}
    for k in ("entity",):
        if k in doc:
            ep[k] = doc[k]
    ep["path"] = path
    for k in ("method", "params", "body", "response_format", "timeout_seconds"):
        if k in req:
            ep[k] = req.pop(k)
    for k in _PER_ENDPOINT_KEYS:
        if k in doc and k not in ep:
            ep[k] = doc[k]
    top = {k: v for k, v in doc.items() if k not in _PER_ENDPOINT_KEYS and k != "request"}
    top.setdefault("source", doc.get("source") or doc.get("id"))   # stored records keep their source
    top["request"] = req
    order = ["id", "name", "source", "kind", "enabled", "allowed_hosts", "auth", "request", "rate_limit", "retry"]
    out = {k: top[k] for k in order if k in top}
    out.update({k: v for k, v in top.items() if k not in out})
    out["endpoints"] = [ep]
    header = "".join(line for line in text.splitlines(True)[:40] if line.startswith("#"))
    return header + yaml.safe_dump(out, sort_keys=False, allow_unicode=True, width=120)
