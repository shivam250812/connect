"""Connector specification — the config language. Validated before anything runs (B-2).

A connector says how to log in (FR-1), which endpoint to call (FR-2), how to page (FR-3),
how often to run (FR-4) and how to map records into one common schema (FR-5). The schema has
three entities, each stored in its own table: users, devices and events (events = alerts too),
plus `record` for anything else an API returns (patches, software, vulnerabilities...): every
field is kept and shown.

One file can describe a whole integration: the login, base URL and limits once, then an
`endpoints:` list. Each endpoint becomes its own connector (`<id>.<endpoint>`) sharing that login.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

# Common schema (PRD §4). `source` and `fetched_at` are added to every record by the platform.
ENTITY_FIELDS: Dict[str, Dict[str, str]] = {
    "user": {"id": "str", "name": "str", "email": "str", "status": "str", "last_login": "datetime",
             "title": "str", "department": "str", "mfa_enabled": "bool"},
    "device": {"id": "str", "hostname": "str", "ip": "ip", "os": "str", "owner": "str", "last_seen": "datetime",
               "mac": "str", "status": "str"},
    "event": {"id": "str", "type": "str", "severity": "str", "timestamp": "datetime", "description": "str",
              "user": "str", "src_ip": "ip", "dst_ip": "ip", "dst_port": "int", "action": "str", "outcome": "str",
              "cve": "str", "product": "str", "url": "str", "country": "str", "score": "float"},
    # anything else: id, a title and a time are columns; every other mapped field is kept in `data`
    "record": {"id": "str", "title": "str", "timestamp": "datetime", "data": "str"},
}
REQUIRED: Dict[str, List[str]] = {
    "user": ["id", "name"],
    "device": ["id", "hostname"],
    "event": ["id", "type", "timestamp"],
    "record": [],  # without an id field, the record's content hash is its id
}
TABLES = {"user": "users", "device": "devices", "event": "events", "record": "records"}
_RECORD_FIELD = re.compile(r"^[a-z_][a-z0-9_]{0,60}$")
SECRET_REF = re.compile(r"\$\{secret:([a-zA-Z0-9_.-]+)\}")
_ANY_REF = re.compile(r"\$\{(secret|env|zscaler_key):[A-Za-z0-9_.-]+\}")
# keys that carry credentials when they appear in headers / query params / bodies
_CREDENTIAL_KEY = re.compile(r"(^|[-_])(authorization|api[-_]?key|apikey|x[-_]api[-_]key|token|access[-_]?token|"
                             r"secret|client[-_]?secret|password|passwd|pwd|session|cookie|private[-_]?key|"
                             r"signature|uaks)($|[-_])|^key$", re.I)
# well-known token formats — rejected wherever they are pasted, under any key
KNOWN_TOKEN = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|"
    r"sk_live_[A-Za-z0-9]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def find_plaintext_credentials(obj, where: str = "") -> List[str]:
    """Locations in a config where a credential is written literally instead of as ${secret:…}/${env:…}."""
    found: List[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            loc = f"{where}.{k}" if where else str(k)
            if isinstance(v, str) and _CREDENTIAL_KEY.search(str(k)) and v.strip() and not _ANY_REF.search(v) \
                    and not re.fullmatch(r"(?i)(bearer|basic|token|sswS|apikey)?\s*", v):
                found.append(loc)
            else:
                found += find_plaintext_credentials(v, loc)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            found += find_plaintext_credentials(v, f"{where}[{i}]")
    elif isinstance(obj, str) and KNOWN_TOKEN.search(obj):
        found.append(where or "value")
    return found
_DURATION = re.compile(r"^\s*(\d+)\s*(s|sec|m|min|h|hr|d)\w*\s*$", re.I)


def parse_duration(value: Any) -> int:
    if isinstance(value, (int, float)):
        return int(value)
    m = _DURATION.match(str(value))
    if not m:
        raise ValueError(f"cannot read duration '{value}' (use e.g. 30s, 15m, 1h)")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)[0].lower()]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class LoginSpec(_Strict):
    """Token exchange: call a login endpoint first, then use the token it returns on every request.
    Covers vendors such as Prisma Cloud, Lacework, Cisco FMC, ArcSight, Forcepoint and Zscaler."""
    url: str
    method: Literal["POST", "GET"] = "POST"
    json_body: Optional[Dict[str, Any]] = Field(None, alias="json")
    form: Optional[Dict[str, Any]] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    basic_username: Optional[str] = None      # send HTTP basic auth on the login call
    basic_password: Optional[str] = None
    token_from: Literal["body", "header", "cookie"] = "body"
    token_path: str = "token"                 # body: JSON path · header/cookie: the name
    expires_in_path: Optional[str] = None
    ttl_seconds: int = 600                    # used when the response does not say when it expires


class DiscoverSpec(_Strict):
    """After logging in, ask the API where your data lives (e.g. Sophos Central whoami)."""
    url: str
    base_url_path: Optional[str] = None       # response path holding the real API base URL
    headers: Dict[str, str] = Field(default_factory=dict)  # header name -> response path (e.g. X-Tenant-ID: id)


class AuthSpec(_Strict):
    type: Literal["none", "api_key", "bearer", "basic", "oauth2_client_credentials", "aws_sigv4",
                  "token_exchange", "google_service_account", "cortex_advanced"] = "none"
    # PRD shorthand: `secret: okta_key` names the vault entry holding the credential.
    secret: Optional[str] = None
    optional: bool = False                 # skip auth if the secret is not set (e.g. NVD key is optional)
    header: Optional[str] = None           # api_key: header name (default X-API-Key)
    in_: Literal["header", "query"] = Field("header", alias="in")
    param: Optional[str] = None            # api_key in query: parameter name
    scheme: str = "Bearer"                 # bearer: "Bearer", "SSWS" (Okta), "token"
    token: Optional[str] = None
    value: Optional[str] = None
    username: Optional[str] = None         # basic: e.g. Jira account email (not a secret)
    password: Optional[str] = None
    token_url: Optional[str] = None        # oauth2 client credentials
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    scope: Optional[str] = None
    access_key_id: Optional[str] = None    # aws_sigv4
    secret_access_key: Optional[str] = None
    region: str = "us-east-1"
    service: Optional[str] = None
    client_auth: Literal["basic", "body"] = "basic"   # oauth2: how client_id/secret are sent
    extra: Dict[str, str] = Field(default_factory=dict)  # oauth2: extra token fields, e.g. audience
    login: Optional[LoginSpec] = None                # token_exchange
    discover: Optional[DiscoverSpec] = None          # optional second step after any login
    key_id: Optional[str] = None                     # cortex_advanced: the API key ID (not secret)

    _urls_are_http = field_validator("token_url")(classmethod(lambda cls, v: _http_url(v)))

    @model_validator(mode="after")
    def _expand_secret(self):
        if self.secret:
            ref = f"${{secret:{self.secret}}}"
            slot = {"api_key": "value", "bearer": "token", "basic": "password",
                    "oauth2_client_credentials": "client_secret", "google_service_account": "value",
                    "cortex_advanced": "value"}.get(self.type)
            if not slot:
                raise ValueError(f"'secret' shorthand is not supported for auth type '{self.type}'")
            if getattr(self, slot) is None:
                setattr(self, slot, ref)
        if self.type == "api_key":
            if self.value is None:
                raise ValueError("api_key auth needs `secret: <name>`")
            if self.in_ == "header" and not self.header:
                self.header = "X-API-Key"
            if self.in_ == "query" and not self.param:
                raise ValueError("api_key with in: query needs `param`")
        if self.type == "basic" and (self.username is None or self.password is None):
            raise ValueError("basic auth needs `username` and `secret` (or password)")
        if self.type == "bearer" and self.token is None:
            raise ValueError("bearer auth needs `secret: <name>`")
        if self.type == "oauth2_client_credentials" and not (self.token_url and self.client_id and self.client_secret):
            raise ValueError("oauth2_client_credentials needs token_url, client_id and secret")
        if self.type == "token_exchange":
            if not self.login:
                raise ValueError("token_exchange needs a `login:` block")
            if not self.header:
                self.header = "Authorization"
        if self.type == "google_service_account" and (self.value is None or not self.scope):
            raise ValueError("google_service_account needs `secret` (the JSON key) and `scope`")
        if self.type == "cortex_advanced" and (self.value is None or not self.key_id):
            raise ValueError("cortex_advanced needs `secret` (API key) and `key_id`")
        return self


def _http_url(value: Optional[str]) -> Optional[str]:
    if value is not None and not re.match(r"^https?://[^/\s]+", value):
        raise ValueError(f"`{value}` must be an http:// or https:// address")
    return value


class RequestSpec(_Strict):
    base_url: str

    _base_is_http = field_validator("base_url")(classmethod(lambda cls, v: _http_url(v)))
    path: str = ""
    method: Literal["GET", "POST"] = "GET"
    params: Dict[str, Any] = Field(default_factory=dict)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Dict[str, Any]] = None
    timeout_seconds: float = 20.0
    response_format: Literal["json", "xml"] = "json"


class PaginationSpec(_Strict):
    type: Literal["none", "link_header", "next_url", "next_token", "page_number", "offset"] = "none"
    token_path: Optional[str] = None
    token_param: Optional[str] = None
    token_in: Literal["query", "body"] = "query"
    page_param: str = "page"
    page_size_param: Optional[str] = None
    page_size: int = 100
    start_page: int = 1
    offset_param: str = "offset"
    offset_end_param: Optional[str] = None  # APIs that take a range (Cortex: search_from / search_to)
    params_in: Literal["query", "body"] = "query"  # where page/offset/size params go; body paths may nest (a.b[0].c)
    total_path: Optional[str] = None        # offset: stop once offset >= total (e.g. NVD totalResults)
    has_more_path: Optional[str] = None     # stop when this response flag is false (GraphQL hasNextPage)
    max_pages: int = Field(20, ge=1, le=1000)


class CursorSpec(_Strict):
    """Incremental sync (B-1): send the newest timestamp seen last run; fetch only newer records."""
    field: str
    param: str
    param_in: Literal["query", "body"] = Field("query", alias="in")
    end_param: Optional[str] = None         # some APIs (NVD) need an explicit window end = now
    template: str = "{value}"               # e.g. ">={value}" for search-style filters
    initial: str = "-1d"
    format: Literal["iso", "iso_z", "date", "epoch", "epoch_ms"] = "iso_z"


class ScheduleSpec(_Strict):
    every: Any = "15m"

    @property
    def seconds(self) -> int:
        return parse_duration(self.every)

    @field_validator("every")
    @classmethod
    def _valid(cls, v):
        if parse_duration(v) < 1:
            raise ValueError("schedule must be at least 1 second")
        return v


class RetrySpec(_Strict):
    """Default matches the PRD: retry after 1 s, 2 s, 4 s, then mark the run failed."""
    max_attempts: int = Field(4, ge=1, le=10)
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    jitter: bool = False
    retry_on: List[int] = Field(default_factory=lambda: [408, 429, 500, 502, 503, 504])


class RateLimitSpec(_Strict):
    requests_per_second: float = Field(5.0, gt=0)
    burst: int = Field(5, ge=1)


class FileSpec(_Strict):
    path: str
    format: Literal["kv", "regex", "csv", "jsonl", "cef"] = "jsonl"
    filter: Optional[str] = None            # only lines matching this regex (shared syslog files)
    pattern: Optional[str] = None
    columns: List[str] = Field(default_factory=list)
    delimiter: str = ","
    max_bytes_per_run: int = 1_000_000


class FieldMap(_Strict):
    from_: Optional[str] = Field(None, alias="from")
    const: Any = None
    template: Optional[str] = None
    parse_json: bool = False
    path: Optional[str] = None
    regex: Optional[str] = None
    lower: bool = False
    map: Optional[Dict[str, Any]] = None
    map_default: Any = None
    type: Optional[Literal["str", "int", "float", "datetime", "ip", "bool"]] = None
    format: Optional[str] = None
    default: Any = None

    @model_validator(mode="after")
    def _one_source(self):
        if sum(x is not None for x in (self.from_, self.const, self.template)) > 1:
            raise ValueError("use only one of from / const / template")
        return self


class ConnectorSpec(_Strict):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,40}(\.[a-z0-9][a-z0-9_-]{0,40})?$")
    name: str
    description: str = ""
    source: Optional[str] = None             # value stored in every record's `source` (default: id)
    entity: Literal["user", "device", "event", "record"] = "event"
    integration: Optional[str] = None        # set for endpoints of a multi-endpoint file: the file's id
    integration_name: Optional[str] = None
    endpoint: Optional[str] = None
    columns: List[str] = Field(default_factory=list)  # optional display order for the Data view
    kind: Literal["http", "file"] = "http"
    enabled: bool = True
    allowed_hosts: List[str] = Field(default_factory=list)
    schedule: ScheduleSpec = Field(default_factory=ScheduleSpec)
    auth: AuthSpec = Field(default_factory=AuthSpec)
    request: Optional[RequestSpec] = None
    pagination: PaginationSpec = Field(default_factory=PaginationSpec)
    cursor: Optional[CursorSpec] = None
    records: str = ""
    file: Optional[FileSpec] = None
    rate_limit: RateLimitSpec = Field(default_factory=RateLimitSpec)
    retry: RetrySpec = Field(default_factory=RetrySpec)
    mapping: Optional[Dict[str, FieldMap]] = None   # None (left out, empty, or `auto`) = learned from the data

    @field_validator("mapping", mode="before")
    @classmethod
    def _shorthand(cls, v):
        if v is None or (isinstance(v, str) and v.strip().lower() == "auto"):
            return None
        # PRD style: `email: profile.login` means `email: {from: profile.login}`
        if isinstance(v, dict):
            return {k: ({"from": m} if isinstance(m, str) else m) for k, m in v.items()}
        return v

    @model_validator(mode="after")
    def _consistency(self):
        allowed = ENTITY_FIELDS[self.entity]
        if self.entity == "record":  # free-form fields, kept in `data`
            allowed = {k for k in (self.mapping or {}) if _RECORD_FIELD.match(k)} - {"data", "source", "connector"}
        unknown = sorted(set(self.mapping or {}) - set(allowed))
        if unknown:
            raise ValueError(f"mapping: unknown {self.entity} field(s) {unknown}; allowed: {sorted(allowed)}")
        missing = [f for f in REQUIRED[self.entity] if self.mapping is not None and f not in self.mapping]
        if missing:
            raise ValueError(f"mapping: required {self.entity} field(s) {missing} have no mapping "
                             f"(or leave `mapping` out to map automatically)")
        if self.kind == "http" and not self.request:
            raise ValueError("kind: http requires a 'request' block")
        if self.kind == "file" and not self.file:
            raise ValueError("kind: file requires a 'file' block")
        if self.kind == "http":
            hosts = self.egress_hosts()
            urls = [self.request.base_url, self.auth.token_url,
                    self.auth.login.url if self.auth.login else None,
                    self.auth.discover.url if self.auth.discover else None]
            for url in filter(None, urls):
                host = urlsplit(url).hostname
                if not self.host_allowed(host):
                    raise ValueError(f"host '{host}' is not in allowed_hosts {sorted(hosts)}")
            if self.auth.login:
                bodies = {**(self.auth.login.json_body or {}), **(self.auth.login.form or {}),
                          **self.auth.login.headers}
                for key, val in bodies.items():
                    if re.search(r"pass|secret|api_?key|token|uaks", key, re.I) and isinstance(val, str) \
                            and not (SECRET_REF.search(val) or val.startswith("${zscaler_key:")):
                        raise ValueError(f"auth.login.{key}: credentials must come from the vault (`${{secret:name}}`)")
                if self.auth.login.basic_password and not SECRET_REF.fullmatch(self.auth.login.basic_password):
                    raise ValueError("auth.login.basic_password must be a ${secret:name} reference")
            for name, value in self.auth.model_dump().items():
                if name in ("token", "value", "password", "client_secret", "secret_access_key") and value \
                        and not SECRET_REF.fullmatch(value):
                    raise ValueError(f"auth.{name}: looks like a credential written in plain text. Save it on the "
                                     "Secrets tab and write `secret: <name>` instead (the file holds only names)")
            leaks = find_plaintext_credentials(
                {"headers": self.request.headers, "params": self.request.params, "body": self.request.body or {}},
                "request")
            if leaks:
                raise ValueError(f"{', '.join(leaks)}: looks like a credential written in plain text. Store it in "
                                 "the vault and reference it as ${secret:name} (or ${env:NAME})")
        # well-known token formats are refused anywhere in the file (mapping constants, descriptions, …)
        anywhere = [loc for loc in find_plaintext_credentials(self.model_dump(mode="json", by_alias=True))
                    if KNOWN_TOKEN.search(str(_dig(self.model_dump(mode="json", by_alias=True), loc)))]
        if anywhere:
            raise ValueError(f"{', '.join(anywhere)}: contains a real-looking token (GitHub/AWS/Slack/Stripe/Google/"
                             "private key/JWT). Secrets must not be written in a config file")
        return self

    @property
    def source_name(self) -> str:
        return self.source or self.id

    @property
    def secret_names(self) -> List[str]:
        """The only vault entries this connector may read — exactly those its config references."""
        dumped = self.model_dump_json()
        return sorted(set(SECRET_REF.findall(dumped)) | set(re.findall(r"\$\{zscaler_key:([a-zA-Z0-9_.-]+)\}", dumped)))

    def egress_hosts(self) -> set:
        hosts = set(self.allowed_hosts)
        if self.request and not hosts:
            for url in filter(None, [self.request.base_url, self.auth.token_url,
                                     self.auth.login.url if self.auth.login else None,
                                     self.auth.discover.url if self.auth.discover else None]):
                hosts.add(urlsplit(url).hostname)
        return hosts

    def host_allowed(self, host: Optional[str]) -> bool:
        """Exact names, or wildcards like `*.central.sophos.com` for region-specific API hosts."""
        if not host:
            return False
        return any(host == h or (h.startswith("*.") and host.endswith(h[1:])) for h in self.egress_hosts())


def _dig(obj, loc: str):
    for i, k, _empty in re.findall(r"\[(\d+)\]|\.?([^.\[\]]+)|()", loc):
        if i:
            obj = obj[int(i)] if isinstance(obj, list) and int(i) < len(obj) else None
        elif k:
            obj = obj.get(k) if isinstance(obj, dict) else None
    return obj


class SpecError(ValueError):
    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


# What an entry under `endpoints:` may set. Everything else (login, base URL, limits, retries) is shared.
ENDPOINT_KEYS = {"name", "title", "description", "entity", "enabled", "source", "path", "method", "params", "headers",
                 "body", "response_format", "timeout_seconds", "records", "pagination", "cursor", "mapping",
                 "schedule", "columns"}
_PER_ENDPOINT = {"entity", "enabled", "source", "description", "request", "records", "pagination", "cursor",
                 "mapping", "schedule", "columns", "name"}


def _expand(data: dict) -> tuple:
    """A file with `endpoints:` becomes one connector config per endpoint; otherwise the file itself.
    Returns ([(where, config)], errors) so every mistake in the file is reported at once."""
    if "endpoints" not in data:
        return [("", data)], []
    endpoints = data.pop("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise SpecError(["endpoints: must be a list with at least one endpoint"])
    pid, errors, out, seen = data.get("id"), [], [], set()
    for i, ep in enumerate(endpoints):
        name = ep.get("name") if isinstance(ep, dict) else None
        if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,40}", name):
            errors.append(f"endpoints[{i}].name: required; lowercase letters, digits, - and _")
            continue
        where = f"endpoints.{name}"
        if name in seen:
            errors.append(f"{where}: two endpoints have this name")
            continue
        seen.add(name)
        for k in sorted(set(ep) - ENDPOINT_KEYS):
            from connectforge.config.intake import suggest
            hint = suggest(k, sorted(ENDPOINT_KEYS))
            errors.append(f"{where}.{k}: unknown setting, not part of an endpoint"
                          + (f" (did you mean '{hint}'?)" if hint else " (check the spelling or remove it)"))
        child = {k: copy.deepcopy(v) for k, v in data.items() if k not in ("mapping", "records", "cursor")}
        req = dict(child.get("request") or {})
        for k in ("path", "method", "body", "response_format", "timeout_seconds"):
            if k in ep:
                req[k] = ep[k]
        for k in ("params", "headers"):
            if k in ep:
                req[k] = {**(req.get(k) or {}), **(ep[k] or {})}
        if req:
            child["request"] = req
        for k in ("entity", "enabled", "records", "pagination", "cursor", "mapping", "schedule", "columns", "description"):
            if k in ep:
                child[k] = ep[k]
        child.update(id=f"{pid}.{name}", name=ep.get("title") or name.replace("_", " ").replace("-", " ").capitalize(),
                     source=ep.get("source") or data.get("source") or pid, integration=pid,
                     integration_name=data.get("name"), endpoint=name)
        out.append((where, child))
    return out, errors


def _keys(model) -> List[str]:
    return [f.alias or name for name, f in model.model_fields.items()]


def _section_keys(loc: tuple) -> List[str]:
    """The settings allowed where an unknown key was found, for "did you mean" hints."""
    parent = [str(p) for p in loc[:-1]]
    sections = {(): ConnectorSpec, ("request",): RequestSpec, ("auth",): AuthSpec, ("pagination",): PaginationSpec,
                ("schedule",): ScheduleSpec, ("cursor",): CursorSpec, ("retry",): RetrySpec,
                ("rate_limit",): RateLimitSpec, ("file",): FileSpec, ("auth", "login"): LoginSpec,
                ("auth", "discover"): DiscoverSpec}
    if len(parent) == 2 and parent[0] == "mapping":
        return _keys(FieldMap)
    model = sections.get(tuple(parent))
    return _keys(model) + (["endpoints"] if model is ConnectorSpec else []) if model else []


def _messages(e: ValidationError, where: str) -> List[str]:
    from connectforge.config.intake import suggest

    out = []
    for err in e.errors():
        loc = ".".join(str(p) for p in err["loc"])
        prefix = where if where and (not err["loc"] or err["loc"][0] in _PER_ENDPOINT) else ""
        path = ".".join(p for p in (prefix, loc) if p) or "connector"
        if err["type"] == "extra_forbidden":
            hint = suggest(str(err["loc"][-1]), _section_keys(err["loc"]))
            msg = "unknown setting, not part of the connector format" + \
                (f" (did you mean '{hint}'?)" if hint else " (check the spelling or remove it)")
        else:
            msg = err["msg"].removeprefix("Value error, ")
        out.append(f"{path}: {msg}")
    return out


def parse_specs_with_fixes(text: str) -> tuple:
    """Every connector a file defines, plus the automatic fixes applied to read it (see normalize.py).
    A file may hold one connector, an integration with `endpoints:`, or several configs (a YAML list or
    `---` documents); it may be JSON or sit inside a markdown ``` block."""
    from connectforge.config.intake import IntakeError, normalize, read_documents

    try:
        docs, fixes = read_documents(text)
    except IntakeError as e:
        raise SpecError([str(e)]) from e
    specs, errors = [], []
    for n, doc in enumerate(docs):
        label = f"[config {n + 1}] " if len(docs) > 1 else ""
        try:
            doc, notes = normalize(doc, label)
        except IntakeError as e:
            errors.append(f"{label}{e}")
            continue
        except Exception:  # noqa: BLE001 - a shape the fixer did not expect: validate as written instead
            notes = []
        fixes += notes
        try:
            items, problems = _expand(doc)
        except SpecError as e:
            errors += [f"{label}{m}" for m in e.errors]
            continue
        except (TypeError, AttributeError, ValueError) as e:
            errors.append(f"{label}endpoints: could not read the endpoint list ({e})")
            continue
        errors += [f"{label}{m}" for m in problems]
        for where, item in items:
            try:
                specs.append(ConnectorSpec.model_validate(item))
            except ValidationError as e:
                errors += [f"{label}{m}" for m in _messages(e, where) if f"{label}{m}" not in errors]
    dupes = sorted({s.id for s in specs if [x.id for x in specs].count(s.id) > 1})
    if dupes:
        errors.append(f"id used twice in this file: {', '.join(dupes)}")
    if errors:
        raise SpecError(errors)
    return specs, fixes


def parse_specs(text: str) -> List[ConnectorSpec]:
    """Every connector a file defines: one, or one per entry under `endpoints:`."""
    return parse_specs_with_fixes(text)[0]


def parse_spec(text: str) -> ConnectorSpec:
    """A file that defines exactly one connector (multi-endpoint files: use parse_specs)."""
    specs = parse_specs(text)
    if len(specs) != 1:
        raise SpecError([f"this file defines {len(specs)} endpoints; pick one by its id"])
    return specs[0]


def masked(spec: ConnectorSpec) -> dict:
    """The spec as stored — it only ever contains secret *names*, never values."""
    return spec.model_dump(mode="json", by_alias=True, exclude_none=True)
