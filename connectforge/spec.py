"""Connector specification — the config language. Validated before anything runs (B-2).

A connector says how to log in (FR-1), which endpoint to call (FR-2), how to page (FR-3),
how often to run (FR-4) and how to map records into one common schema (FR-5). The schema has
three entities, each stored in its own table: users, devices and events (events = alerts too).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Literal, Optional
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

# Common schema (PRD §4). `source` and `fetched_at` are added to every record by the platform.
ENTITY_FIELDS: Dict[str, Dict[str, str]] = {
    "user": {"id": "str", "name": "str", "email": "str", "status": "str", "last_login": "datetime",
             "title": "str", "department": "str", "mfa_enabled": "bool"},
    "device": {"id": "str", "hostname": "str", "ip": "ip", "os": "str", "owner": "str", "last_seen": "datetime",
               "mac": "str", "status": "str"},
    "event": {"id": "str", "type": "str", "severity": "str", "timestamp": "datetime", "description": "str",
              "user": "str", "src_ip": "ip", "dst_ip": "ip", "dst_port": "int", "action": "str", "outcome": "str",
              "cve": "str", "product": "str", "url": "str", "country": "str", "score": "float"},
}
REQUIRED: Dict[str, List[str]] = {
    "user": ["id", "name"],
    "device": ["id", "hostname"],
    "event": ["id", "type", "timestamp"],
}
TABLES = {"user": "users", "device": "devices", "event": "events"}
SECRET_REF = re.compile(r"\$\{secret:([a-zA-Z0-9_.-]+)\}")
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


class RequestSpec(_Strict):
    base_url: str
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
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]{2,40}$")
    name: str
    description: str = ""
    source: Optional[str] = None             # value stored in every record's `source` (default: id)
    entity: Literal["user", "device", "event"] = "event"
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
    mapping: Dict[str, FieldMap]

    @field_validator("mapping", mode="before")
    @classmethod
    def _shorthand(cls, v):
        # PRD style: `email: profile.login` means `email: {from: profile.login}`
        if isinstance(v, dict):
            return {k: ({"from": m} if isinstance(m, str) else m) for k, m in v.items()}
        return v

    @model_validator(mode="after")
    def _consistency(self):
        allowed = ENTITY_FIELDS[self.entity]
        unknown = sorted(set(self.mapping) - set(allowed))
        if unknown:
            raise ValueError(f"mapping: unknown {self.entity} field(s) {unknown}; allowed: {sorted(allowed)}")
        missing = [f for f in REQUIRED[self.entity] if f not in self.mapping]
        if missing:
            raise ValueError(f"mapping: required {self.entity} field(s) {missing} have no mapping")
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
                    raise ValueError(f"auth.{name}: credentials must come from the vault (`secret: name`), "
                                     "never written in the config")
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


class SpecError(ValueError):
    def __init__(self, errors: List[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


def parse_spec(text: str) -> ConnectorSpec:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise SpecError([f"YAML syntax: {e}"]) from e
    if not isinstance(data, dict):
        raise SpecError(["connector file must be a YAML mapping"])
    try:
        return ConnectorSpec.model_validate(data)
    except ValidationError as e:
        raise SpecError([
            f"{'.'.join(str(p) for p in err['loc']) or 'connector'}: {err['msg'].removeprefix('Value error, ')}"
            for err in e.errors()
        ]) from e


def masked(spec: ConnectorSpec) -> dict:
    """The spec as stored — it only ever contains secret *names*, never values."""
    return spec.model_dump(mode="json", by_alias=True, exclude_none=True)
