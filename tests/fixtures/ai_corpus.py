"""Connector configs written the way AI assistants actually write them.

Each case: (name, text, expect, check). `expect` is "ok" (must be accepted, possibly after automatic
fixes) or "reject:<words the error must contain>". `check(specs)` asserts that what was understood is
what the author meant, so a "fix" can never silently change the meaning.
"""

GH = "https://api.github.com"


def _one(specs):
    assert len(specs) == 1, [s.id for s in specs]
    return specs[0]


CASES = [
    # --- wrappers around the YAML ------------------------------------------------------------
    ("markdown fence and chat text", '''Sure! Here is a ConnectForge config for GitHub advisories:

```yaml
id: github-advisories-ai
name: GitHub advisories
entity: event
auth: {type: bearer, secret: github_token}
request: {base_url: https://api.github.com, path: /advisories}
pagination: {type: link_header, page_size_param: per_page, page_size: 50}
```

This polls every 15 minutes. Save your token as `github_token` first.''', "ok",
     lambda s: _one(s).request.path == "/advisories"),

    ("json instead of yaml", '''{
  "id": "epss-json",
  "name": "EPSS",
  "entity": "event",
  "request": {"base_url": "https://api.first.org", "path": "/data/v1/epss", "params": {"epss-gt": 0.9}},
  "pagination": {"type": "offset", "offset_param": "offset", "page_size_param": "limit", "page_size": 100, "total_path": "total"},
  "records": "data"
}''', "ok", lambda s: _one(s).pagination.total_path == "total"),

    ("tabs used for indentation", "id: tabbed\nname: Tabbed\nrequest:\n\tbase_url: https://api.github.com\n\tpath: /users\n",
     "ok", lambda s: _one(s).request.path == "/users"),

    ("yaml list of two configs", '''- id: cisa-list
  name: CISA KEV
  request: {base_url: https://www.cisa.gov, path: /sites/default/files/feeds/known_exploited_vulnerabilities.json}
  records: vulnerabilities
- id: epss-list
  name: EPSS
  request: {base_url: https://api.first.org, path: /data/v1/epss}
''', "ok", lambda s: [x.id for x in s] == ["cisa-list", "epss-list"]),

    ("two yaml documents", '''id: doc-one
name: One
request: {base_url: https://api.github.com, path: /users}
---
id: doc-two
name: Two
request: {base_url: https://api.github.com, path: /advisories}
''', "ok", lambda s: [x.id for x in s] == ["doc-one", "doc-two"]),

    # --- different names for the same thing --------------------------------------------------
    ("flat url endpoint interval", '''name: GitHub Users
url: https://api.github.com
endpoint: /users
method: get
interval: 30m
entity: users
auth:
  type: bearer_token
  token: ${secret:github_token}
''', "ok", lambda s: (_one(s).request.base_url == GH and s[0].request.path == "/users" and s[0].request.method == "GET"
                      and s[0].schedule.seconds == 1800 and s[0].entity == "user" and s[0].id == "github-users")),

    ("api_url and headers at top level", '''id: okta-users-ai
name: Okta users
api_url: https://acme.okta.com/api/v1/users
headers:
  Accept: application/json
auth:
  type: api_key
  header_name: Authorization
  secret_name: okta_token
schedule: every 15 minutes
''', "ok", lambda s: (_one(s).request.base_url == "https://acme.okta.com/api/v1/users" and s[0].request.headers == {"Accept": "application/json"}
                      and s[0].auth.header == "Authorization" and s[0].auth.value == "${secret:okta_token}" and s[0].schedule.seconds == 900)),

    ("schedule as seconds number", '''id: sched-num
name: Sched
request: {base_url: https://api.github.com, path: /users}
schedule: 300
''', "ok", lambda s: _one(s).schedule.seconds == 300),

    ("schedule as interval_seconds", '''id: sched-secs
name: Sched
request: {base_url: https://api.github.com, path: /users}
schedule: {interval_seconds: 3600}
''', "ok", lambda s: _one(s).schedule.seconds == 3600),

    ("schedule hourly word", '''id: sched-word
name: Sched
request: {base_url: https://api.github.com, path: /users}
schedule: hourly
''', "ok", lambda s: _one(s).schedule.seconds == 3600),

    ("cron schedule", '''id: sched-cron
name: Sched
request: {base_url: https://api.github.com, path: /users}
schedule: {cron: "*/5 * * * *"}
''', "reject:cron", None),

    # --- paging ------------------------------------------------------------------------------
    ("cursor pagination words", '''id: cursor-ai
name: Cursor
entity: event
request: {base_url: https://api.example.com, path: /v1/alerts}
pagination:
  style: cursor
  cursor_param: after
  cursor_path: meta.next_cursor
  limit_param: limit
  limit: 200
''', "ok", lambda s: (_one(s).pagination.type == "next_token" and s[0].pagination.token_param == "after"
                      and s[0].pagination.token_path == "meta.next_cursor" and s[0].pagination.page_size_param == "limit"
                      and s[0].pagination.page_size == 200)),

    ("pagination as a single word", '''id: pg-word
name: Pg
request: {base_url: https://api.github.com, path: /users}
pagination: link
''', "ok", lambda s: _one(s).pagination.type == "link_header"),

    ("page based paging", '''id: pg-page
name: Pg
request: {base_url: https://api.example.com, path: /v1/users}
pagination: {type: page, page_param: page, per_page_param: per_page, per_page: 50}
''', "ok", lambda s: (_one(s).pagination.type == "page_number" and s[0].pagination.page_size_param == "per_page"
                      and s[0].pagination.page_size == 50)),

    ("offset limit paging with total", '''id: pg-offset
name: Pg
request: {base_url: https://api.example.com, path: /v1/hosts}
pagination: {type: offset_limit, offset_param: offset, limit_param: limit, page_size: "100", total_field: meta.total}
''', "ok", lambda s: (_one(s).pagination.type == "offset" and s[0].pagination.total_path == "meta.total"
                      and s[0].pagination.page_size == 100)),

    ("next link paging", '''id: pg-next
name: Pg
request: {base_url: https://example.atlassian.net, path: /wiki/api/v2/spaces}
pagination: {type: next_link, next_url_path: _links.next}
''', "ok", lambda s: _one(s).pagination.type == "next_url" and s[0].pagination.token_path == "_links.next"),

    # --- JSONPath and mapping shapes ---------------------------------------------------------
    ("jsonpath records and mapping", '''id: jsonpath-ai
name: JSONPath
entity: user
request: {base_url: https://api.example.com, path: /v1/users}
records: $.data.items[*]
mapping:
  id: $.id
  name: $.profile.displayName
  email: $['profile']['email']
''', "ok", lambda s: (_one(s).records == "data.items" and s[0].mapping["id"].from_ == "id"
                      and s[0].mapping["name"].from_ == "profile.displayName"
                      and s[0].mapping["email"].from_ == "profile.email")),

    ("mapping as a list of source target", '''id: maplist-ai
name: Map list
entity: device
request: {base_url: https://api.example.com, path: /v1/devices}
data_path: results
field_mappings:
  - source: device_id
    target: id
  - source: host.name
    target: hostname
  - {source: last_contact, target: last_seen, type: timestamp}
''', "ok", lambda s: (_one(s).records == "results" and s[0].mapping["hostname"].from_ == "host.name"
                      and s[0].mapping["last_seen"].type == "datetime")),

    ("mapping values as field objects", '''id: mapobj-ai
name: Map objects
entity: event
request: {base_url: https://api.example.com, path: /v1/alerts}
mapping:
  id: {field: alert_id, type: string}
  type: {field: category}
  timestamp: {path: created_at, type: datetime, format: "YYYY-MM-DD HH:mm:ss"}
  score: {source: risk, type: number}
  dst_port: {field: port, type: integer}
''', "ok", lambda s: (_one(s).mapping["id"].from_ == "alert_id" and s[0].mapping["id"].type == "str"
                      and s[0].mapping["timestamp"].format == "%Y-%m-%d %H:%M:%S" and s[0].mapping["score"].type == "float"
                      and s[0].mapping["dst_port"].type == "int")),

    ("mapping target to source the other way round", '''id: mapinv-ai
name: Map inverted
entity: user
request: {base_url: https://api.example.com, path: /v1/users}
mapping:
  userId: id
  displayName: name
  mail: email
''', "ok", lambda s: (_one(s).mapping["id"].from_ == "userId" and s[0].mapping["name"].from_ == "displayName"
                      and s[0].mapping["email"].from_ == "mail")),

    ("unknown target field", '''id: badtarget
name: Bad
entity: user
request: {base_url: https://api.example.com, path: /v1/users}
mapping: {id: id, name: login, favourite_colour: colour}
''', "reject:favourite_colour", None),

    # --- secrets -----------------------------------------------------------------------------
    ("env style secret", '''id: gh-env
name: GitHub
request: {base_url: https://api.github.com, path: /users}
auth: {type: bearer, token: "${GITHUB_TOKEN}"}
''', "ok", lambda s: _one(s).auth.token == "${secret:github_token}"),

    ("github actions style secret", '''id: gh-actions
name: GitHub
request: {base_url: https://api.github.com, path: /users}
auth:
  type: bearer
  token: "{{ secrets.GITHUB_TOKEN }}"
''', "ok", lambda s: _one(s).auth.token == "${secret:github_token}"),

    ("secret given as a full reference", '''id: gh-ref
name: GitHub
request: {base_url: https://api.github.com, path: /users}
auth: {type: bearer, secret: "${secret:github_token}"}
''', "ok", lambda s: _one(s).auth.token == "${secret:github_token}"),

    ("credential pasted in plain text", '''id: gh-leak
name: GitHub
request: {base_url: https://api.github.com, path: /users}
auth: {type: bearer, token: ghp_16C7e42F292c6912E7710c838347Ae178B4a}
''', "reject:plain text", None),

    ("api key pasted in a header", '''id: header-leak
name: Leak
request:
  base_url: https://api.example.com
  path: /v1/users
  headers: {X-API-Key: 9f8e7d6c5b4a39281706f5e4d3c2b1a0}
''', "reject:credential", None),

    ("auth header with a reference is fine", '''id: header-ref
name: Header ref
request:
  base_url: https://api.example.com
  path: /v1/users
  headers: {Authorization: "Bearer ${secret:example_token}"}
''', "ok", lambda s: _one(s).secret_names == ["example_token"]),

    # --- auth shapes -------------------------------------------------------------------------
    ("oauth2 the way an AI writes it", '''id: oauth-ai
name: OAuth
entity: device
request: {base_url: https://api.example.com, path: /v1/hosts}
auth:
  type: oauth2
  grant_type: client_credentials
  token_endpoint: https://api.example.com/oauth2/token
  client_id: abc123
  client_secret: ${secret:example_client_secret}
  scopes: [read:hosts, read:alerts]
''', "ok", lambda s: (_one(s).auth.type == "oauth2_client_credentials" and s[0].auth.token_url.endswith("/oauth2/token")
                      and s[0].auth.client_secret == "${secret:example_client_secret}" and s[0].auth.scope == "read:hosts read:alerts")),

    ("crowdstrike config pasted earlier", '''id: crowdstrike-falcon-source
name: "CrowdStrike Falcon Security Logs"
entity: device
schedule:
  every: "5m"
auth:
  type: oauth2_client_credentials
  token_url: "https://api.crowdstrike.com/oauth2/token"
  client_id_env_var: "CROWDSTRIKE_CLIENT_ID"
  client_secret_env_var: "CROWDSTRIKE_CLIENT_SECRET"
  header: Authorization
request:
  base_url: "https://api.crowdstrike.com"
  path: /devices/combined/devices/v1
  params: {limit: 100}
pagination:
  type: offset_or_cursor
  cursor_param: offset
  page_size_param: limit
  page_size: 100
records: resources
''', "ok", lambda s: (_one(s).auth.client_id == "${env:CROWDSTRIKE_CLIENT_ID}"
                      and s[0].auth.client_secret == "${secret:crowdstrike_client_secret}" and s[0].pagination.type == "next_token")),

    ("basic auth with password reference", '''id: jira-ai
name: Jira
entity: user
request: {base_url: https://acme.atlassian.net, path: /rest/api/3/users/search}
auth: {type: basic_auth, username: me@acme.com, password: "${JIRA_API_TOKEN}"}
''', "ok", lambda s: _one(s).auth.type == "basic" and s[0].auth.password == "${secret:jira_api_token}"),

    ("api key in the query string", '''id: key-query
name: Query key
request: {base_url: https://api.example.com, path: /v1/feed}
auth: {type: apikey, location: query, query_param: api_key, secret: example_key}
''', "ok", lambda s: _one(s).auth.in_ == "query" and s[0].auth.param == "api_key"),

    ("no auth written as none", '''id: auth-none
name: None
request: {base_url: https://api.first.org, path: /data/v1/epss}
auth: none
''', "ok", lambda s: _one(s).auth.type == "none"),

    # --- whole-file shapes -------------------------------------------------------------------
    ("endpoints as a dictionary", '''id: vendor-ai
name: Vendor
base_url: https://api.example.com
auth: {type: bearer, secret: vendor_token}
endpoints:
  alerts:
    endpoint: /v1/alerts
    method: get
    entity: alerts
  hosts:
    url: https://api.example.com/v1/hosts
    entity: devices
''', "ok", lambda s: ([x.id for x in s] == ["vendor-ai.alerts", "vendor-ai.hosts"] and s[0].entity == "event"
                      and s[1].request.path == "/v1/hosts" and s[1].entity == "device")),

    ("no id and an awkward name", '''name: "CrowdStrike Falcon (Hosts) v2!"
request: {base_url: https://api.crowdstrike.com, path: /devices/combined/devices/v1}
''', "ok", lambda s: _one(s).id == "crowdstrike-falcon-hosts-v2"),

    ("invalid id gets cleaned", '''id: My Source_ID
name: Mine
request: {base_url: https://api.github.com, path: /users}
''', "ok", lambda s: _one(s).id == "my-source_id"),

    ("metadata an AI likes to add", '''id: meta-ai
name: Meta
version: "1.0.0"
author: ChatGPT
tags: [security, siem]
metadata: {owner: soc-team}
logging: {level: INFO, file: ./logs/sync.log}
swaggerhub_logging: {enabled: true}
request: {base_url: https://api.github.com, path: /users}
''', "ok", lambda s: _one(s).id == "meta-ai"),

    ("rate limits and retries in other words", '''id: limits-ai
name: Limits
request: {base_url: https://api.github.com, path: /users, timeout: 30}
rate_limit: {requests_per_minute: 120}
retries: {max_retries: 3, backoff: exponential, initial_delay: 2}
''', "ok", lambda s: (_one(s).rate_limit.requests_per_second == 2 and s[0].retry.max_attempts == 4
                      and s[0].retry.base_delay_seconds == 2 and s[0].request.timeout_seconds == 30)),

    ("query string inside the path", '''id: qs-path
name: QS
request: {base_url: "https://api.example.com/", path: "v1/alerts?status=open&limit=50"}
''', "ok", lambda s: _one(s).request.path == "/v1/alerts" and s[0].request.params == {"status": "open", "limit": "50"}),

    ("swaggerhub config pasted earlier", '''# ConnectForge Core Engine
id: my-source
name: "My source"
entity: user
schedule:
  every: "15m"
auth:
  type: api_key
  secret: my_api_key
  header: X-API-Key
request:
  base_url: "https://api.example.com"
  path: /api/v1/users
pagination:
  type: link_header
  page_size_param: limit
  page_size: 100
mapping:

swaggerhub_logging:
  enabled: true
  owner: "Some Institute"
  log_level: "INFO"
''', "ok", lambda s: _one(s).mapping is None),

    ("a typo that is not an alias", '''id: typo
name: Typo
request: {base_url: https://api.github.com, path: /users}
schedual: {every: 1h}
''', "reject:did you mean 'schedule'", None),

    ("duplicate keys", '''id: dupes
name: Dupes
request: {base_url: https://api.github.com, path: /users}
auth: {type: none}
auth: {type: bearer, secret: x}
''', "reject:appears twice", None),

    # --- hostile input -----------------------------------------------------------------------
    ("yaml bomb", '''a: &a ["x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g]
''', "reject:alias", None),

    ("python object tag", '''id: evil
name: !!python/object/apply:os.system ["echo pwned"]
request: {base_url: https://api.github.com, path: /users}
''', "reject:YAML", None),

    ("huge file", "id: huge\nname: Huge\nrequest: {base_url: https://api.github.com, path: /users}\n# " + "x" * 600_000 + "\n",
     "reject:too large", None),

    ("not a config at all", "Sorry, I can't help with that request.", "reject:connector", None),
]


# --- held-out sets: written without looking at the rules, scored blind, then kept as regression tests ----
_HELD_OUT_1 = [
 ("auth method header + mustache", "id: h1x\nname: H1\nrequest: {base_url: https://api.x.io, path: /v1/a}\nauth: {method: header, header: X-Key, value: '{{API_KEY}}'}\n", "ok"),
 ("API Key with key_name/key_value", "id: h2x\nname: H2\nrequest: {base_url: https://api.x.io, path: /v1/a}\nauth: {type: API Key, key_name: x-apikey, key_value: '${API_KEY}'}\n", "ok"),
 ("endpoint_url + http_verb + query_string", "id: h3x\nname: H3\nrequest: {endpoint_url: https://api.x.io/v1/a, http_verb: get, query_string: {a: 1}}\n", "ok"),
 ("every 10min", "id: h4x\nname: H4\nrequest: {base_url: https://api.x.io, path: /a}\nschedule: {every: 10min}\n", "ok"),
 ("cron as string", "id: h5x\nname: H5\nrequest: {base_url: https://api.x.io, path: /a}\nschedule: '*/10 * * * *'\n", "reject"),
 ("cursor jsonpath keys", "id: h6x\nname: H6\nrequest: {base_url: https://api.x.io, path: /a}\npagination: {type: cursor, next_cursor_jsonpath: $.next, cursor_query_param: cursor}\n", "ok"),
 ("response block with records_path", "id: h7x\nname: H7\nrequest: {base_url: https://api.x.io, path: /a}\nresponse: {records_path: $.items, format: json}\n", "ok"),
 ("camelCase jsonPath dataType", "id: h8x\nname: H8\nentity: event\nrequest: {base_url: https://api.x.io, path: /a}\nmapping:\n  id: {jsonPath: $.uid, dataType: string}\n  type: {jsonPath: $.kind}\n  timestamp: {jsonPath: $.ts, dataType: timestamp}\n", "ok"),
 ("connector wrapper", "connector:\n  id: h9x\n  name: H9\n  request: {base_url: https://api.x.io, path: /a}\n", "ok"),
 ("integration wrapper with endpoints", "integration:\n  name: H10\n  base_url: https://api.x.io\n  endpoints:\n    - {name: a, path: /a, response_path: data}\n", "ok"),
 ("bearer with prefix Token", "id: h11\nname: H11\nrequest: {base_url: https://api.x.io, path: /a}\nauth: {type: bearer, header: Authorization, prefix: Token, secret: x_token}\n", "ok"),
 ("oauth client_id env style", "id: h12\nname: H12\nrequest: {base_url: https://api.x.io, path: /a}\nauth: {type: oauth2, token_url: https://api.x.io/token, client_id: '${CLIENT_ID}', client_secret: '${CLIENT_SECRET}'}\n", "ok"),
 ("entity vulnerabilities", "id: h13\nname: H13\nentity: vulnerabilities\nrequest: {base_url: https://api.x.io, path: /a}\n", "ok"),
 ("retry attempts backoff_ms", "id: h14\nname: H14\nrequest: {base_url: https://api.x.io, path: /a}\nretry: {attempts: 3, backoff_ms: 500}\n", "ok"),
 ("headers as name/value list", "id: h15\nname: H15\nrequest:\n  base_url: https://api.x.io\n  path: /a\n  headers:\n    - {name: Accept, value: application/json}\n", "ok"),
 ("params as key/value list", "id: h16\nname: H16\nrequest:\n  base_url: https://api.x.io\n  path: /a\n  params:\n    - {key: status, value: open}\n", "ok"),
 ("source as a block", "id: h17\nname: H17\nsource:\n  url: https://api.x.io/v1/a\n  auth: {type: none}\n", "ok"),
 ("token pasted under a nice name", "id: h18\nname: H18\nrequest: {base_url: https://api.x.io, path: /a}\nauth: {type: bearer, token: 'xoxb-1234567890-abcdefghij'}\n", "reject"),
]

_HELD_OUT_2 = [
 ("postman url object", "id: p1x\nname: P1\nrequest:\n  method: GET\n  url: {raw: 'https://api.x.io/v1/a?x=1', host: [api, x, io]}\n", "ok",
  lambda s: s[0].request.base_url.startswith("https://api.x.io") and s[0].request.params.get("x") == "1"),
 ("openapi snippet", "id: p2x\nname: P2\nservers: [{url: 'https://api.x.io'}]\npaths:\n  /v1/alerts:\n    get: {summary: list}\n", "ok",
  lambda s: s[0].request.base_url == "https://api.x.io" and s[0].request.path == "/v1/alerts"),
 ("auth type as key bearer", "id: p3x\nname: P3\nrequest: {base_url: https://api.x.io, path: /a}\nauth:\n  bearer: {token: '${TOKEN}'}\n", "ok",
  lambda s: s[0].auth.type == "bearer" and s[0].auth.token == "${secret:token}"),
 ("auth type as key api_key", "id: p4x\nname: P4\nrequest: {base_url: https://api.x.io, path: /a}\nauth:\n  api_key: {header: X-Key, value: '${KEY}'}\n", "ok",
  lambda s: s[0].auth.type == "api_key" and s[0].auth.header == "X-Key"),
 ("auth type as key basic", "id: p5x\nname: P5\nrequest: {base_url: https://api.x.io, path: /a}\nauth:\n  basic: {username: u, password: '${PW}'}\n", "ok",
  lambda s: s[0].auth.type == "basic" and s[0].auth.password == "${secret:pw}"),
 ("next_page jsonpath", "id: p6x\nname: P6\nrequest: {base_url: https://api.x.io, path: /a}\npagination: {next_page: $.links.next}\n", "ok",
  lambda s: s[0].pagination.type == "next_url" and s[0].pagination.token_path == "links.next"),
 ("1 hr", "id: p7x\nname: P7\nrequest: {base_url: https://api.x.io, path: /a}\nschedule: {every: 1 hr}\n", "ok", lambda s: s[0].schedule.seconds == 3600),
 ("1.5 hours", "id: p8x\nname: P8\nrequest: {base_url: https://api.x.io, path: /a}\nschedule: 1.5 hours\n", "ok", lambda s: s[0].schedule.seconds == 5400),
 ("jinja item paths", "id: p9x\nname: P9\nentity: user\nrequest: {base_url: https://api.x.io, path: /a}\nmapping: {id: '{{ item.id }}', name: '{{ item.profile.name }}'}\n", "ok",
  lambda s: s[0].mapping["name"].from_ == "profile.name"),
 ("transform lowercase", "id: p10\nname: P10\nentity: user\nrequest: {base_url: https://api.x.io, path: /a}\nmapping:\n  id: id\n  name: login\n  status: {from: state, transform: lowercase}\n", "ok",
  lambda s: s[0].mapping["status"].lower is True),
 ("entity Alerts capitalised", "id: p11\nname: P11\nentity: Alerts\nrequest: {base_url: https://api.x.io, path: /a}\n", "ok", lambda s: s[0].entity == "event"),
 ("jq style records", "id: p12\nname: P12\nrequest: {base_url: https://api.x.io, path: /a}\nrecords: .data.items[]\n", "ok", lambda s: s[0].records == "data.items"),
 ("mustache in auth header", "id: p13\nname: P13\nrequest:\n  base_url: https://api.x.io\n  path: /a\n  headers: {Authorization: 'Bearer {{API_TOKEN}}'}\n", "ok",
  lambda s: s[0].request.headers["Authorization"] == "Bearer ${secret:api_token}"),
 ("nested request in endpoint", "id: p14\nname: P14\nbase_url: https://api.x.io\nendpoints:\n  - name: a\n    request: {path: /v1/a, method: post, body: {q: 1}}\n", "ok",
  lambda s: s[0].request.path == "/v1/a" and s[0].request.method == "POST" and s[0].request.body == {"q": 1}),
 ("numeric id", "id: 123\nname: Numeric\nrequest: {base_url: https://api.x.io, path: /a}\n", "ok", lambda s: s[0].id.startswith("src-123") or s[0].id == "numeric"),
 ("legit yaml anchors", "id: p16\nname: P16\nbase_url: https://api.x.io\nmap: &m {id: uid, type: kind, timestamp: ts}\nendpoints:\n  - {name: a, path: /a, entity: event, mapping: *m}\n  - {name: b, path: /b, entity: event, mapping: *m}\n", "ok",
  lambda s: s[1].mapping["id"].from_ == "uid"),
 ("aws key in a constant", "id: p17\nname: P17\nentity: event\nrequest: {base_url: https://api.x.io, path: /a}\nmapping: {id: id, type: {const: AKIAIOSFODNN7EXAMPLE}, timestamp: ts}\n", "reject", None),
 ("bad url scheme", "id: p18\nname: P18\nrequest: {base_url: 'ftp://files.x.io', path: /a}\n", "reject", None),
]

_REJECT_WORDS = {'cron as string': 'cron', 'token pasted under a nice name': 'plain text', 'aws key in a constant': 'real-looking token', 'bad url scheme': 'http'}
CASES += [(n, t, "ok" if e == "ok" else f"reject:{_REJECT_WORDS[n]}", None) for n, t, e in _HELD_OUT_1]
CASES += [(n, t, "ok" if e == "ok" else f"reject:{_REJECT_WORDS[n]}", c) for n, t, e, c in _HELD_OUT_2]


# --- configs that were also run against the real APIs (GitHub, CISA, EPSS, NVD) and mapped real data ----
_LIVE = {'github': 'Here\'s a config to pull GitHub security advisories and your repos into ConnectForge:\n\n```yaml\nconnector:\n  name: GitHub (AI generated)\n  baseUrl: https://api.github.com\n  authentication:\n    bearer:\n      token: "{{ secrets.GITHUB_TOKEN }}"\n  headers:\n    - {name: Accept, value: application/vnd.github+json}\n  paging: {style: link, perPage: 30, perPageParam: per_page, maxPages: 1}\n  pollInterval: 2 hours\n  endpoints:\n    advisories:\n      url: https://api.github.com/advisories?type=reviewed\n      entity: vulnerabilities\n    my_repos:\n      endpoint: /user/repos\n      entity: repositories\n```\n', 'cisa': '{"source": {"url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "auth": {"type": "none"}},\n "name": "CISA KEV (AI)", "entity_type": "alerts", "frequency": "daily",\n "response": {"records_path": "$.vulnerabilities[*]"},\n "field_mappings": [{"source": "$.cveID", "target": "id"}, {"source": "$.vulnerabilityName", "target": "type"},\n                    {"source": "$.dateAdded", "target": "timestamp", "type": "date", "format": "YYYY-MM-DD"},\n                    {"source": "$.shortDescription", "target": "description"}, {"source": "$.cveID", "target": "cve"}]}\n', 'epss': 'id: EPSS Feed\napi_url: https://api.first.org/data/v1/epss?epss-gt=0.95\ntype: rest_api\ninterval_seconds: 86400\npagination:\n  strategy: offset_limit\n  offsetParameter: offset\n  limitParameter: limit\n  pageSize: 50\n  totalCountPath: $.total\n  max_pages: 2\nrecords: .data[]\nentity: Alerts\n', 'nvd': 'openapi: "3.0.0"\nservers: [{url: "https://services.nvd.nist.gov"}]\npaths:\n  /rest/json/cves/2.0:\n    get: {summary: CVE list}\nname: NVD (AI)\nentity: findings\nquery: {resultsPerPage: 20, noRejected: ""}\nrecords: $.vulnerabilities[*]\nmapping:\n  id: {jsonPath: $.cve.id, dataType: string}\n  type: {const: cve}\n  timestamp: {jsonPath: $.cve.published, dataType: timestamp}\n  description: "{{ item.cve.descriptions[0].value }}"\n'}
CASES += [
    ("live: github wrapped integration", _LIVE["github"], "ok",
     lambda s: [x.id for x in s] == ["github-ai-generated.advisories", "github-ai-generated.my_repos"]
     and s[0].request.params == {"type": "reviewed"} and s[0].entity == "event" and s[1].entity == "record"
     and s[0].auth.token == "${secret:github_token}" and s[0].schedule.seconds == 7200),
    ("live: cisa json with source block", _LIVE["cisa"], "ok",
     lambda s: s[0].records == "vulnerabilities" and s[0].mapping["timestamp"].format == "%Y-%m-%d"
     and s[0].schedule.seconds == 86400 and (s[0].request.base_url + s[0].request.path).endswith("known_exploited_vulnerabilities.json")),
    ("live: epss camelCase paging", _LIVE["epss"], "ok",
     lambda s: s[0].id == "epss-feed" and s[0].records == "data" and s[0].pagination.type == "offset"
     and s[0].pagination.total_path == "total" and s[0].request.params == {"epss-gt": "0.95"}),
    ("live: nvd openapi snippet", _LIVE["nvd"], "ok",
     lambda s: s[0].request.path == "/rest/json/cves/2.0" and s[0].mapping["description"].from_ == "cve.descriptions[0].value"),
]
