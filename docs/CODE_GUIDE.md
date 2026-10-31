# ConnectForge: complete code guide

This guide explains every part of ConnectForge: what each file and function does, how they fit together, and why it is built that way. Every heading links to the exact line, so you can read the guide and the code side by side.

**Contents**

1. [The mental model](#1-the-mental-model)
2. [Folder map](#2-folder-map)
3. [Startup: what happens when you run `./run.sh`](#3-startup)
4. [`spec.py`: the config language](#4-specpy--the-config-language)
5. [`mapping.py`: turning any record into the common schema](#5-mappingpy--turning-any-record-into-the-common-schema)
6. [`auth.py`: logging in to every kind of API](#6-authpy--logging-in-to-every-kind-of-api)
7. [`vault.py`: secrets](#7-vaultpy--secrets)
8. [`store.py`: the database](#8-storepy--the-database)
9. [`runtime.py`: the engine](#9-runtimepy--the-engine)
10. [`syslog.py`: receiving pushed logs](#10-syslogpy--receiving-pushed-logs)
11. [`server.py`: the HTTP API](#11-serverpy--the-http-api)
12. [`cli.py`: terminal commands](#12-clipy--terminal-commands)
13. [`static/`: the health page](#13-static--the-health-page)
14. [`mock/`: the lab](#14-mock--the-lab)
15. [The YAML folders, with one config explained line by line](#15-the-yaml-folders)
16. [`tests/`](#16-tests)
17. [Every login flow as a diagram](#17-every-login-flow-as-a-diagram)
18. [Glossary](#18-glossary)
19. [Known limitations](#19-known-limitations)

---

## 1. The mental model

```
                ┌──────────────── a connector = one YAML file ────────────────┐
                │ how to log in · which URL · how to page · how often ·        │
                │ how to translate fields into users / devices / events        │
                └───────────────────────────────┬──────────────────────────────┘
                                                │ validated by spec.py
                                                ▼
 scheduler ──► run() ──► vault (secret) ──► auth (login / token / signature)
                │                                   │
                │                      egress allowlist + rate limit + retries
                │                                   ▼
                │                          fetch_pages (pagination)
                │                                   ▼
                │                      mapping (convert / validate each record)
                │                         │                        │
                │                   bad record                 good record
                │                         ▼                        ▼
                │                    quarantine          upsert into users/devices/events
                ▼
        checkpoint + run metrics + health status + alerts ──► health page
```

**The one rule behind the whole design:** the YAML only *describes* a source; the platform *does* everything. There is no `if vendor == ...` anywhere in the engine. Every connector, from CISA's public feed to Prisma Cloud's token login, goes through the same functions. That is why they all "behave the same way when things go wrong", which is the PRD's goal.

## 2. Folder map

| Path | What it is |
|---|---|
| [`connectforge/`](../connectforge/) | The platform (Python package) |
| [`connectforge/static/`](../connectforge/static/) | The health page (HTML/CSS/JS) |
| [`connectforge/mock/`](../connectforge/mock/) | Lab servers that imitate vendor APIs, including their failures |
| [`connectors/`](../connectors/) | Connectors that run by default: the real APIs, plus anything you saved from the UI |
| [`catalog/`](../catalog/) | 37 vendor templates: SIEM, EDR, DLP, firewall, cloud |
| [`examples/`](../examples/) | Ready-to-fill configs (Okta, Jira, AbuseIPDB, Cloudflare, EPSS, GitHub users) |
| [`lab/`](../lab/) and [`lab/enterprise/`](../lab/enterprise/) | Connectors that run against the mock, for the failure drills and to prove each feature |
| [`tests/`](../tests/) | 62 automated tests, no network |
| `data/` *(not in git)* | Runtime state: encrypted vault, master key, SQLite database, feed files |

## 3. Startup

**[`run.sh`](../run.sh)**:

1. It creates `.venv` if it doesn't exist and installs the pinned [`requirements.txt`](../requirements.txt).
2. `cli seed-demo` stores the **lab** credentials in the vault. These are the mock's fake keys; your real tokens are never touched.
3. It sets `CF_SYSLOG_PORT=5514`, which turns the UDP syslog receiver on, and `MOCK_SYSLOG_TARGET_PORT`, so the lab firewalls send syslog to it.
4. It starts the mock on `:9100` in the background. `trap … EXIT` kills the mock when you stop the script, so nothing is left running.
5. It starts the platform on `:8100`.

**[`server.lifespan()`](../connectforge/server.py#L33)** runs once when the platform starts:

1. `platform.load_dir(...)` loads every YAML from `connectors/`, `lab/` and `lab/enterprise/`.
2. `platform.start()` starts the scheduler loop. Tests turn this off with `CF_SCHEDULER=0`.
3. If `CF_SYSLOG_PORT` is set, it starts the syslog receiver.
4. On shutdown, it closes the receiver and calls `platform.stop()`, which cancels the runs and closes the HTTP client.

---

## 4. `spec.py`: the config language

[spec.py](../connectforge/spec.py) defines **everything a YAML connector is allowed to say**, and rejects anything wrong *before it runs*.

### The common schema: [`ENTITY_FIELDS`, `REQUIRED`, `TABLES`](../connectforge/spec.py#L18)

```python
ENTITY_FIELDS = {"user":   {"id": "str", "name": "str", "email": "str", "status": "str", "last_login": "datetime", ...},
                 "device": {"id": "str", "hostname": "str", "ip": "ip", "os": "str", "owner": "str", "last_seen": "datetime", ...},
                 "event":  {"id": "str", "type": "str", "severity": "str", "timestamp": "datetime", "description": "str", ...}}
REQUIRED = {"user": ["id", "name"], "device": ["id", "hostname"], "event": ["id", "type", "timestamp"]}
```

These come straight from the PRD's §4 minimum schema. The extra fields (`src_ip`, `cve`, `score`, …) are optional security context.

Four other parts of the code read from this one dictionary:

* validation, which rejects unknown fields;
* mapping, which converts values to the right type;
* `store.py`, which builds the SQL tables from it;
* the web form, which fills its field dropdowns from it.

Change it in one place and all four follow, so they can never disagree.

### [`parse_duration()`](../connectforge/spec.py#L37)

Turns `"30s"`, `"15m"`, `"2h"` or `"1d"` into seconds. The PRD says "every 15 minutes", and people write `15m`.

### [`_Strict`](../connectforge/spec.py#L46)

```python
model_config = ConfigDict(extra="forbid", populate_by_name=True)
```

* `extra="forbid"` means an unknown key (a typo like `paginaton:`) is an **error**, not something silently ignored.
* `populate_by_name=True` lets YAML say `from:` and `in:`, which are reserved words in Python, while the code uses `from_` and `in_`.

### [`LoginSpec`](../connectforge/spec.py#L50) and [`DiscoverSpec`](../connectforge/spec.py#L66)

These describe enterprise login flows.

**`LoginSpec`** is "call this URL first to get a token". It holds:

* `url` and `method`;
* what to send: `json`, `form`, `headers`, or basic auth;
* where the token comes back: `token_from` = body, header or cookie, and `token_path`;
* how long it lasts: `expires_in_path` or `ttl_seconds`.

**`DiscoverSpec`** is "after logging in, ask the API where my data lives". It holds:

* `url`;
* `base_url_path`, the JSON path of the real host in the response;
* `headers`, extra headers built from the response, e.g. `X-Tenant-ID: id`.

### [`AuthSpec`](../connectforge/spec.py#L73)

It covers nine login types: `none`, `api_key`, `bearer`, `basic`, `oauth2_client_credentials`, `aws_sigv4`, `token_exchange`, `google_service_account` and `cortex_advanced`.

[`_expand_secret()`](../connectforge/spec.py#L102) makes the PRD shorthand `secret: name` work. It moves `${secret:name}` into the slot each type uses:

| Type | Slot |
|---|---|
| `api_key` | `value` |
| `bearer` | `token` |
| `basic` | `password` |
| OAuth2 | `client_secret` |
| Google | `value` (the JSON key) |
| Cortex | `value` |

It then checks each type is complete, e.g. "token_exchange needs a `login:` block", or "basic needs username + secret".

Other options:

* `optional: true` means "call without a key if none is stored" (NVD).
* `client_auth: body` and `extra: {audience: …}` cover OAuth variants (Wiz, Sophos, CrowdStrike).

### [`RequestSpec`](../connectforge/spec.py#L137)

`base_url`, `path`, `method`, `params`, `headers`, `body`, `timeout_seconds`, and `response_format: json|xml`.

### [`PaginationSpec`](../connectforge/spec.py#L148)

The `type` is one of `none`, `link_header`, `next_url`, `next_token`, `page_number` or `offset`. The other fields:

* `token_path` / `token_param` / `token_in`: where the next-page token is read from, and where it is sent;
* `page_param`, `page_size_param`, `page_size`, `start_page`, `offset_param`;
* `offset_end_param`: some APIs want a range (Cortex `search_from`/`search_to`);
* `params_in: body`: page values go into the JSON body, and **may be nested paths** like `request_data.search_from`;
* `total_path`: stop when `offset >= total`;
* `has_more_path`: stop when this flag is false (GraphQL `hasNextPage`);
* `max_pages`: a safety cap so a buggy API can never loop forever.

### [`CursorSpec`](../connectforge/spec.py#L165): incremental sync (B-1)

* `field`: where each record's timestamp is.
* `param` / `in`: where the checkpoint is sent.
* `end_param`: for APIs that need a window end, set to "now" (NVD, AWS).
* `template`: for search-filter syntax, e.g. CrowdStrike FQL.
* `initial`: how far back the very first run starts, e.g. `-23h` for Sophos's 24-hour limit.
* `format`: `iso_z`, `iso`, `date`, `epoch` or `epoch_ms`.

### The smaller specs

* [`ScheduleSpec`](../connectforge/spec.py#L176): `every`.
* [`RetrySpec`](../connectforge/spec.py#L191): the defaults are **4 attempts, base 1 s, no jitter**, which gives exactly the PRD's "1 s, 2 s, 4 s, then mark as failed".
* [`RateLimitSpec`](../connectforge/spec.py#L200): requests per second and burst size.
* [`FileSpec`](../connectforge/spec.py#L205):
  * `path`;
  * `format` = `kv`, `regex`, `csv`, `jsonl` or `cef`;
  * `filter`: a regex that picks *this vendor's* lines out of a shared syslog file;
  * `pattern`, `columns`, `delimiter`, `max_bytes_per_run`.

### [`FieldMap`](../connectforge/spec.py#L215)

One mapping rule. Its value comes from **exactly one** of `from`, `const` or `template` (the `_one_source` check enforces this). Then these optional steps run in order:

`parse_json` → `path` → `regex` → `lower` → `map` (lookup table) → `type` → `default`.

### [`ConnectorSpec`](../connectforge/spec.py#L236)

The whole connector.

[`_shorthand`](../connectforge/spec.py#L258) runs *before* validation. It turns `email: profile.login` into `{from: profile.login}`, the PRD's syntax.

[`_consistency`](../connectforge/spec.py#L265) holds the checks that involve several fields:

1. Every mapped field exists for this entity, otherwise the error lists the allowed fields.
2. Every required field is mapped.
3. `kind: http` needs a `request` block; `kind: file` needs a `file` block.
4. **Every URL's host** (base, OAuth token, login, discovery) is allowed.
5. **No literal credentials:** `token/value/password/client_secret/secret_access_key` must be `${secret:…}` references. Inside login bodies and headers, any key that looks like a password, secret, API key, token or Lacework's `UAKS` must also be a reference.

[`secret_names`](../connectforge/spec.py#L307) scans the whole config for `${secret:x}` (and `${zscaler_key:x}`). **This list is the connector's permission:** the vault will only hand out these names to this connector. It's derived automatically, so you never declare secrets twice.

[`egress_hosts()`](../connectforge/spec.py#L312) and [`host_allowed()`](../connectforge/spec.py#L321) form the allowlist. If you don't set one, it is the hosts of your own URLs. Wildcards like `*.central.sophos.com` allow region hosts. `host_allowed("x.central.sophos.com.evil.io")` is **false**, because a wildcard only matches the end of the name.

[`parse_spec()`](../connectforge/spec.py#L334) uses `yaml.safe_load`; the unsafe loader can construct Python objects from YAML. It turns the validation errors into readable, numbered messages.

---

## 5. `mapping.py`: turning any record into the common schema

[mapping.py](../connectforge/mapping.py)

* **[`get_path(obj, "a.b[0].c")`](../connectforge/mapping.py#L26)** reads a nested value. It understands `name`, `[0]` and `['key.with.dots']` (Elastic's `_source['kibana.alert.severity']`). It returns `None` for anything missing and **never raises**, because real API data is full of missing fields.
* **[`set_path(body, "request_data.filters[0].value", v)`](../connectforge/mapping.py#L40)** is the reverse. It *writes* a value at a nested path, creating dicts and lists as needed. This is what lets paging and cursor values go deep inside request bodies: GraphQL `variables.after`, Cortex `request_data.search_from`, AWS `Filters.UpdatedAt[0].Start`.
* **[`xml_to_dict()`](../connectforge/mapping.py#L63)** turns an XML response into dicts:
  * attributes become `@name`;
  * repeated tags become a list;
  * text becomes a value (or `#text` when the element also has attributes or children).

  **Security:** it refuses any document containing `<!DOCTYPE` or `<!ENTITY`. That blocks XXE and "billion laughs" attacks, where a tiny XML file expands to gigabytes.
* **[`parse_cef()`](../connectforge/mapping.py#L94)** parses ArcSight's Common Event Format, `CEF:0|Vendor|Product|Version|SigID|Name|Severity|k=v k=v`:
  * the 7 header fields are split on **unescaped** `|`, since `\|` is a literal pipe;
  * the extension pairs are parsed so values may contain spaces (`msg=blocked by rule 12`) and escaped `\=`;
  * anything before `CEF:` (the syslog prefix) is kept as `syslog_prefix`.
* **[`parse_datetime()`](../connectforge/mapping.py#L122)** accepts:
  * epoch seconds or milliseconds (anything above 1e11 is treated as ms);
  * ISO with `Z`;
  * date only;
  * custom formats (`format:`); for syslog's year-less dates the current year is filled in.

  Times without a timezone are treated as UTC.
* **[`_cast()`](../connectforge/mapping.py#L141)** converts to the schema type:
  * `ip` uses Python's `ipaddress` module, which really validates (`10.0.1.999` fails);
  * `bool` accepts true/yes/1/active;
  * `str` turns objects into JSON text.
* **[`map_field()`](../connectforge/mapping.py#L157)** runs one FieldMap's pipeline in its fixed order. `template` fills `{path}` placeholders from the record.
* **[`map_record()`](../connectforge/mapping.py#L186)** maps every field and casts its type.
  * The **first failure returns a reason string** instead of raising, e.g. `"src_ip: '10.0.1.999' does not appear to be an IPv4 or IPv6 address"`. The caller quarantines the record and carries on (FR-9).
  * It checks required fields, then adds `source`.
  * `fetched_at` is added by the store, because only the store knows when the write happens.
* **[`preview()`](../connectforge/mapping.py#L208)** runs the same function on a few records, for the dry run. So the preview can never disagree with a real run.

---

## 6. `auth.py`: logging in to every kind of API

[auth.py](../connectforge/auth.py)

### Secret resolution: [`make_resolver()`](../connectforge/auth.py#L40)

It replaces `${secret:name}` (from the vault) and `${env:NAME}` (from environment variables). It runs **at the moment of the request**, so the real value only ever exists briefly in memory. It is never stored in the config, in the connector object, or in logs.

### [`sigv4_headers()`](../connectforge/auth.py#L57): AWS request signing

AWS doesn't accept a plain key; each request must be signed:

1. **Canonical request:** method, URL path, sorted query string, sorted signed headers, and the SHA-256 of the body.
2. **String to sign:** algorithm, timestamp, scope (`date/region/service/aws4_request`) and the hash of step 1.
3. **Signing key:** an HMAC chain, date → region → service → `aws4_request`, starting from `"AWS4" + secret`.
4. **Signature:** an HMAC of step 2 with that key, placed in the `Authorization` header.

A test checks it against AWS's own botocore library **byte for byte**.

### Vendor helpers: tiny and isolated

* **[`zscaler_obfuscated_key()`](../connectforge/auth.py#L89):** Zscaler requires the API key scrambled using the login timestamp:
  * take the last 6 digits of the millisecond timestamp ("high") and pick those character positions from the key;
  * then take `high >> 1`, zero-padded to 6 digits ("low"), and pick positions `digit + 2`.

  A test uses a vector worked out by hand.
* **[`cortex_advanced_headers()`](../connectforge/auth.py#L96):** Palo Alto "advanced" keys. Each request sends a fresh random nonce, a timestamp, the key ID, and `Authorization = sha256(key + nonce + timestamp)`. The key itself never travels, and a captured request can't be replayed later.
* **[`google_jwt_assertion()`](../connectforge/auth.py#L105):** builds a JWT (claims: issuer = service account email, scope, audience = token URL, issued-at, expiry +1 h), signs it with the service account's RSA private key (RS256), and returns it with the token URL.

### [`Authenticator`](../connectforge/auth.py#L124)

There's one per connector, and it lives across runs, so cached tokens survive between runs.

* **[`__init__`](../connectforge/auth.py#L129)** receives the auth spec, the resolver, `host_allowed` (the connector's allowlist) and `client_factory` (makes a throw-away HTTP client for login calls).
* **[`invalidate()`](../connectforge/auth.py#L142)** drops the cached token and the discovery result. The engine calls it on a 401, then retries once.
* **[`_check()`](../connectforge/auth.py#L149)** checks login, token and discovery URLs against the allowlist too. Credentials can't be sent to a host the config didn't approve, even during login.
* **[`_resolve_tree()`](../connectforge/auth.py#L153)** fills the placeholders in login bodies and headers: `${now_ms}`, `${zscaler_key:x}`, `${secret:x}` and `${env:X}`. It computes the timestamp **once**, so the obfuscated key and the `timestamp` field agree.
* **[`_cached()`](../connectforge/auth.py#L165)** reuses the token until 30 seconds before it expires, then fetches a new one.
* **[`_oauth()`](../connectforge/auth.py#L172)** sends a client-credentials request:
  * `client_auth: basic` sends the ID and secret as HTTP basic auth;
  * `client_auth: body` sends them as form fields;
  * `extra` adds fields like `audience=wiz-api`.
* **[`_google()`](../connectforge/auth.py#L191)** sends the signed JWT to the token URL and gets an access token.
* **[`_login()`](../connectforge/auth.py#L202)** is the token exchange. It sends JSON, form, headers or basic auth as configured, then takes the token from the **body** (a JSON path), a **response header** (Cisco FMC) or a **cookie** (Zscaler). It returns the token and how long it lasts.
* **[`_discover()`](../connectforge/auth.py#L233)** calls the discovery URL (e.g. Sophos `whoami`), reads the real API host, **checks it against the allowlist**, and builds extra headers such as `X-Tenant-ID`.
* **[`credential_headers()`](../connectforge/auth.py#L248)** gives the header for token-based types:
  * `Authorization: Bearer …`;
  * a custom header, e.g. `x-redlock-auth: <token>` with no prefix;
  * `Cookie: JSESSIONID=…`.
* **[`prepare()`](../connectforge/auth.py#L263)** runs discovery before the first request, if configured.
* **[`apply()`](../connectforge/auth.py#L268)** / **[`_apply()`](../connectforge/auth.py#L276)** attach the credential to one request according to the type. If a secret is missing and `optional: true`, the request is sent without a credential.

**Why logins use a separate, throw-away client:** login responses often set cookies. If they landed in the shared client, they could be sent along with *another* connector's requests to the same domain. A fresh client per login keeps every session isolated.

---

## 7. `vault.py`: secrets

[vault.py](../connectforge/vault.py)

* **[`_load_or_create_key()`](../connectforge/vault.py#L45):** the master key comes from `CF_MASTER_KEY`, or in development from `data/master.key` with permissions 0600 (only you can read it). The key is kept apart from `vault.json`, so a copied vault file is useless on its own.
* **[`_save()`](../connectforge/vault.py#L56):** writes to a temporary file, then renames it. A crash halfway through writing can't corrupt the vault.
* **[`put()`](../connectforge/vault.py#L64):** trims whitespace from pasted tokens, encrypts with **Fernet** (AES plus an HMAC tamper check), and records the created and rotated times.
* **[`get(name, connector, declared)`](../connectforge/vault.py#L88):**
  1. If `name` isn't in this connector's declared list, it raises `SecretAccessDenied` and logs `secret.denied`.
  2. Otherwise it decrypts, records the last use, and logs `secret.read`.
* **[`metadata()`](../connectforge/vault.py#L105):** returns names, status, which connectors use each secret, its age, last use and whether rotation is due. **Never the value.** That is what makes the page's Secrets tab write-only.
* **[`redact()`](../connectforge/vault.py#L124):** replaces any stored secret value found in a text with `[REDACTED:name]`. Every saved error and retry note passes through it.

---

## 8. `store.py`: the database

[store.py](../connectforge/store.py), SQLite in WAL mode (readers don't block writers).

* **[`_entity_ddl()`](../connectforge/store.py#L42)** builds `CREATE TABLE users / devices / events` **from `ENTITY_FIELDS`**, with `PRIMARY KEY (source, id)` plus `fetched_at`, `connector` and `digest` columns.
* **State tables:**
  * `cursors`: one checkpoint per connector;
  * `runs`: every run's numbers;
  * `quarantine`: bad records with their reason. A unique fingerprint stops the same bad record being stored again on every run;
  * `alerts`;
  * `audit`.
* **[`upsert()`](../connectforge/store.py#L71)**: for each row it computes a digest of the content and looks up `(source, id)`:
  * same digest → **unchanged** (only `fetched_at` is refreshed);
  * different digest → **updated**;
  * not found → **new**.

  It returns the three counts the cards display.
* **[`records()`](../connectforge/store.py#L99)** serves the Users, Devices and Events tabs, with a source filter and text search. All values are bound parameters, so no SQL injection is possible.
* The other methods are small getters and setters for checkpoints, runs, quarantine, alerts and audit.

---

## 9. `runtime.py`: the engine

[runtime.py](../connectforge/runtime.py)

### Rate limiting: [`TokenBucket`](../connectforge/runtime.py#L48)

The bucket holds up to `burst` tokens and refills at `rate` per second. Each request takes one; if none are left, it waits exactly long enough for one to refill.

* An `asyncio.Lock` stops two requests from racing for the same token.
* The `sleep` function is **injected**, so tests can record waits instead of sleeping.

### [`retry_after_seconds()`](../connectforge/runtime.py#L69)

Reads `Retry-After` (seconds or an HTTP date) or `X-Rate-Limit-Reset` (an epoch time). This is how "wait 30 s when the API says so" works.

### [`RunMetrics`](../connectforge/runtime.py#L86)

The counters for one run: pages, fetched, new, updated, unchanged, rejected, retries, throttled_ms, plus a list of notes.

### [`Fetcher.request()`](../connectforge/runtime.py#L122): one request, done safely

```
prepare auth (login/discovery, cached)          ─┐
rewrite base URL to the discovered region host   │ once per run (then cached)
egress check on the final URL ──────────────────┘ → blocked = error, credential never attached
for attempt 1..max_attempts:
    wait for a rate-limit token
    resolve ${secret:} in query params + static headers
    build request, attach credential
    send WITHOUT following redirects; clear cookies afterwards
    timeout / network error      → retryable
    401 + refreshable token      → invalidate, retry immediately (once)
    408 / 429 / 5xx              → retryable; use Retry-After if given
    3xx                          → error (credentials never follow redirects)
    401 / 403                    → error now, with kind + provider's message
    other 4xx                    → error now with body excerpt
    2xx                          → return
    wait: Retry-After, or backoff 1 s · 2 s · 4 s (optional jitter), add a note
raise "failed after N attempts: <last problem>"
```

Test connection calls this with `max_attempts=1`, so the real error isn't hidden behind retries.

### [`format_cursor()`](../connectforge/runtime.py#L175) / [`initial_cursor()`](../connectforge/runtime.py#L190)

Format the checkpoint the way each API wants it (`iso_z`, epoch, date, or wrapped in a template), and compute the first run's start, e.g. `-23h` means 23 hours ago.

### [`fetch_pages()`](../connectforge/runtime.py#L198): pagination

An async generator that yields one page of records at a time, so memory stays small.

1. Build the URL. **Deep-copy** the configured body, so the spec itself is never changed.
2. [`put(where, key, value)`](../connectforge/runtime.py#L207) writes into the query string, or into the body with `set_path`, which allows nested paths.
3. Insert the checkpoint and `end_param`; set the first page, offset or offset-end.
4. Loop up to `max_pages`:
   1. request;
   2. parse the response as JSON, or with `xml_to_dict`;
   3. find the records list via `records:`;
   4. **yield** the page;
   5. `has_more_path` false → stop;
   6. work out the next page:
      * Link header or next URL → follow it (the egress check still applies);
      * `next_token` → write the token where configured, which may be nested;
      * page number → next page; stop on a short page;
      * offset → add the record count; stop at the total or on a short page; update the range end.
5. If `max_pages` is hit, add a note; the rest is fetched next run.

### File sources: [`parse_line()`](../connectforge/runtime.py#L274), [`read_new_lines()`](../connectforge/runtime.py#L296)

* **Formats:** `cef` uses `parse_cef`; `jsonl` is one JSON object per line; `kv` is key=value with quoted values; `regex` uses named groups; `csv` checks the column count.
* **Reading:**
  * seek to the byte offset and read at most `max_bytes`;
  * **cut at the last newline**, so a half-written line waits for the next run;
  * if the file is now smaller than the offset, it was rotated, so start from 0.

### [`ConnectorState`](../connectforge/runtime.py#L312)

Per-connector live state: the spec, its rate-limit bucket, its Authenticator (which keeps cached tokens), paused/running flags, the failure count, the next run time, the last run, notes, whether an alert has been sent, and the source file path.

### [`Platform`](../connectforge/runtime.py#L327)

* [`_make_state()`](../connectforge/runtime.py#L347) wires in the vault resolver, **limited to `spec.secret_names`**, the allowlist and the throw-away login client factory.
* [`load_dir()`](../connectforge/runtime.py#L355) loads every YAML; a broken file goes into `load_errors` and the others still load.
* [`add()`](../connectforge/runtime.py#L369) saves and registers a connector live, with no restart (UI save, upload or form).
* [`remove()`](../connectforge/runtime.py#L382) stops a connector and **moves** its YAML to `data/removed/`. Stored records are kept.
* [`_resolve_file()`](../connectforge/runtime.py#L404) is the file sandbox: only paths inside `data/feeds` are allowed.
* [`_ingest()`](../connectforge/runtime.py#L415) maps records, quarantines failures and upserts the good ones.
* [`_run_http()`](../connectforge/runtime.py#L431) loads the checkpoint, iterates over pages, tracks the newest timestamp among **accepted** records, and **saves the checkpoint only after every page succeeded**.
* [`_run_file()`](../connectforge/runtime.py#L451) reads new lines, applies `file.filter` (other vendors' lines are skipped, not errors), parses, ingests, and saves the byte offset.
* [`run()`](../connectforge/runtime.py#L473) is the full lifecycle:
  1. Skip if already running.
  2. Start a run record, take a concurrency slot, and run.
  3. **A catch-all handler**: one connector's bug can never crash the platform.
  4. Afterwards: redact the error, save the metrics, update health.
     * success → reset the failure count, plus a "recovered" alert if one was outstanding;
     * failure → count it, and at **3 in a row** send **one** alert.
  5. Schedule the next run.
* [`next_delay()`](../connectforge/runtime.py#L513) is the circuit breaker: after 3 or more failures, it waits `every × 2^n`, up to 1 hour, while still probing.
* [`_alert()`](../connectforge/runtime.py#L530) posts `{"text": …}` to a Slack/Teams webhook (`CF_ALERT_WEBHOOK` or the `alert_webhook` secret). It always records the alert, so it works even without Slack.
* [`test_connection()`](../connectforge/runtime.py#L551) makes one request with no retries and stores nothing. For file connectors it checks the file is readable.
* [`preview()`](../connectforge/runtime.py#L574) shows one page (or the last few lines) as raw versus mapped. Nothing is stored.
* [`_tick()`](../connectforge/runtime.py#L596) / [`_loop()`](../connectforge/runtime.py#L605) form the scheduler: every second, start any connector that's due. Setting `next_run = now + 3600` immediately prevents a double start; `run()` then sets the real next time.
* [`health()`](../connectforge/runtime.py#L623) decides the status:
  * disabled or paused;
  * pending or running;
  * failing (3 or more failures);
  * degraded (last run failed, or more than 20% of records rejected);
  * healthy.

  It returns everything the card shows.

---

## 10. `syslog.py`: receiving pushed logs

[syslog.py](../connectforge/syslog.py)

* A UDP listener ([`_SyslogProtocol.datagram_received`](../connectforge/syslog.py#L22)) receives each syslog message, replaces newlines, caps it at 8 KB, and **appends it as one line** to `data/feeds/syslog.log`. At 50 MB the file is rotated, and the tailing connectors detect the rotation.
* [`start_syslog()`](../connectforge/syslog.py#L33) binds to **127.0.0.1 by default**. To accept real devices on the network you must opt in with `CF_SYSLOG_HOST=0.0.0.0`.
* **Why a file in the middle:** the receiver stays tiny; connectors get checkpoints and replay for free; and many vendors can share one port, each picking its own lines with `file.filter`.

---

## 11. `server.py`: the HTTP API

[server.py](../connectforge/server.py), built with FastAPI. Its automatic docs are at `/docs`.

| Endpoint | What it does |
|---|---|
| `GET /api/overview` | Everything the dashboard needs: cards (real APIs first, then lab), table counts, totals |
| `GET /api/connectors/{id}` | Details: health, config, last 25 runs, quarantined records |
| `GET /api/schema` | The common schema, used by the web form |
| `POST /api/connectors/validate` | B-2: returns errors, or a summary (table, login, paging, schedule, fields, secrets, hosts) |
| `POST /api/connectors` | Save and start (no restart) |
| `DELETE /api/connectors/{id}` | Remove and archive the YAML |
| `POST /api/connectors/{id}/run` · `/pause` · `/resume` · `/reset-cursor` | Operator actions, each audited |
| `POST /api/test` | B-3: test a saved id or unsaved YAML |
| `POST /api/preview` | Dry run |
| `GET /api/records/{users,devices,events}` (+ `.jsonl`) | FR-11 data. The table name is checked against a fixed list before it goes near SQL |
| `GET /api/quarantine`, `/api/alerts`, `/api/audit` | Logs |
| `GET /api/secrets` · `PUT /api/secrets/{name}` | Metadata only · write-only |
| `GET /api/examples` | Feeds "Load example…" from `examples/`, `catalog/`, `lab/` and `connectors/` |
| `GET /static/{name}` | Static files, with a path-traversal guard (`../` blocked) |

[`admin()`](../connectforge/server.py#L53): if `CF_ADMIN_TOKEN` is set, every endpoint that changes something needs the `X-Admin-Token` header.

---

## 12. `cli.py`: terminal commands

[cli.py](../connectforge/cli.py)

* **`seed-demo`:** stores the lab credentials, including the enterprise lab ones. Your real secret names are never touched.
* **`set-secret NAME`:** prompts with `getpass`, so the value isn't echoed and doesn't land in shell history.
* **`validate FILES…`:** lints configs and exits non-zero on failure, so it can gate a CI pipeline.
* **`test ID|FILE`:** B-3 from the terminal.

---

## 13. `static/`: the health page

* **[index.html](../connectforge/static/index.html)** holds the layout:
  * top bar with 🔒 Secrets and + Add source;
  * summary tiles and the connection cards;
  * tabs: Users, Devices, Events, Quarantined, Alerts, Secrets, Audit;
  * the details drawer;
  * the Add-source window (Web form / YAML, Upload .yaml, Load example).
* **[app.js](../connectforge/static/app.js)**:
  * `esc()`: **every** value from a source is HTML-escaped. API data is untrusted, so this stops script injection (XSS) in the analyst's browser.
  * `api()`: a fetch wrapper that adds the admin token if set and turns errors into readable messages.
  * `refresh()`, every 3 s: `renderSummary()` and `renderGrid()` draw the cards (real-API or lab badge, metrics, last run, next run, checkpoint, error, retry notes, and Run / Test / Pause / Details / Remove buttons).
  * `renderTab()`: the three tables (source filter, search, JSONL export) and the log tabs.
  * Secrets tab inputs use `autocomplete="new-password"` so the browser doesn't autofill them, values are trimmed, and pasting the page's own address is refused.
  * `openDetail()`: run history, quarantine, config and a live mapping preview.
  * **The web form (B-5):** `renderForm()` builds fields from `/api/schema`; `generateYaml()` and `toYaml()` produce the YAML for you to review. YAML stays the one source of truth.
  * Upload `.yaml`: reads the file in the browser (200 KB cap) and validates it automatically.
  * **One delegated click handler** for the whole page: cards re-render every 3 s, so per-button listeners would keep disappearing.
* **[styles.css](../connectforge/static/styles.css):** dark theme, consistent status colours, and works on narrow screens.

---

## 14. `mock/`: the lab

**Why it exists:** real APIs won't fail on demand, and the PRD wants you to *show* 429s, outages and bad records. It also lets every enterprise login pattern be proven without vendor accounts. All of its data is synthetic: documentation-only IP addresses and `.example` domains.

* **[sources.py](../connectforge/mock/sources.py):**
  * **Okta-style users:** `SSWS` auth, a **429 on every 3rd call**, Link paging, some broken records;
  * **EDR devices:** API key, offset paging with a total, a bad IP;
  * **CloudTrail:** **actually verifies SigV4** with the same function as the client, plus 503s and truncated records;
  * a **FortiGate log writer**;
  * `/mock/chaos`, to switch on an outage or the poisoned next link live.
* **[enterprise.py](../connectforge/mock/enterprise.py):** one small imitation per enterprise pattern:
  * Prisma (JSON login → token → header);
  * FMC (basic login → **header** token);
  * ZIA (**obfuscated key** → cookie);
  * Sophos (OAuth → **whoami discovery** → region + tenant header, cursor + `has_more`);
  * Wiz (OAuth with `audience` → **GraphQL nested cursor**);
  * Google (**verifies the RS256 JWT signature**);
  * Cortex (**verifies the hash headers**, offsets inside `request_data`);
  * an XML firewall (XML plus one bad record);
  * a **syslog sender** emitting Check Point CEF and Juniper RT_FLOW lines to UDP 5514.

  The lab Google key is stored in `data/lab/` so that the mock process and the vault agree after restarts.

---

## 15. The YAML folders

The folders are described in [section 2](#2-folder-map). Here is one real config read line by line: [catalog/edr/sophos_intercept_x.yaml](../catalog/edr/sophos_intercept_x.yaml).

```yaml
id: sophos-central-alerts           # unique id; also the card name and run history key
name: Sophos Central alerts          # display name
source: sophos                       # written into every row's `source` column
entity: event                        # lands in the events table → mapping must provide id, type, timestamp
schedule: {every: 5m}                # scheduler runs it every 5 minutes
allowed_hosts: [id.sophos.com, api.central.sophos.com, "*.central.sophos.com"]
                                     # the ONLY hosts that may ever receive this connector's credentials;
                                     # the wildcard admits the region host discovered at runtime
auth:
  type: oauth2_client_credentials    # exchange client id + secret for a short-lived token (cached)
  token_url: https://id.sophos.com/api/v2/oauth2/token
  client_id: YOUR_CLIENT_ID          # not secret → lives in the file
  secret: sophos_client_secret       # name of the vault entry; the value never appears in config/logs
  client_auth: body                  # Sophos wants id/secret as form fields, not basic auth
  scope: token
  discover:                          # after login, ask "where is my data?"
    url: https://api.central.sophos.com/whoami/v1
    base_url_path: apiHosts.dataRegion   # e.g. https://api-eu01.central.sophos.com → all requests go there
    headers: {X-Tenant-ID: id}           # and carry the tenant id from the same response
request: {base_url: "https://api.central.sophos.com", path: /siem/v1/alerts}
                                     # base gets swapped for the discovered region host at runtime
pagination: {type: next_token, token_path: next_cursor, token_param: cursor, has_more_path: has_more,
             page_size_param: limit, page_size: 1000}
                                     # send ?cursor=<next_cursor>; stop when has_more is false
cursor: {field: when, param: from_date, format: epoch, initial: -23h}
                                     # incremental: send the newest `when` seen as ?from_date=<epoch>;
                                     # first run 23 h back (Sophos rejects > 24 h)
records: items                       # the list of alerts is at response.items
mapping:                             # raw Sophos alert → common event
  id: id
  type: type
  severity: severity
  timestamp: when
  description: description
  product: location
```

---

## 16. `tests/`

62 tests, about 1.5 s, no network. The mock runs in the same process through httpx's in-memory transport.

| File | Proves |
|---|---|
| [test_spec_and_mapping.py](../tests/test_spec_and_mapping.py) | The PRD's example config works as written; the real sources differ in login and paging; every shipped YAML validates; 7 kinds of bad config give clear errors; mapping and date handling |
| [test_security.py](../tests/test_security.py) | The vault encrypts, scopes, audits and redacts; a wrong master key fails cleanly; `${env:}` works; `data/` is gitignored; **SigV4 matches botocore** |
| [test_runtime.py](../tests/test_runtime.py) | 429 → Retry-After; **exact 1/2/4 s backoff**; network down; wrong key fails fast; alert after 3 failures, then recovery; poisoned link blocked; test connection stores nothing; file tail and rotation; config-only new source; remove and re-upload; file sandbox |
| [test_enterprise.py](../tests/test_enterprise.py) | All 7 enterprise login patterns end to end; token cached then re-login after expiry; XML plus a bad record; CEF and regex sharing one syslog file; the real UDP receiver; helper unit tests (hand-checked Zscaler vector, Cortex hash, entity attack refused); token-exchange validation; wildcard hosts; all catalog configs validate; **the AWS nested cursor lands at `Filters.UpdatedAt[0]`**; the CEF mapping on a realistic Check Point line |
| [test_api.py](../tests/test_api.py) | Dashboard data, record tables, validate/test/save, the schema endpoint, write-only secrets, the admin token, path traversal blocked |

---

## 17. Every login flow as a diagram

```
api_key / bearer / basic      request ──(header or query from vault)──► API

oauth2_client_credentials     token_url ◄─ id+secret (basic or body, + extra e.g. audience)
                              └► access_token (cached until expiry-30s) ──► API (Bearer)

token_exchange                login.url ◄─ json / form / headers / basic (secrets resolved)
                              └► token from body | response header | cookie (cached, re-login on 401)
                                 ──► API with `header: [scheme ]token`  or  Cookie: name=token

+ discover (any of the above) discover.url (authenticated) ──► base_url_path + headers
                              └► all later requests go to the discovered host (allowlist-checked)
                                 with the extra headers (e.g. X-Tenant-ID)

google_service_account        JSON key ─► signed JWT (RS256) ─► token_uri ─► access_token ─► API

cortex_advanced               every request: nonce + timestamp + key id + sha256(key+nonce+ts)

aws_sigv4                     every request signed (canonical request → string to sign → HMAC chain)
```

---

## 18. Glossary

| Term | Meaning |
|---|---|
| Connector | One YAML file describing one data source |
| Entity | Which table a connector fills: user, device or event |
| Checkpoint (cursor) | The bookmark from the last successful run, so only new data is fetched |
| Upsert | Insert if new, update if changed, leave it if identical |
| Quarantine | Where records that fail mapping go, with their reason |
| Egress allowlist | The hosts that may receive a connector's credentials |
| Token exchange | Log in first, then reuse the returned token |
| Discovery | Ask the API at runtime which host or tenant to use |
| Circuit breaker | Slow down after repeated failures, keep probing, and recover automatically |
| CEF | Common Event Format, a standard syslog payload used by many security tools |
| Lab | The local mock that imitates vendor APIs and their failures |

## 19. Known limitations

1. The 36 vendor files in `catalog/` (37 with the endpoints config) are **templates**. Their login and paging *patterns* are proven against the lab, but not against real tenants. Check each with Test connection and Dry-run preview.
2. One machine only. A second instance would run every connector twice; the fix is workers that claim connectors with a lease.
3. Two-step token chains (Forcepoint) and "list IDs, then fetch details" APIs (GuardDuty's native API) aren't supported. Forcepoint goes through syslog instead, and GuardDuty through Security Hub.
4. Times without a timezone are treated as UTC.
5. Mappings have no if/then logic, by design: configs can't run code.
6. The development master key is a local file; in production it should come from a key manager (KMS).
