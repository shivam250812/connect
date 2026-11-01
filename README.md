# ConnectForge

**Config-driven security integration platform** · CyberForge 2026, Problem 05

Connecting a new data source (a firewall, an EDR, an identity provider, a cloud console) is a YAML file, not new
code. The platform does the rest the same way for every source: logs in, pages, retries, respects rate limits,
maps records into one common schema, quarantines bad data, keeps secrets safe, shows health, and tells people on
Slack or email when something needs them.

![Dashboard](docs/health.png)

## Quick start

```bash
./run.sh                 # installs on first run, then serves http://127.0.0.1:8100
CF_LAB=1 ./run.sh        # also starts mock vendor APIs on :9100 for failure drills
```

Open the page, **create an account** (email notifications go to registered addresses), then add secrets on the
**Secrets** tab and connectors with **Add connector** (form, YAML, file upload, or a template).

Requires Python 3.10+. `make help` lists the development tasks.

## What is connected

12 live integrations in [`integrations/connectors/`](integrations/connectors/), 31 endpoints, verified against the
real APIs (2 are switched off until the account has the needed plan or permission: Atlassian audit log, CrowdStrike
host groups):

| Integration | Endpoints | Login | Paging |
|---|---|---|---|
| CISA | Known Exploited Vulnerabilities | none | none |
| FIRST EPSS | likely-exploited CVEs | none | offset |
| NIST NVD | CVEs, CVE change history | optional API key | offset + incremental |
| GitHub | advisories, users, repositories | bearer token | Link header |
| AbuseIPDB | blacklist, IP check, abuse reports | API key | page number |
| Atlassian | users, audit log, Jira issues, projects, Confluence spaces | basic (email + token) | offset, token, next link |
| Cloudflare | audit logs, members, zones | bearer token | page number + incremental |
| CrowdStrike Falcon | hosts, alerts, host groups | OAuth2 client credentials | token |
| Elastic Security | detection alerts, users | API key | offset in body + incremental |
| Google Cloud | audit logs, IAM changes, errors | service-account JWT | page token |
| Okta | users, system log, groups | SSWS token | Link header + incremental |
| Sophos Central | endpoints, alerts | OAuth2 + region discovery | page key |

Templates: [`integrations/examples/`](integrations/examples/) (11 ready-to-fill files for free or trial APIs) and
[`integrations/catalog/`](integrations/catalog/) (51 enterprise vendor templates: SIEM, EDR, DLP, firewall, cloud).
Catalog templates are written from vendor API documentation and validated against lab imitations, not run against
real tenants: use **Test connection** and **Preview** on yours first.

## Writing a connector

One file describes an integration: the login and base URL once, then every endpoint to pull.

```yaml
id: github
name: GitHub
auth: {type: bearer, secret: github_token}         # the secret's name; its value lives in the vault
request: {base_url: https://api.github.com}
pagination: {type: link_header, page_size_param: per_page, page_size: 50}
endpoints:
  - name: advisories
    entity: event                                   # user | device | event | record
    path: /advisories
    schedule: {every: 15m}
    mapping:                                        # optional: left out, it is learned from real data
      id: ghsa_id
      severity: {from: severity, lower: true}
      timestamp: published_at
      description: summary
  - {name: users, entity: user, path: /users}
  - {name: repos, entity: record, path: /user/repos}
```

* **Login:** `none`, `api_key` (header or query), `bearer` (any scheme), `basic`, `oauth2_client_credentials`
  (with discovery, audience, body credentials), `aws_sigv4`, `token_exchange`, `google_service_account`,
  `cortex_advanced`.
* **Paging:** `link_header`, `next_url`, `next_token`, `page_number`, `offset`, `none`. If the next page's location
  is not given, the engine finds it in the response.
* **Mapping:** nested paths (`a.b[0].c`), `template`, `const`, `map`, `regex`, `parse_json`, dates and epochs,
  type casts. Leave `mapping` out and fields are matched automatically and checked against real values; Preview
  shows the result to pin or adjust.
* **Files written by an AI assistant** are accepted as they come (chat text, JSON, JSONPath, other key names,
  `${TOKEN}`-style secrets...). **Validate** lists every automatic fix and offers the corrected YAML; anything
  ambiguous is refused with a reason. A real credential in a file is always refused.
* `connectforge upgrade FILE...` turns older single-endpoint files into this format.

## Requirement map

| ID | Requirement | How |
|---|---|---|
| FR-1 | Auth: API key + one more | 9 login types (above); the PRD syntax `auth: {type: api_key, header: X-API-Key, secret: okta_key}` works as written |
| FR-2 | Endpoints | path, method, params, headers, body; several endpoints per file sharing one login |
| FR-3 | ≥ 2 paging styles | 6 styles, nested body paths, `has_more_path`, automatic next-page discovery |
| FR-4 | Schedule | per integration and per endpoint (`30s`, `15m`, `1d`); resumes across restarts without re-running everything |
| FR-5 | Mapping | direct mapping (rename, nested, dates, casts) and automatic mapping |
| FR-6 | Safe secrets | Fernet-encrypted vault or HashiCorp Vault / AWS Secrets Manager; files hold names only; write-only; scoped per connector; audited; redacted from errors |
| FR-7 | Retries | 1 s, 2 s, 4 s, then failed; 401/403 fail fast with the provider's message |
| FR-8 | Rate limits | token bucket per connector; `Retry-After` / `X-Rate-Limit-Reset` on 429 |
| FR-9 | Bad data | each bad record quarantined with its exact reason; the run continues |
| FR-10 | Health view | status, last run, pulled / new / updated / rejected, retries, next run, checkpoint, last error; a Data tab per endpoint |
| FR-11 | One store | `users`, `devices`, `events` (+ `records` for anything else), keyed by `(source, id)`; every row keeps `source` and `fetched_at` |
| B-1 | Incremental sync | `cursor:` checkpoint saved only after a successful run |
| B-2 | Validate config | strict schema, "did you mean" hints, automatic fixes for AI-written files |
| B-3 | Test connection | one authenticated request, nothing stored |
| B-4 | Alerts | Slack + email: failing / recovered, credential rejected, bad-data spike, new critical findings, key due for rotation |
| B-5 | Web form | builds a multi-endpoint integration and generates the YAML |

Common schema: **users** (id, name, email, status, last_login, title, department, mfa_enabled), **devices**
(id, hostname, ip, os, owner, last_seen, mac, status), **events** (id, type, severity, timestamp, description,
user, src_ip, dst_ip, dst_port, action, outcome, cve, product, url, country, score).

## Secrets and key rotation

Secrets are referenced by name. To rotate: create a new key at the vendor, paste it on the **Secrets** tab (or
`connectforge set-secret NAME`), check with **Test connection**, revoke the old key. Sessions made from the old key
are dropped at once; keys older than 90 days trigger a reminder.

| `CF_SECRETS_BACKEND` | Where `github_token` is read | Settings |
|---|---|---|
| `local` (default) | encrypted `data/vault.json` | none |
| `hashicorp` | KV v2 `secret/data/<prefix>github_token`, field `value` | `VAULT_ADDR`, `VAULT_TOKEN`, `CF_VAULT_MOUNT`, `CF_VAULT_FIELD`, `VAULT_NAMESPACE` |
| `aws` | Secrets Manager `<prefix>github_token` | `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` |
| `env` | `CF_SECRET_GITHUB_TOKEN` | none |

With an external manager, rotate there and click **Reload** (or wait for `CF_SECRETS_CACHE_SECONDS`, default 300);
a 401 also re-reads the secret and retries once.

## Notifications

**Notifications** sends to a Slack incoming webhook (Teams and Mattermost work too) and/or email over SMTP, to every
registered account plus optional extra addresses. Each rule can be switched off, repeats are held back for the
cooldown (60 minutes by default), and a connection's first run is a baseline rather than news. The webhook URL and
SMTP password are secrets (`slack_webhook`, `smtp_password`).

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `CF_HOST`, `CF_PORT` | `127.0.0.1`, `8100` | where `run.sh` serves the app |
| `CF_DATA_DIR` | `data` | database, vault and master key |
| `CF_CONNECTORS_DIRS` | `integrations/connectors` | colon-separated connector folders; the first one receives UI saves |
| `CF_LAB` | off | `1` adds the mock lab sources and their connectors |
| `CF_SIGNUP` | `open` | `closed` stops new accounts once your team has signed up |
| `CF_ADMIN_TOKEN` | unset | lets scripts call the API with an `X-Admin-Token` header |
| `CF_MASTER_KEY` | file in `data/` | vault encryption key (use a KMS-provided value in production) |
| `CF_SYSLOG_PORT`, `CF_SYSLOG_HOST` | `5514` (run.sh), `127.0.0.1` | UDP syslog/CEF receiver for push-only devices |
| `CF_SMTP_HOST`, `CF_SMTP_PORT`, `CF_SMTP_USER`, `CF_SMTP_FROM`, `CF_ALERT_EMAIL_TO` | unset | email settings from the environment |
| `CF_ALERT_WEBHOOK` | unset | Slack-compatible webhook URL from the environment |

## Failure drills (PRD "testing failures")

| Drill | Do this | You see |
|---|---|---|
| Wrong key | save a bad value for a secret, **Run now** | HTTP 401 at once, the provider's message, a "credential rejected" notice, no key in logs |
| Network off | turn Wi-Fi off, **Run now** | retries 1 s / 2 s / 4 s, then failed; after 3 runs "failing" + notice; recovers by itself |
| 429 | `CF_LAB=1`, run **Okta users (lab)** | "HTTP 429 → retry in 1s (Retry-After)" |
| Missing fields | any lab source | the Quarantine tab shows each bad record and its reason |
| Outage | `curl -X POST localhost:9100/mock/chaos -d '{"source":"edr","mode":"outage"}' -H 'content-type: application/json'` | retries, then failing, notice, recovery |
| Poisoned next link | same with `{"source":"okta","mode":"evil_link"}` | blocked before sending; credentials never leave; `egress.blocked` in the audit log |

## Development

```bash
make install    # .venv + ConnectForge with dev tools
make test       # 197 tests, no network
make lint       # ruff: style, bugs, security rules
make stress     # 85 AI-written configs: rewritten correctly or refused for the right reason
make fuzz       # 20,000 randomly damaged config files: no crashes
```

Code layout and data flow: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). CI runs lint, tests and the AI corpus on
every push ([.github/workflows/ci.yml](.github/workflows/ci.yml)). A container image builds from the
[Dockerfile](Dockerfile) (data in the `/app/data` volume).

## Security notes

* Everything behind a login: scrypt password hashes, HttpOnly SameSite=Strict session cookies (only their hash
  stored), lockout after 5 wrong passwords.
* Calls only go to hosts a connector declares (egress allowlist, wildcards supported); redirects are never followed
  with credentials; one connector's cookies never reach another.
* Config intake refuses YAML bombs, `!!python` tags, duplicate keys and files over 256 KB; XML with DOCTYPE/ENTITY is
  refused.
* `data/`, `.env`, keys and certificates are ignored by git.

## Disclosure

Runtime: FastAPI, Uvicorn, httpx, Pydantic, PyYAML, cryptography. Tests: pytest, pytest-asyncio, botocore (only to
cross-check SigV4). Live data comes from the vendors listed above; lab data is synthetic (RFC 5737 addresses,
`.example` domains). Built with AI coding assistance.
