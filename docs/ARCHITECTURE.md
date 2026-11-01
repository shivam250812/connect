# Architecture

ConnectForge turns a YAML file into a running integration. Everything a source needs (login, paging, retries,
rate limits, mapping, secrets, health, alerts) is done once, in the engine, for every connector.

## Data flow

```
YAML file ──► config.intake ──► config.schema ──► engine.platform (scheduler, one run per endpoint)
              read safely,      strict models,        │
              normalise AI      expand endpoints      ├─► security.auth      log in (API key, OAuth2, SigV4, JWT ...)
              spellings                               ├─► engine.http        one request: egress allowlist, rate limit,
                                                      │                      retries 1-2-4 s, Retry-After
                                                      ├─► engine.pagination  next page / checkpoint (incremental sync)
                                                      ├─► mapping            records -> common schema (written or learned)
                                                      ├─► storage.store      upsert by (source, id), quarantine, runs
                                                      └─► notifications      Slack / email when someone must act
api (FastAPI) ──► the web UI in web/static, protected by security.accounts (login, sessions)
```

## Package layout (`src/connectforge/`)

| Package | Modules | Responsibility |
|---|---|---|
| `config` | `schema.py`, `intake.py` | The config language: pydantic models and validation (`schema`), and the forgiving intake that reads hand- or AI-written files (`intake`). `parse_specs()` is the entry point. |
| `engine` | `platform.py` | `Platform`: loads connectors, schedules runs, runs them, health, test connection, preview, notices. |
| | `http.py` | `Fetcher` (one request with credentials, allowlist, retries), `TokenBucket`, `RunMetrics`. |
| | `pagination.py` | `fetch_pages()` for every paging style, checkpoints for incremental sync. |
| | `files.py`, `syslog.py` | Connectors that tail a log file; the UDP syslog/CEF receiver that writes it. |
| | `errors.py` | `FetchError`, `EgressBlocked`. |
| `mapping` | `paths.py` | Reading values: nested paths, XML (no DTD/entities), CEF, dates. |
| | `mapper.py` | Direct mapping: rename, nested, template, map, regex, type casting; bad records -> quarantine reason. |
| | `inference.py` | Automatic mapping, finding the record list, finding the next page. |
| `security` | `auth.py` | Logging in to sources (all auth types), secret resolution. |
| | `vault.py`, `secret_backends.py` | Encrypted secret store, scoping, audit, redaction; HashiCorp Vault / AWS Secrets Manager / env backends. |
| | `accounts.py` | Users of ConnectForge: sign-up, scrypt password hashes, sessions, lockout. |
| `storage` | `store.py` | SQLite: users / devices / events / records tables, runs, checkpoints, quarantine, deliveries, alerts, audit, settings. |
| `notifications` | `notifier.py` | Slack webhook and SMTP email, rules, cooldowns. |
| `api` | `app.py`, `deps.py`, `routes/*` | FastAPI app, login middleware, shared state, one router per area. |
| `lab` | `sources.py`, `enterprise.py` | Mock vendor APIs used by tests and `CF_LAB=1` failure drills. |
| `web/static` | `index.html`, `app.js`, `styles.css` | The single-page UI (no build step). |
| | `settings.py`, `cli.py` | Environment settings; the `connectforge` command. |

Dependencies point one way: `api` -> `engine` -> (`security`, `mapping`, `storage`, `notifications`) -> `config`.
`config` depends on nothing else in the package.

## Repository layout

```
integrations/connectors/   live connector files (the UI saves new ones here)
integrations/examples/     ready-to-fill templates for real free / trial APIs
integrations/catalog/      enterprise vendor templates (SIEM, EDR, DLP, firewall, cloud, production)
integrations/lab/          connectors for the mock lab sources (failure drills, tests)
tests/                     pytest suite (no network); tests/fixtures holds the AI-config corpus
scripts/                   stress_ai_configs.py (85-case AI corpus), fuzz_intake.py (mutation fuzzing)
data/                      runtime state: database, encrypted vault, master key (never committed)
```

## Design rules

* **Configuration, not code.** A new source is a YAML file. A new *kind* of login or paging is a change to the
  engine, done once for every connector.
* **Secrets are names.** Files hold `secret: github_token`; values live in the vault or an external manager, are
  scoped per connector, audited, and redacted from every error.
* **Never silently wrong.** The intake reports every fix it makes; anything ambiguous is refused with a reason.
  Bad records are quarantined with a reason; the run continues.
* **Deterministic.** Automatic mapping is rule-based and checked against real values, so the same input always
  gives the same output.
