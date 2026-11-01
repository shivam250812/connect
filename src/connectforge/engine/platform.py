"""The platform engine — identical behaviour for every connector:

  rate limit (token bucket) -> egress allowlist -> auth -> request -> retry with backoff
  (1 s, 2 s, 4 s; honours Retry-After on 429) -> pagination -> mapping -> quarantine bad
  records -> upsert into users/devices/events -> checkpoint -> health + alerts.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

from connectforge.config.schema import ConnectorSpec, SpecError, parse_specs
from connectforge.engine.errors import FetchError
from connectforge.engine.files import parse_line, read_new_lines
from connectforge.engine.http import Fetcher, RunMetrics, Sleep, TokenBucket
from connectforge.engine.pagination import fetch_pages, initial_cursor
from connectforge.mapping import (
    MappingError,
    get_path,
    infer_mapping,
    map_record,
    mapping_yaml,
    parse_datetime,
)
from connectforge.mapping import preview as map_preview
from connectforge.notifications.notifier import SEVERITY_RANK, Notifier
from connectforge.security.auth import Authenticator, AuthError, make_resolver
from connectforge.security.vault import SecretAccessDenied, SecretMissing, Vault
from connectforge.storage.store import Store, now_iso

log = logging.getLogger(__name__)
ALERT_AFTER_FAILURES = 3


# --- Platform ---------------------------------------------------------------------------------------


@dataclass
class ConnectorState:
    spec: ConnectorSpec
    bucket: TokenBucket
    auth: Authenticator
    paused: bool = False
    running: bool = False
    consecutive_failures: int = 0
    next_run: float = 0.0
    last_run: Optional[dict] = None
    last_success_at: Optional[str] = None
    last_notes: List[str] = field(default_factory=list)
    alerted: bool = False
    path: Optional[Path] = None       # the YAML file this connector came from
    learned: Optional[Dict[str, Any]] = None  # automatic mapping, when the config has none


class Platform:
    def __init__(self, connectors_dir: Path, data_dir: Path, transport: Optional[httpx.AsyncBaseTransport] = None,
                 sleep: Sleep = asyncio.sleep, file_roots: Optional[List[Path]] = None, max_concurrency: int = 8,
                 alert_transport: Optional[httpx.AsyncBaseTransport] = None):
        self.connectors_dir = Path(connectors_dir)
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.data_dir / "connectforge.db")
        self.vault = Vault(self.data_dir / "vault.json", audit=self.store.audit)
        self.vault.on_change = self.secret_changed  # e.g. `cli set-secret` while the server is running
        self.transport, self.sleep, self.alert_transport = transport, sleep, alert_transport
        self.notifier = Notifier(self.store, self.vault, transport=alert_transport)
        self._rotation_checked = 0.0
        self.file_roots = [p.resolve() for p in (file_roots or [self.data_dir / "feeds"])]
        self.states: Dict[str, ConnectorState] = {}
        self.load_errors: Dict[str, List[str]] = {}
        self._sem = asyncio.Semaphore(max_concurrency)
        self._client: Optional[httpx.AsyncClient] = None
        self._loop_task: Optional[asyncio.Task] = None
        self._auths: Dict[str, Tuple[Any, Authenticator]] = {}  # integration id -> one shared login
        self._tasks: set = set()

    # --- lifecycle -------------------------------------------------------------------------------

    def _make_state(self, spec: ConnectorSpec, share: bool = True) -> ConnectorState:
        """Endpoints of one integration file share a login, so the vendor sees one session, not one per endpoint."""
        owner = spec.integration or spec.id
        shared = self._auths.get(owner) if share and spec.integration else None
        if shared and shared[0] == spec.auth:
            auth = shared[1]
        else:
            resolve = make_resolver(lambda name: self.vault.get(name, owner, spec.secret_names))
            auth = Authenticator(spec.auth, resolve, spec.host_allowed,
                                 client_factory=lambda: httpx.AsyncClient(
                                     transport=self.transport, timeout=30, follow_redirects=False),
                                 forget_secrets=lambda: self._forget_cached(spec.secret_names))
            if share and spec.integration:
                self._auths[owner] = (spec.auth, auth)
        return ConnectorState(spec=spec, bucket=TokenBucket(spec.rate_limit.requests_per_second,
                                                            spec.rate_limit.burst, self.sleep), auth=auth)

    def _resume(self, st: ConnectorState) -> None:
        """After a restart, carry on where the connection left off: show its last run, and wait out the rest
        of its interval instead of running everything at once (which burns vendor quotas, e.g. AbuseIPDB)."""
        runs = self.store.runs(st.spec.id, 50)
        if not runs or not runs[0].get("finished_at"):
            return
        last = runs[0]
        st.last_run = {k: last.get(k) for k in ("id", "status", "error", "trigger", "finished_at", "pages", "fetched",
                                                 "new", "updated", "unchanged", "rejected", "retries", "throttled_ms")}
        ok = next((r for r in runs if r["status"] == "ok"), None)
        st.last_success_at = ok["finished_at"] if ok else None
        st.consecutive_failures = next((i for i, r in enumerate(runs) if r["status"] == "ok"), len(runs))
        st.alerted = st.consecutive_failures >= ALERT_AFTER_FAILURES   # its "failing" notice was already sent
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(last["finished_at"])).total_seconds()
        st.next_run = time.monotonic() + max(self.next_delay(st) - age, 0)

    def _files(self, extra_dirs: Optional[List[Path]] = None) -> List[Path]:
        return [p for d in [self.connectors_dir, *(extra_dirs or [])] if Path(d).exists()
                for p in sorted(Path(d).glob("*.y*ml"))]

    def _drop_from_file(self, path: Optional[Path], keep: set) -> List[str]:
        """Endpoints that were removed from a file stop running."""
        gone = [cid for cid, st in self.states.items() if path and st.path == path and cid not in keep]
        for cid in gone:
            del self.states[cid]
        return gone

    def _forget_cached(self, names: List[str]) -> bool:
        backend = self.vault.backend
        return any([backend.forget(n) for n in names]) if backend else False

    def secret_changed(self, name: str) -> List[str]:
        """A secret was rotated: drop its cached value and every login token derived from it, so the
        next request uses the new key. Returns the connectors affected."""
        if self.vault.backend:
            self.vault.backend.forget(name)
        affected = [cid for cid, st in self.states.items() if name in st.spec.secret_names]
        for cid in affected:
            self.states[cid].auth.invalidate()
        return affected

    def load_dir(self, extra_dirs: Optional[List[Path]] = None) -> None:
        """Load every connector file. New connectors from the UI are saved to the first directory."""
        self.connectors_dir.mkdir(parents=True, exist_ok=True)
        for path in self._files(extra_dirs):
            try:
                specs = parse_specs(path.read_text())
            except SpecError as e:
                self.load_errors[path.name] = e.errors
                continue
            for spec in specs:
                self.states[spec.id] = self._make_state(spec)
                self.states[spec.id].path = path
                self._resume(self.states[spec.id])

    def reload_dir(self, extra_dirs: Optional[List[Path]] = None, actor: str = "admin") -> dict:
        """Pick up YAML files edited on disk (e.g. in VS Code) without restarting.
        Changed files replace their connector; new files are added; broken files are reported, not loaded."""
        changed, added, errors, removed = [], [], {}, []
        for path in self._files(extra_dirs):
            try:
                specs = parse_specs(path.read_text())
            except SpecError as e:
                errors[path.name] = e.errors
                continue
            if any(self.states[c].running for c in self.states if self.states[c].path == path):
                errors[path.name] = ["connector is running, reload again in a moment"]
                continue
            for spec in specs:
                old = self.states.get(spec.id)
                if old and old.spec == spec:
                    continue
                if spec.integration:
                    self._auths.pop(spec.integration, None)  # login settings may have changed
                self.states[spec.id] = self._make_state(spec)
                self.states[spec.id].path = path
                (changed if old else added).append(spec.id)
                self.store.audit(actor, "connector.reloaded" if old else "connector.added", spec.id)
            removed += self._drop_from_file(path, {s.id for s in specs})
        self.load_errors = errors
        return {"changed": changed, "added": added, "removed": removed, "errors": errors}

    def yaml_text(self, cid: str) -> str:
        """The connector's YAML as written (secrets appear only as ${secret:name} references)."""
        st = self.states[cid]
        if st.path and st.path.exists():
            return st.path.read_text()
        import yaml as _yaml
        return _yaml.safe_dump(st.spec.model_dump(mode="json", by_alias=True, exclude_none=True), sort_keys=False)

    def add(self, text: str, actor: str = "admin", persist: bool = True) -> List[ConnectorSpec]:
        """Save a connector file (one connector, or one per endpoint) and start running it."""
        specs = parse_specs(text)
        file_id = specs[0].integration or specs[0].id
        olds = [st for st in self.states.values() if (st.spec.integration or st.spec.id) == file_id]
        path = None
        if persist:
            self.connectors_dir.mkdir(parents=True, exist_ok=True)
            path = next((st.path for st in olds if st.path), None) or self.connectors_dir / f"{file_id}.yaml"
            path.write_text(text)
        self._auths.pop(file_id, None)
        for st in olds:
            self.states.pop(st.spec.id, None)
        for spec in specs:
            self.states[spec.id] = self._make_state(spec)
            self.states[spec.id].path = path
            self.store.audit(actor, "connector.updated" if olds else "connector.added", spec.id)
        return specs

    def remove(self, cid: str, actor: str = "admin") -> Optional[str]:
        """Stop the connector (every endpoint of its file) and archive the YAML to data/removed/.
        Stored records are kept."""
        st = self.states.pop(cid, None)
        if st and st.spec.integration:
            for other in [c for c, s in self.states.items() if s.spec.integration == st.spec.integration]:
                del self.states[other]
            self._auths.pop(st.spec.integration, None)
        archived = None
        if st and st.path and st.path.exists():
            dest_dir = self.data_dir / "removed"
            dest_dir.mkdir(parents=True, exist_ok=True)
            dest = dest_dir / st.path.name
            if dest.exists():
                dest = dest_dir / f"{st.path.stem}-{int(time.time())}{st.path.suffix}"
            st.path.replace(dest)
            archived = str(dest)
        self.store.audit(actor, "connector.removed", f"{cid} (config archived to {archived})" if archived else cid)
        return archived

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(transport=self.transport, follow_redirects=False,
                                             headers={"User-Agent": "ConnectForge/0.2"})
        return self._client

    def _resolve_file(self, spec: ConnectorSpec) -> Path:
        path = Path(spec.file.path)
        path = (path if path.is_absolute() else Path.cwd() / path).resolve()
        if not any(path.is_relative_to(root) for root in self.file_roots):
            raise FetchError(f"file path outside permitted feed directories {[str(r) for r in self.file_roots]}")
        if not path.exists():
            raise FetchError(f"file not found: {spec.file.path}")
        return path

    # --- running ----------------------------------------------------------------------------------

    def _auto_mapped(self, spec: ConnectorSpec, records: List[Any], m: RunMetrics,
                     st: Optional[ConnectorState] = None) -> ConnectorSpec:
        """No `mapping` in the config: learn it from the first records, then keep it for this connector."""
        st = st or self.states.get(spec.id)
        learned = st.learned if st else None
        if learned is None:
            try:
                learned = infer_mapping(spec.entity, records, default_type=spec.source_name)
            except MappingError as e:
                raise FetchError(str(e)) from e
            if st:
                st.learned = learned
            m.notes.append("mapped automatically: " + ", ".join(
                f"{k} <- {fm.from_ if fm.from_ is not None else repr(fm.const)}" for k, fm in learned.items()))
        return spec.model_copy(update={"mapping": learned})

    def _ingest(self, records: List[Any], spec: ConnectorSpec, run_id: int, m: RunMetrics) -> List[Any]:
        if spec.mapping is None:
            if not records:
                return []
            spec = self._auto_mapped(spec, records, m)
        good_raw, rows = [], []
        for rec in records:
            row, why = map_record(rec, spec)
            if why:
                m.rejected += 1
                self.store.quarantine(spec.id, run_id, why, rec)
            else:
                good_raw.append(rec)
                rows.append(row)
        new, updated, unchanged = self.store.upsert(spec.entity, spec.id, rows,
                                                    new_rows=m.fresh if spec.entity == "event" else None)
        m.new += new
        m.updated += updated
        m.unchanged += unchanged
        return good_raw

    async def _run_http(self, st: ConnectorState, run_id: int, m: RunMetrics) -> None:
        spec = st.spec
        saved = self.store.get_cursor(spec.id)
        cursor = (parse_datetime(saved) if saved else initial_cursor(spec.cursor)) if spec.cursor else None
        newest = cursor
        fetcher = Fetcher(spec, self.client, st.auth, st.bucket, m, self.sleep,
                          on_block=lambda url: self.store.audit(spec.id, "egress.blocked", url))
        async for records in fetch_pages(spec, fetcher, cursor):
            m.pages += 1
            m.fetched += len(records)
            for rec in self._ingest(records, spec, run_id, m):
                if spec.cursor:
                    try:
                        ts = parse_datetime(get_path(rec, spec.cursor.field))
                        newest = ts if newest is None or ts > newest else newest
                    except (ValueError, TypeError):
                        pass
        if spec.cursor and newest is not None:
            self.store.set_cursor(spec.id, newest.isoformat())

    async def _run_file(self, st: ConnectorState, run_id: int, m: RunMetrics) -> None:
        spec = st.spec
        path = self._resolve_file(spec)
        offset = int(self.store.get_cursor(spec.id) or 0)
        lines, new_offset, rotated = read_new_lines(path, offset, spec.file.max_bytes_per_run)
        if rotated:
            m.notes.append("file rotated or truncated, reading from the start")
        m.pages, m.fetched = (1 if lines else 0), len(lines)
        parsed = []
        line_filter = re.compile(spec.file.filter) if spec.file.filter else None
        for line in lines:
            if not line.strip() or (line_filter and not line_filter.search(line)):
                continue  # shared syslog files: other vendors' lines are not ours (and not errors)
            rec, why = parse_line(line, spec)
            if why:
                m.rejected += 1
                self.store.quarantine(spec.id, run_id, why, line)
            else:
                parsed.append(rec)
        self._ingest(parsed, spec, run_id, m)
        self.store.set_cursor(spec.id, str(new_offset))

    async def run(self, cid: str, trigger: str = "schedule") -> dict:
        st = self.states[cid]
        if st.running:
            return {"skipped": "already running"}
        st.running = True
        m = RunMetrics()
        run_id = self.store.start_run(cid, trigger)
        status, error, started = "ok", None, time.monotonic()
        try:
            async with self._sem:
                await (self._run_http(st, run_id, m) if st.spec.kind == "http" else self._run_file(st, run_id, m))
        except (FetchError, AuthError, SecretMissing, SecretAccessDenied) as e:
            status, error = "error", str(e)
        except Exception as e:  # one connector can never take the platform down
            status, error = "error", f"{type(e).__name__}: {e}"
        finally:
            error = self.vault.redact(error) if error else None
            counters = {k: v for k, v in asdict(m).items() if k not in ("notes", "fresh")}
            st.last_notes = [self.vault.redact(n) for n in m.notes[-10:]]
            self.store.finish_run(run_id, status=status, error=error, **counters)
            st.running = False
            st.last_run = {"id": run_id, "status": status, "error": error, "trigger": trigger,
                           "finished_at": now_iso(), "duration_ms": int((time.monotonic() - started) * 1000),
                           **counters}
            baseline = st.last_success_at is None  # a connection's first good run is history, not news
            if status == "ok":
                if st.alerted:
                    await self._alert(st, "recovered", f"{st.spec.name} recovered",
                                      [f"Working again after {st.consecutive_failures} failed runs"])
                st.consecutive_failures, st.alerted = 0, False
                st.last_success_at = st.last_run["finished_at"]
                await self._data_notices(st, m, baseline)
            else:
                st.consecutive_failures += 1
                if re.search(r"HTTP (401|403)\b|denied access|returned HTTP (401|403)", error or ""):
                    await self._alert(st, "auth_failed", f"{st.spec.name}: credential rejected", [
                        f"The source refused the login: {error[:300]}",
                        f"Check or rotate the secret ({', '.join(st.spec.secret_names) or 'none configured'}) "
                        "on the Secrets tab"])
                if st.consecutive_failures >= ALERT_AFTER_FAILURES and not st.alerted:
                    st.alerted = True
                    await self._alert(st, "failing", f"{st.spec.name} failed {st.consecutive_failures} runs in a row",
                                      [f"Last error: {error}",
                                       "ConnectForge keeps retrying with growing gaps and will say when it recovers"])
            st.next_run = time.monotonic() + self.next_delay(st)
        return st.last_run

    @staticmethod
    def next_delay(st: ConnectorState) -> float:
        base = st.spec.schedule.seconds
        if st.consecutive_failures >= ALERT_AFTER_FAILURES:  # circuit open: back off, keep probing
            return min(base * 2 ** min(st.consecutive_failures - 2, 6), 3600)
        return base

    # --- alerts (B-4) -------------------------------------------------------------------------------

    async def _alert(self, st: ConnectorState, kind: str, title: str, lines: List[str]) -> str:
        """Slack and email (see notify.py); every notice is also kept on the Notifications page."""
        return await self.notifier.notify(kind, st.spec.id, title, [self.vault.redact(x) for x in lines])

    async def _data_notices(self, st: ConnectorState, m: RunMetrics, baseline: bool) -> None:
        if m.fetched >= 10 and m.rejected / m.fetched > 0.2:
            await self._alert(st, "data_quality", f"{st.spec.name}: {m.rejected} of {m.fetched} records rejected", [
                "The source may have changed its format. The rejected records and reasons are on the Quarantine tab",
                "Good records were still stored"])
        settings = self.notifier.settings()
        floor = SEVERITY_RANK[settings["min_severity"]]
        hits = [r for r in m.fresh if SEVERITY_RANK.get(str(r.get("severity") or "").lower(), -1) >= floor]
        if hits and not baseline:
            lines = [f"[{r.get('severity')}] {r.get('id')}: {str(r.get('description') or r.get('type') or '')[:140]}"
                     + (f" ({r['url']})" if r.get("url") else "") for r in hits[:5]]
            if len(hits) > 5:
                lines.append(f"...and {len(hits) - 5} more on the connection's Data tab")
            await self._alert(st, "critical_data", f"{len(hits)} new {settings['min_severity']}+ finding"
                              f"{'s' if len(hits) > 1 else ''} from {st.spec.name}", lines)

    async def check_rotation(self) -> int:
        used = {cid: s.spec.secret_names for cid, s in self.states.items()}
        return await self.notifier.check_rotation(used)

    # --- test connection (B-3) & preview -------------------------------------------------------------

    def _spec_and_state(self, cid_or_yaml: str, endpoint: Optional[str] = None) -> Tuple[ConnectorSpec, ConnectorState]:
        if cid_or_yaml in self.states:
            st = self.states[cid_or_yaml]
            return st.spec, st
        specs = parse_specs(cid_or_yaml)
        spec = next((s for s in specs if endpoint in (s.endpoint, s.id)), specs[0])
        return spec, self._make_state(spec, share=False)

    async def test_connection(self, cid_or_yaml: str, endpoint: Optional[str] = None) -> dict:
        """One authenticated request, no retries, nothing stored: can we log in and read data?"""
        spec, st = self._spec_and_state(cid_or_yaml, endpoint)
        started = time.monotonic()
        m = RunMetrics()
        try:
            if spec.kind == "file":
                path = self._resolve_file(spec)
                return {"ok": True, "connector": spec.id, "detail": f"file readable ({path.stat().st_size} bytes)",
                        "latency_ms": int((time.monotonic() - started) * 1000)}
            fetcher = Fetcher(spec, self.client, st.auth, st.bucket, m, self.sleep, on_block=lambda url: None,
                              max_attempts=1)
            cursor = initial_cursor(spec.cursor) if spec.cursor else None
            async for records in fetch_pages(spec, fetcher, cursor):
                return {"ok": True, "connector": spec.id, "latency_ms": int((time.monotonic() - started) * 1000),
                        "detail": ("connected (no login needed)" if spec.auth.type == "none" else "authenticated")
                                  + f", first page returned {len(records)} record(s)",
                        "auth": spec.auth.type}
            return {"ok": True, "connector": spec.id, "detail": "no data"}
        except (FetchError, AuthError, SecretMissing, SecretAccessDenied, OSError) as e:
            return {"ok": False, "connector": spec.id, "latency_ms": int((time.monotonic() - started) * 1000),
                    "detail": self.vault.redact(str(e))}

    async def preview(self, cid_or_yaml: str, limit: int = 5, endpoint: Optional[str] = None) -> dict:
        spec, st = self._spec_and_state(cid_or_yaml, endpoint)
        m = RunMetrics()
        if spec.kind == "file":
            path = self._resolve_file(spec)
            lines, _, _ = read_new_lines(path, max(path.stat().st_size - 6000, 0), 6000)
            records = []
            for line in lines[1:limit + 1]:
                rec, why = parse_line(line, spec)
                records.append(rec if rec is not None else {"_unparsed": line, "_error": why})
        else:
            fetcher = Fetcher(spec, self.client, st.auth, st.bucket, m, self.sleep, on_block=lambda url: None)
            cursor = initial_cursor(spec.cursor) if spec.cursor else None
            records = []
            async for page in fetch_pages(spec, fetcher, cursor):
                records = page
                break
        learned = None
        if spec.mapping is None and records:
            spec = self._auto_mapped(spec, records, m, st)
            learned = mapping_yaml(spec.mapping)
        return {"connector": spec.id, "entity": spec.entity, "samples": map_preview(records, spec, limit),
                "notes": m.notes, "learned_mapping": learned}

    # --- scheduler (FR-4) ---------------------------------------------------------------------------

    async def _tick(self) -> None:
        now = time.monotonic()
        for cid, st in list(self.states.items()):
            if st.spec.enabled and not st.paused and not st.running and now >= st.next_run:
                st.next_run = now + 3600
                task = asyncio.create_task(self.run(cid))
                self._tasks.add(task)
                task.add_done_callback(self._tasks.discard)

    async def _loop(self) -> None:
        while True:
            await self._tick()
            if time.monotonic() - self._rotation_checked > 86400:  # once a day: keys due for rotation
                self._rotation_checked = time.monotonic()
                try:
                    await self.check_rotation()
                except Exception:  # a notice failing must never stop the scheduler
                    log.exception("daily key-rotation check failed")
            await asyncio.sleep(1)

    def start(self) -> None:
        self._loop_task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        if self._loop_task:
            self._loop_task.cancel()
        for t in list(self._tasks):
            t.cancel()
        if self._client:
            await self._client.aclose()

    # --- health (FR-10) -----------------------------------------------------------------------------

    def health(self, cid: str) -> dict:
        st = self.states[cid]
        lr = st.last_run
        reasons: List[str] = []
        if not st.spec.enabled:
            status = "disabled"
        elif st.paused:
            status = "paused"
        elif not lr:
            status = "running" if st.running else "pending"
        elif st.consecutive_failures >= ALERT_AFTER_FAILURES:
            status, reasons = "failing", [f"{st.consecutive_failures} failed runs in a row, alert sent, backing off"]
        elif lr["status"] == "error":
            status, reasons = "degraded", ["last run failed"]
        else:
            status = "healthy"
            if lr["fetched"] and lr["rejected"] / lr["fetched"] > 0.2:
                status, reasons = "degraded", [f"{lr['rejected']} of {lr['fetched']} records rejected"]
        next_in = max(st.next_run - time.monotonic(), 0) if st.next_run else 0
        return {
            "id": cid, "name": st.spec.name, "description": st.spec.description, "kind": st.spec.kind,
            "integration": st.spec.integration or cid, "integration_name": st.spec.integration_name or st.spec.name,
            "endpoint": st.spec.endpoint,
            "entity": st.spec.entity, "source": st.spec.source_name, "status": status, "reasons": reasons,
            "running": st.running, "paused": st.paused, "last_run": lr, "last_success_at": st.last_success_at,
            "consecutive_failures": st.consecutive_failures,
            "next_run_in_s": None if st.paused or not st.spec.enabled else round(next_in),
            "every_seconds": st.spec.schedule.seconds, "notes": st.last_notes,
            "cursor": self.store.get_cursor(cid), "totals": self.store.totals(cid),
            "records_stored": self.store.count_for_connector(st.spec.entity, cid),
            "auth": st.spec.auth.type, "pagination": st.spec.pagination.type,
            "hosts": sorted(st.spec.egress_hosts()) if st.spec.kind == "http" else [],
            "secrets": st.spec.secret_names,
        }
