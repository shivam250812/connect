"""One place for results (FR-11): `users`, `devices` and `events` tables in the common schema
(and `records` for data outside it),
plus platform state — checkpoints, runs, quarantined records, alerts and the audit log.

Rows are keyed by (source, id): re-fetching a record updates it in place instead of duplicating it,
and every row keeps `source` and `fetched_at` so you can tell where it came from.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from connectforge.config.schema import ENTITY_FIELDS, TABLES

_SQL_TYPE = {"int": "INTEGER", "float": "REAL", "bool": "INTEGER"}

STATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS cursors (connector TEXT PRIMARY KEY, value TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, connector TEXT, started_at TEXT, finished_at TEXT,
  status TEXT, trigger TEXT, pages INTEGER, fetched INTEGER, new INTEGER, updated INTEGER,
  unchanged INTEGER, rejected INTEGER, retries INTEGER, throttled_ms INTEGER, error TEXT);
CREATE INDEX IF NOT EXISTS runs_by_connector ON runs(connector, id DESC);
CREATE TABLE IF NOT EXISTS quarantine (
  id INTEGER PRIMARY KEY AUTOINCREMENT, connector TEXT, run_id INTEGER, at TEXT, reason TEXT,
  record TEXT, fp TEXT UNIQUE);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, connector TEXT, kind TEXT, message TEXT, delivered TEXT);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, actor TEXT, action TEXT, detail TEXT);
-- which connector delivered which record: a record is stored once even when two connectors fetch it,
-- and still shows up in each one's Data view
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS deliveries (connector TEXT NOT NULL, tbl TEXT NOT NULL, source TEXT NOT NULL,
  id TEXT NOT NULL, last_seen TEXT, PRIMARY KEY (connector, tbl, source, id));
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _entity_ddl(entity: str) -> str:
    cols = ", ".join(f"{name} {_SQL_TYPE.get(kind, 'TEXT')}" for name, kind in ENTITY_FIELDS[entity].items()
                     if name != "id")
    table = TABLES[entity]
    return (f"CREATE TABLE IF NOT EXISTS {table} (id TEXT NOT NULL, source TEXT NOT NULL, {cols}, "
            f"fetched_at TEXT NOT NULL, connector TEXT, digest TEXT, PRIMARY KEY (source, id));"
            f"CREATE INDEX IF NOT EXISTS {table}_by_fetch ON {table}(fetched_at DESC);")


class Store:
    def __init__(self, path: Path | str = ":memory:"):
        self._lock = threading.Lock()
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript(STATE_SCHEMA + "".join(_entity_ddl(e) for e in ENTITY_FIELDS))
        for table in TABLES.values():  # rows stored before deliveries existed belong to their writer
            self.db.execute(f"INSERT OR IGNORE INTO deliveries SELECT connector, '{table}', source, id, fetched_at "
                            f"FROM {table} WHERE connector IS NOT NULL")
        self.db.commit()

    def _exec(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur

    def _rows(self, sql: str, args: tuple = ()) -> List[dict]:
        with self._lock:
            return [dict(r) for r in self.db.execute(sql, args).fetchall()]

    # --- common-schema records ------------------------------------------------------------------

    def upsert(self, entity: str, connector: str, rows: List[Dict[str, Any]],
               new_rows: Optional[List[Dict[str, Any]]] = None) -> Tuple[int, int, int]:
        """Insert or update rows by (source, id). Returns (new, updated, unchanged); rows seen for the first
        time are also appended to `new_rows` when given (used for "new critical findings" notices)."""
        table, fields = TABLES[entity], list(ENTITY_FIELDS[entity])
        new = updated = unchanged = 0
        fetched_at = now_iso()
        with self._lock:
            self.db.executemany("INSERT INTO deliveries VALUES (?, ?, ?, ?, ?) ON CONFLICT DO UPDATE SET last_seen=excluded.last_seen",
                                [(connector, table, r["source"], r["id"], fetched_at) for r in rows])
            for row in rows:
                digest = hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()[:16]
                prev = self.db.execute(f"SELECT digest FROM {table} WHERE source=? AND id=?",
                                       (row["source"], row["id"])).fetchone()
                if prev and prev["digest"] == digest:
                    unchanged += 1
                    self.db.execute(f"UPDATE {table} SET fetched_at=? WHERE source=? AND id=?",
                                    (fetched_at, row["source"], row["id"]))
                    continue
                values = [row.get(f) for f in fields]
                self.db.execute(
                    f"INSERT INTO {table} ({', '.join(fields)}, source, fetched_at, connector, digest) "
                    f"VALUES ({', '.join('?' * (len(fields) + 4))}) ON CONFLICT(source, id) DO UPDATE SET "
                    + ", ".join(f"{f}=excluded.{f}" for f in fields[1:] + ["fetched_at", "connector", "digest"]),
                    (*values, row["source"], fetched_at, connector, digest))
                if prev:
                    updated += 1
                else:
                    new += 1
                    if new_rows is not None and len(new_rows) < 500:
                        new_rows.append(row)
            self.db.commit()
        return new, updated, unchanged

    def records(self, entity: str, source: Optional[str] = None, limit: int = 100, q: Optional[str] = None,
                connector: Optional[str] = None) -> List[dict]:
        table = TABLES[entity]
        where, args = [], []
        if source:
            where.append("source=?")
            args.append(source)
        if connector:
            where.append(f"EXISTS (SELECT 1 FROM deliveries d WHERE d.connector=? AND d.tbl='{table}' "
                         f"AND d.source={table}.source AND d.id={table}.id)")
            args.append(connector)
        if q:
            where.append("(" + " OR ".join(f"CAST({f} AS TEXT) LIKE ?" for f in ENTITY_FIELDS[entity]) + ")")
            args += [f"%{q}%"] * len(ENTITY_FIELDS[entity])
        sql = f"SELECT * FROM {table}" + (" WHERE " + " AND ".join(where) if where else "") + \
            " ORDER BY fetched_at DESC, id LIMIT ?"
        rows = self._rows(sql, (*args, limit))
        for r in rows:
            r.pop("digest", None)
        return rows

    def counts(self) -> Dict[str, Dict[str, int]]:
        out = {}
        for table in TABLES.values():
            out[table] = {r["source"]: r["n"] for r in self._rows(f"SELECT source, COUNT(*) n FROM {table} GROUP BY source")}
        return out

    def count_for_connector(self, entity: str, connector: str) -> int:
        return self._rows("SELECT COUNT(*) n FROM deliveries WHERE connector=? AND tbl=?", (connector, TABLES[entity]))[0]["n"]

    # --- checkpoints ---------------------------------------------------------------------------

    def purge(self, connector: str) -> int:
        """Delete everything one connector produced: records, runs, checkpoint, quarantine and alerts."""
        n = 0
        for table in list(TABLES.values()) + ["runs", "cursors", "quarantine", "alerts", "deliveries"]:
            n += self._exec(f"DELETE FROM {table} WHERE connector=?", (connector,)).rowcount
        return n

    def rename_connector(self, old: str, new: str) -> int:
        """Move a connection's history to a new id (e.g. a single connector becoming an endpoint of an
        integration): runs, checkpoint, deliveries, quarantine, alerts and stored rows. Rows the new id already
        has are kept; the old id's duplicates are dropped."""
        n = 0
        with self._lock:
            for table in ["runs", "quarantine", "alerts"] + list(TABLES.values()):
                n += self.db.execute(f"UPDATE {table} SET connector=? WHERE connector=?", (new, old)).rowcount
            for table in ("cursors", "deliveries"):
                n += self.db.execute(f"UPDATE OR IGNORE {table} SET connector=? WHERE connector=?", (new, old)).rowcount
                self.db.execute(f"DELETE FROM {table} WHERE connector=?", (old,))
            self.db.commit()
        return n

    def get_cursor(self, connector: str) -> Optional[str]:
        rows = self._rows("SELECT value FROM cursors WHERE connector=?", (connector,))
        return rows[0]["value"] if rows else None

    def set_cursor(self, connector: str, value: str) -> None:
        self._exec("INSERT INTO cursors VALUES(?,?,?) ON CONFLICT(connector) DO UPDATE SET value=excluded.value,"
                   " updated_at=excluded.updated_at", (connector, value, now_iso()))

    def reset_cursor(self, connector: str) -> None:
        self._exec("DELETE FROM cursors WHERE connector=?", (connector,))

    # --- runs ------------------------------------------------------------------------------------

    def start_run(self, connector: str, trigger: str) -> int:
        return self._exec("INSERT INTO runs(connector, started_at, status, trigger) VALUES(?,?,?,?)",
                          (connector, now_iso(), "running", trigger)).lastrowid

    def finish_run(self, run_id: int, **m: Any) -> None:
        self._exec("UPDATE runs SET finished_at=?, status=?, pages=?, fetched=?, new=?, updated=?, unchanged=?,"
                   " rejected=?, retries=?, throttled_ms=?, error=? WHERE id=?",
                   (now_iso(), m["status"], m["pages"], m["fetched"], m["new"], m["updated"], m["unchanged"],
                    m["rejected"], m["retries"], m["throttled_ms"], m.get("error"), run_id))

    def runs(self, connector: str, limit: int = 20) -> List[dict]:
        return self._rows("SELECT * FROM runs WHERE connector=? ORDER BY id DESC LIMIT ?", (connector, limit))

    def totals(self, connector: str) -> dict:
        return self._rows("SELECT COALESCE(SUM(fetched),0) fetched, COALESCE(SUM(new),0) new,"
                          " COALESCE(SUM(rejected),0) rejected, COUNT(*) runs FROM runs WHERE connector=?",
                          (connector,))[0]

    # --- quarantine (bad data) ---------------------------------------------------------------------

    def quarantine(self, connector: str, run_id: Optional[int], reason: str, record: Any) -> None:
        blob = json.dumps(record, default=str, sort_keys=True)
        fp = hashlib.sha256(f"{connector}|{blob}".encode()).hexdigest()[:24]
        self._exec("INSERT OR IGNORE INTO quarantine(connector, run_id, at, reason, record, fp) VALUES(?,?,?,?,?,?)",
                   (connector, run_id, now_iso(), reason, blob[:4000], fp))

    def quarantined(self, connector: Optional[str] = None, limit: int = 50) -> List[dict]:
        if connector:
            return self._rows("SELECT * FROM quarantine WHERE connector=? ORDER BY id DESC LIMIT ?", (connector, limit))
        return self._rows("SELECT * FROM quarantine ORDER BY id DESC LIMIT ?", (limit,))

    def quarantine_count(self) -> int:
        return self._rows("SELECT COUNT(*) n FROM quarantine")[0]["n"]

    # --- alerts & audit -----------------------------------------------------------------------------

    def add_alert(self, connector: str, kind: str, message: str, delivered: str) -> None:
        self._exec("INSERT INTO alerts(at, connector, kind, message, delivered) VALUES(?,?,?,?,?)",
                   (now_iso(), connector, kind, message, delivered))

    def recent_alert(self, connector: str, kind: str, since: str) -> bool:
        return bool(self._rows("SELECT 1 FROM alerts WHERE connector=? AND kind=? AND at>=? AND delivered NOT LIKE "
                               "'held back%' AND delivered != 'switched off' LIMIT 1", (connector, kind, since)))

    def get_setting(self, key: str) -> Any:
        rows = self._rows("SELECT value FROM settings WHERE key=?", (key,))
        return json.loads(rows[0]["value"]) if rows else None

    def set_setting(self, key: str, value: Any) -> None:
        self._exec("INSERT INTO settings VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   (key, json.dumps(value)))

    def alerts(self, limit: int = 50) -> List[dict]:
        return self._rows("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))

    def audit(self, actor: str, action: str, detail: str) -> None:
        self._exec("INSERT INTO audit(at, actor, action, detail) VALUES(?,?,?,?)", (now_iso(), actor, action, detail))

    def audit_log(self, limit: int = 100) -> List[dict]:
        return self._rows("SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,))
