"""PostgreSQL store. One connection per thread; every write is one transaction."""
from __future__ import annotations

import datetime as dt
import pathlib
import threading
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SCHEMA = pathlib.Path(__file__).with_name("schema.sql")


class PostgresStore:
    name = "postgres"

    def __init__(self, url: str):
        self.url = url
        self._local = threading.local()

    def _conn(self) -> psycopg.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed:
            # autocommit: a single statement commits by itself, and `with conn.transaction()` is a real
            # transaction. Without it psycopg opens one implicitly and those blocks turn into savepoints
            # that nothing ever commits.
            conn = psycopg.connect(self.url, row_factory=dict_row, autocommit=True)
            self._local.conn = conn
        return conn

    def init(self) -> int:
        """Create tables if missing. -> schema version."""
        with self._conn().transaction():
            self._conn().execute(SCHEMA.read_text())
        return self._conn().execute("SELECT max(version) AS v FROM schema_version").fetchone()["v"]

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None and not conn.closed:
            conn.close()

    # ---- runs ----
    def _ensure_run(self, cur, run_id: str) -> None:
        cur.execute("INSERT INTO runs (id) VALUES (%s) ON CONFLICT DO NOTHING", (run_id,))

    def list_runs(self, root: pathlib.Path) -> list[dict]:
        rows = self._conn().execute("SELECT id, name, meta FROM runs WHERE meta <> '{}'::jsonb ORDER BY id DESC").fetchall()
        return [{"id": r["id"], "name": r["name"], "summary": r["meta"].get("summary"),
                 "stages": r["meta"].get("stages", [])} for r in rows]

    def has_run(self, run_dir: pathlib.Path) -> bool:
        row = self._conn().execute("SELECT 1 FROM runs WHERE id = %s AND meta <> '{}'::jsonb", (run_dir.name,)).fetchone()
        return row is not None

    def get_doc(self, run_dir: pathlib.Path, doc: str) -> Any:
        conn, run_id = self._conn(), run_dir.name
        if True:
            if doc == "meta":
                row = conn.execute("SELECT meta FROM runs WHERE id = %s AND meta <> '{}'::jsonb", (run_id,)).fetchone()
                if row is None:
                    raise KeyError(f"{run_id} has no meta")
                return row["meta"]
            table = {"findings": "findings", "triage": "triage"}[doc]
            rows = conn.execute(f"SELECT body FROM {table} WHERE run_id = %s ORDER BY seq", (run_id,)).fetchall()
            if not rows and conn.execute("SELECT 1 FROM runs WHERE id = %s", (run_id,)).fetchone() is None:
                raise KeyError(f"{run_id} has no {doc}")
            return [r["body"] for r in rows]

    def put_doc(self, run_dir: pathlib.Path, doc: str, data: Any) -> None:
        conn, run_id = self._conn(), run_dir.name
        with conn.transaction(), conn.cursor() as cur:
            self._ensure_run(cur, run_id)
            if doc == "meta":
                cur.execute("UPDATE runs SET name = %s, meta = %s, updated_at = now() WHERE id = %s",
                            (data.get("name"), Jsonb(data), run_id))
            elif doc == "findings":
                cur.execute("DELETE FROM findings WHERE run_id = %s", (run_id,))
                cur.executemany(
                    "INSERT INTO findings (run_id, finding_id, seq, ecosystem, package, version, vuln_id, aliases, scope,"
                    " direct, cvss, epss_percentile, kev, body) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    [(run_id, f["id"], i, f["ecosystem"], f["package"], f["version"], f["vuln_id"], f.get("aliases", []),
                      f["scope"], f["direct"], f.get("cvss"), f.get("epss_percentile"), f["kev"], Jsonb(f))
                     for i, f in enumerate(data)])
            elif doc == "triage":
                cur.execute("DELETE FROM triage WHERE run_id = %s", (run_id,))
                cur.executemany(
                    "INSERT INTO triage (run_id, finding_id, seq, rule_bucket, final_bucket, risk, decided_by, needs_review,"
                    " verdict, body) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                    [(run_id, t["finding_id"], i, t["rule_bucket"], t["final_bucket"], t["risk"],
                      t.get("decided_by", "rule"), t.get("needs_review", False),
                      (t.get("verification") or {}).get("verdict"), Jsonb(t)) for i, t in enumerate(data)])
            else:
                raise KeyError(doc)

    # ---- append-only logs ----
    def append_event(self, run_dir: pathlib.Path, event: dict) -> None:
        conn = self._conn()
        with conn.transaction(), conn.cursor() as cur:
            self._ensure_run(cur, run_dir.name)
            cur.execute("INSERT INTO events (run_id, ts, body) VALUES (%s, %s, %s)",
                        (run_dir.name, float(event.get("ts", 0)), Jsonb(event)))

    def events(self, run_dir: pathlib.Path) -> list[dict]:
        rows = self._conn().execute("SELECT body FROM events WHERE run_id = %s ORDER BY id", (run_dir.name,)).fetchall()
        return [r["body"] for r in rows]

    def append_decision(self, run_dir: pathlib.Path, decision: dict) -> None:
        conn = self._conn()
        with conn.transaction(), conn.cursor() as cur:
            self._ensure_run(cur, run_dir.name)
            cur.execute("INSERT INTO decisions (run_id, target, status, decided_by, reason, decided_at, body)"
                        " VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        (run_dir.name, decision["target"], decision["status"], decision["by"], decision.get("reason", ""),
                         dt.datetime.fromisoformat(decision["at"]), Jsonb(decision)))

    def decisions(self, run_dir: pathlib.Path) -> list[dict]:
        rows = self._conn().execute("SELECT body FROM decisions WHERE run_id = %s ORDER BY id", (run_dir.name,)).fetchall()
        return [r["body"] for r in rows]

    # ---- HTTP response cache ----
    def cache_get(self, key: str) -> tuple[Any, float] | None:
        row = self._conn().execute("SELECT body, extract(epoch FROM fetched_at) AS at FROM http_cache WHERE key = %s",
                                   (key,)).fetchone()
        return (row["body"], float(row["at"])) if row else None

    def cache_put(self, key: str, url: str, body: Any, fetched_at: float | None = None) -> None:
        conn = self._conn()
        at = dt.datetime.fromtimestamp(fetched_at, dt.timezone.utc) if fetched_at else dt.datetime.now(dt.timezone.utc)
        with conn.transaction():
            conn.execute("INSERT INTO http_cache (key, url, body, fetched_at) VALUES (%s, %s, %s, %s)"
                         " ON CONFLICT (key) DO UPDATE SET url = excluded.url, body = excluded.body,"
                         " fetched_at = excluded.fetched_at", (key, url[:2000], Jsonb(body), at))

    # ---- across runs ----
    def search(self, root: pathlib.Path, package: str | None = None, vuln_id: str | None = None,
               limit: int = 200) -> list[dict]:
        where, args = [], []
        if package:
            where.append("lower(f.package) = lower(%s)"); args.append(package)
        if vuln_id:
            where.append("(f.vuln_id = %s OR %s = ANY (f.aliases))"); args += [vuln_id, vuln_id]
        sql = f"""
            WITH latest AS (SELECT DISTINCT ON (name) id, name FROM runs WHERE meta <> '{{}}'::jsonb ORDER BY name, id DESC)
            SELECT l.id AS run_id, l.name AS run_name, f.finding_id, f.package, f.version, f.vuln_id,
                   t.final_bucket, f.kev
            FROM latest l JOIN findings f ON f.run_id = l.id
            LEFT JOIN triage t ON t.run_id = f.run_id AND t.finding_id = f.finding_id
            {"WHERE " + " AND ".join(where) if where else ""}
            ORDER BY l.id DESC, f.seq LIMIT %s"""
        rows = self._conn().execute(sql, (*args, limit)).fetchall()
        return rows
