"""PostgreSQL store. One connection per thread; every write is one transaction."""
from __future__ import annotations

import datetime as dt
import pathlib
import threading
from typing import Any

import psycopg
import psycopg.sql
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SCHEMA = pathlib.Path(__file__).with_name("schema.sql")


class PostgresStore:
    name = "postgres"

    def __init__(self, url: str, schema: str | None = None):
        self.url = url
        self.schema = schema              # a schema of its own (tests); None means the default one
        self._local = threading.local()

    def _conn(self) -> psycopg.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None or conn.closed:
            # autocommit: a single statement commits by itself, and `with conn.transaction()` is a real
            # transaction. Without it psycopg opens one implicitly and those blocks turn into savepoints
            # that nothing ever commits.
            conn = psycopg.connect(self.url, row_factory=dict_row, autocommit=True)
            if self.schema:               # every thread's connection, not only the first one
                conn.execute(psycopg.sql.SQL("CREATE SCHEMA IF NOT EXISTS {0}").format(psycopg.sql.Identifier(self.schema)))
                conn.execute(psycopg.sql.SQL("SET search_path TO {0}").format(psycopg.sql.Identifier(self.schema)))
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

    # ---- work queue ----
    JOB_COLS = "id, run_id, seq, status, heartbeat, body"

    @staticmethod
    def _job(row: dict) -> dict:
        return {**row["body"], "id": row["id"], "run_id": row["run_id"], "seq": row["seq"],
                "status": row["status"], "heartbeat": row["heartbeat"]}

    def job_add(self, run_dir: pathlib.Path, job: dict) -> dict:
        conn, run_id = self._conn(), run_dir.name
        for _ in range(3):      # the active job can finish between the refused insert and the lookup
            with conn.transaction(), conn.cursor() as cur:
                self._ensure_run(cur, run_id)
                # the partial unique index jobs_one_active is what makes "check and insert" one step
                row = cur.execute(
                    "INSERT INTO jobs (id, run_id, kind, status, body) VALUES (%s, %s, %s, 'queued', %s)"
                    " ON CONFLICT (run_id, kind) WHERE status IN ('queued', 'running') DO NOTHING"
                    f" RETURNING {self.JOB_COLS}", (job["id"], run_id, job["kind"], Jsonb(job))).fetchone()
            if row is not None:
                return self._job(row)
            row = conn.execute(f"SELECT {self.JOB_COLS} FROM jobs WHERE run_id = %s AND kind = %s"
                               " AND status IN ('queued', 'running')", (run_id, job["kind"])).fetchone()
            if row is not None:
                return self._job(row)
        raise RuntimeError("could not queue the job")

    def job_get(self, run_dir: pathlib.Path, job_id: str) -> dict | None:
        row = self._conn().execute(f"SELECT {self.JOB_COLS} FROM jobs WHERE run_id = %s AND id = %s",
                                   (run_dir.name, job_id)).fetchone()
        return self._job(row) if row else None

    def job_latest(self, run_dir: pathlib.Path, kind: str) -> dict | None:
        row = self._conn().execute(f"SELECT {self.JOB_COLS} FROM jobs WHERE run_id = %s AND kind = %s"
                                   " ORDER BY seq DESC LIMIT 1", (run_dir.name, kind)).fetchone()
        return self._job(row) if row else None

    def job_claim(self, root: pathlib.Path, patch: dict) -> dict | None:
        # SKIP LOCKED: a second worker asking at the same moment passes over the row this one holds
        row = self._conn().execute(
            "UPDATE jobs SET status = 'running', heartbeat = %s,"
            " body = body || %s || jsonb_build_object('attempts', COALESCE((body->>'attempts')::int, 0) + 1)"
            " WHERE id = (SELECT id FROM jobs WHERE status = 'queued' ORDER BY seq FOR UPDATE SKIP LOCKED LIMIT 1)"
            f" RETURNING {self.JOB_COLS}", (patch.get("heartbeat"), Jsonb(patch))).fetchone()
        return self._job(row) if row else None

    def job_update(self, run_dir: pathlib.Path, job_id: str, patch: dict, worker: str | None = None) -> bool:
        guard, args = "", []
        if worker is not None:
            guard, args = " AND status = 'running' AND body->>'worker' = %s", [worker]
        row = self._conn().execute(
            "UPDATE jobs SET body = body || %s, status = COALESCE(%s, status), heartbeat = COALESCE(%s, heartbeat)"
            f" WHERE run_id = %s AND id = %s{guard} RETURNING id",
            (Jsonb(patch), patch.get("status"), patch.get("heartbeat"), run_dir.name, job_id, *args)).fetchone()
        return row is not None

    def job_list(self, root: pathlib.Path, statuses: tuple[str, ...]) -> list[dict]:
        rows = self._conn().execute(f"SELECT {self.JOB_COLS} FROM jobs WHERE status = ANY (%s) ORDER BY seq",
                                    (list(statuses),)).fetchall()
        return [self._job(r) for r in rows]

    def worker_beat(self, root: pathlib.Path, worker: dict) -> None:
        self._conn().execute("INSERT INTO workers (id, seen, body) VALUES (%s, %s, %s)"
                             " ON CONFLICT (id) DO UPDATE SET seen = excluded.seen, body = excluded.body",
                             (worker["id"], worker["seen"], Jsonb(worker)))
        self._conn().execute("DELETE FROM workers WHERE seen < %s", (worker["seen"] - 86400,))   # long gone

    def workers(self, root: pathlib.Path) -> list[dict]:
        return [r["body"] for r in self._conn().execute("SELECT body FROM workers ORDER BY id").fetchall()]

    # ---- registered services ----
    def service_add(self, root: pathlib.Path, service: dict) -> bool:
        row = self._conn().execute("INSERT INTO services (id, body) VALUES (%s, %s) ON CONFLICT DO NOTHING RETURNING id",
                                   (service["id"], Jsonb(service))).fetchone()
        return row is not None

    def service_get(self, root: pathlib.Path, service_id: str) -> dict | None:
        row = self._conn().execute("SELECT body FROM services WHERE id = %s", (service_id,)).fetchone()
        return row["body"] if row else None

    def service_list(self, root: pathlib.Path) -> list[dict]:
        return [r["body"] for r in self._conn().execute("SELECT body FROM services ORDER BY id").fetchall()]

    def service_update(self, root: pathlib.Path, service_id: str, patch: dict) -> dict | None:
        row = self._conn().execute("UPDATE services SET body = body || %s, updated_at = now() WHERE id = %s RETURNING body",
                                   (Jsonb(patch), service_id)).fetchone()
        return row["body"] if row else None

    def service_delete(self, root: pathlib.Path, service_id: str) -> bool:
        return self._conn().execute("DELETE FROM services WHERE id = %s RETURNING id", (service_id,)).fetchone() is not None

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
