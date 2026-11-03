"""Operations PoC: PostgreSQL job queue with SKIP LOCKED, leases and fencing.
Work is simulated with sleep; this measures the queue, not the sandbox.
usage: python poc/queue_poc.py            run every scenario in a throwaway container
       python poc/queue_poc.py worker <name> <work_seconds> <lease_seconds>"""
import json, os, pathlib, secrets, signal, subprocess, sys, time

import psycopg

IMAGE = "public.ecr.aws/docker/library/postgres:16-alpine"
PORT = 55432
NAME = "sbom-queue-poc"
SCHEMA = """
create table jobs (id bigint primary key, status text not null default 'queued',
  worker text, lease_until timestamptz, attempts int not null default 0, done_by text,
  started_at timestamptz, done_at timestamptz);
create index on jobs (id) where status in ('queued', 'running');
create table starts (job_id bigint, worker text, attempt int);
create table rejected (job_id bigint, worker text, attempt int);
"""
CLAIM = """
update jobs set status = 'running', worker = %s, attempts = attempts + 1, started_at = now(),
                lease_until = now() + make_interval(secs => %s)
where id = (select id from jobs
            where status = 'queued' or (status = 'running' and lease_until < now())
            order by id for update skip locked limit 1)
returning id, attempts"""
FINISH = """
update jobs set status = 'done', done_by = %s, done_at = now()
where id = %s and worker = %s and attempts = %s and status = 'running'"""


def dsn() -> str:
    return f"postgresql://postgres:{os.environ['POC_PG_PASSWORD']}@127.0.0.1:{PORT}/postgres"


def worker(name: str, work: float, lease: float) -> None:
    with psycopg.connect(dsn(), autocommit=True) as db:
        idle = 0
        while idle < 3:
            row = db.execute(CLAIM, (name, lease)).fetchone()
            if row is None:
                idle += 1
                time.sleep(.5)
                continue
            idle = 0
            job, attempt = row
            db.execute("insert into starts values (%s, %s, %s)", (job, name, attempt))
            time.sleep(work)
            # Fencing: a worker whose lease was taken over must not finish the job.
            if db.execute(FINISH, (name, job, name, attempt)).rowcount == 0:
                db.execute("insert into rejected values (%s, %s, %s)", (job, name, attempt))


def spawn(name: str, work: float, lease: float) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, __file__, "worker", name, str(work), str(lease)])


def reset(db: psycopg.Connection, count: int) -> None:
    db.execute("truncate jobs, starts, rejected")
    db.execute("insert into jobs (id) select generate_series(1, %s)", (count,))


def audit(db: psycopg.Connection) -> dict:
    one = lambda sql: db.execute(sql).fetchone()[0]
    return {
        "jobs": one("select count(*) from jobs"),
        "done": one("select count(*) from jobs where status = 'done'"),
        "not_done": one("select count(*) from jobs where status <> 'done'"),
        "started_more_than_once": one("select count(*) from (select job_id from starts group by 1 having count(*) > 1) t"),
        "rejected_finishes": one("select count(*) from rejected"),
        "same_attempt_claimed_twice": one("select count(*) from (select job_id, attempt from starts group by 1, 2 having count(*) > 1) t"),
    }


def wait_all(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        p.wait(timeout=300)


def throughput(db: psycopg.Connection, workers: int, count: int) -> dict:
    reset(db, count)
    wait_all([spawn(f"w{i}", 0, 30) for i in range(workers)])
    seconds = db.execute("select extract(epoch from max(done_at) - min(started_at))::float from jobs").fetchone()[0]
    return {"workers": workers, "jobs_per_sec": round(count / seconds), **audit(db)}


def kill_worker(db: psycopg.Connection) -> dict:
    """SIGKILL one worker mid-job: its lease expires and another worker takes over."""
    reset(db, 60)
    procs = [spawn(f"w{i}", .2, 2) for i in range(3)]
    time.sleep(1.5)
    victim = db.execute("select worker, id from jobs where status = 'running' and worker = 'w0' limit 1").fetchone()
    procs[0].send_signal(signal.SIGKILL)
    wait_all(procs[1:])
    res = audit(db)
    return {"killed_while_holding_job": victim[1] if victim else None, **res,
            "killed_job_final": db.execute("select status, done_by, attempts from jobs where id = %s", (victim[1],)).fetchone() if victim else None}


def stalled_worker(db: psycopg.Connection) -> dict:
    """SIGSTOP past the lease, then resume: the stale finish has to be rejected."""
    reset(db, 30)
    procs = [spawn(f"w{i}", .3, 1.5) for i in range(3)]
    time.sleep(.8)
    victim = db.execute("select id from jobs where status = 'running' and worker = 'w0' limit 1").fetchone()
    procs[0].send_signal(signal.SIGSTOP)
    time.sleep(3)
    procs[0].send_signal(signal.SIGCONT)
    wait_all(procs)
    return {"stalled_job": victim[0] if victim else None, **audit(db),
            "rejected": db.execute("select job_id, worker, attempt from rejected").fetchall()}


def main() -> None:
    os.environ["POC_PG_PASSWORD"] = secrets.token_hex(16)
    subprocess.run(["docker", "run", "-d", "--rm", "--name", NAME, "-p", f"127.0.0.1:{PORT}:5432",
                    "-e", "POSTGRES_PASSWORD", IMAGE], check=True, capture_output=True,
                   env={**os.environ, "POSTGRES_PASSWORD": os.environ["POC_PG_PASSWORD"]})
    try:
        for _ in range(60):
            try:
                db = psycopg.connect(dsn(), autocommit=True, connect_timeout=3)
                db.execute("select 1")
                break
            except psycopg.OperationalError:
                time.sleep(.5)
        else:
            raise SystemExit("postgres did not become ready")
        db.execute(SCHEMA)
        result = {"throughput": [throughput(db, n, 20000) for n in (1, 4, 8)],
                  "kill_worker": kill_worker(db), "stalled_worker": stalled_worker(db)}
        pathlib.Path("out/poc/queue.json").write_text(json.dumps(result, indent=1))
        print(json.dumps(result, indent=1))
    finally:
        subprocess.run(["docker", "rm", "-f", NAME], capture_output=True)


if __name__ == "__main__":
    if sys.argv[1:2] == ["worker"]:
        worker(sys.argv[2], float(sys.argv[3]), float(sys.argv[4]))
    else:
        main()
