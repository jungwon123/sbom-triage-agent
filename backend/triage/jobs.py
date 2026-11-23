"""Work queue for slow steps started from the dashboard (HANDOFF D43, D46).

A job is a record in the storage layer: a kind, the run it belongs to and plain input values. The
API only adds the record. A worker claims the oldest queued job, runs the handler registered for
its kind and writes the result back, so the API process never runs a sandbox pass itself.

Who runs the worker (TRIAGE_WORKER):
- "external": a separate process, `python -m triage worker`. Default with the PostgreSQL store.
  Each worker runs one job at a time; start more workers to run more sandbox passes in parallel.
- "inline": a thread inside the API process running the same loop. Default with the file store,
  so the offline demo needs one process and no database.

Between jobs a worker also queues the checks of registered services that are due (services.py).

A worker renews the job's heartbeat while it works. A running job whose heartbeat stopped (the
worker was killed) is put back in the queue once, then reported as "interrupted". A worker that
was only presumed dead cannot overwrite the job afterwards: updates are checked against the
worker that holds it.
"""
from __future__ import annotations

import datetime as dt
import logging
import os
import pathlib
import socket
import threading
import time
import uuid
from collections.abc import Callable

from . import store
from .models import Job

log = logging.getLogger(__name__)

ACTIVE = ("queued", "running")
SCHEDULE_EVERY = 60.0   # seconds between looks at which registered services are due for a check
BEAT = 5.0              # seconds between heartbeats
STALE = 30.0            # a running job this long without a heartbeat has lost its worker
WORKER_ALIVE = 15.0     # a worker seen within this many seconds counts as alive
MAX_ATTEMPTS = 2
RESULT_RETRY = (1.0, 2.0, 4.0, 8.0, 15.0, 30.0)   # waits between tries to record a finished job
CUT_OFF = "작업자가 작업 도중 중단되어 끝내지 못했습니다. 다시 실행하세요."


def _export_together(run_dir: pathlib.Path, payload: dict) -> dict:
    from . import decide, runner
    return decide.export_view(runner.Run(run_dir), together=True)


def _service_check(scope_dir: pathlib.Path, payload: dict) -> dict:
    from . import services
    return services.check(scope_dir.parent, payload["service_id"]).model_dump()


def _verify(run_dir: pathlib.Path, payload: dict) -> dict:
    """The sandbox pass for a run's items, with the setup command the run already carries."""
    from . import runner
    run = runner.verify(runner.Run(run_dir), None, tuple(payload.get("buckets") or ("NOW",)))
    stages = [e for e in store.get().events(run_dir) if e.get("type") == "stage" and e.get("stage") == "verify"]
    last = stages[-1] if stages else {}
    return {"summary": run.meta.get("summary"), "skipped": last.get("why") if last.get("status") == "skipped" else None}


# kind -> handler(run_dir, payload) -> result. Handlers get plain values, never a closure.
HANDLERS: dict[str, Callable[[pathlib.Path, dict], dict]] = {"export_together": _export_together,
                                                             "service_check": _service_check,
                                                             "verify": _verify}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def mode() -> str:
    return os.environ.get("TRIAGE_WORKER", "external" if store.kind() == "postgres" else "inline").lower()


def new_worker_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"


def alive_workers(root: pathlib.Path) -> list[dict]:
    return [w for w in store.get().workers(root) if w.get("seen", 0) >= time.time() - WORKER_ALIVE]


def reclaim(root: pathlib.Path, st: store.Store | None = None) -> None:
    """Running jobs whose worker went silent: back to the queue, or interrupted once retried."""
    st = st or store.get()
    for row in st.job_list(root, ("running",)):
        if (row.get("heartbeat") or 0) >= time.time() - STALE:
            continue
        if row.get("attempts", 0) < MAX_ATTEMPTS:
            patch = {"status": "queued", "worker": None, "started_at": None}
        else:
            patch = {"status": "interrupted", "error": CUT_OFF, "finished_at": _now()}
        st.job_update(root / row["run_id"], row["id"], patch, worker=row.get("worker"))


def _view(root: pathlib.Path, row: dict) -> Job:
    """The stored record plus what only makes sense at read time."""
    st = store.get()
    if row["status"] == "running" and (row.get("heartbeat") or 0) < time.time() - STALE:
        reclaim(root)
        row = st.job_get(root / row["run_id"], row["id"]) or row
    ahead, waiting = 0, False
    if row["status"] == "queued":
        ahead = sum(1 for j in st.job_list(root, ACTIVE) if j.get("seq", 0) < row.get("seq", 0))
        waiting = not alive_workers(root)
    return Job.model_validate({**row, "position": ahead, "waiting_for_worker": waiting})


def get(run_dir: pathlib.Path, job_id: str) -> Job | None:
    row = store.get().job_get(run_dir, job_id) if job_id.isalnum() else None
    return _view(run_dir.parent, row) if row else None


def latest(run_dir: pathlib.Path, kind: str) -> Job | None:
    row = store.get().job_latest(run_dir, kind)
    return _view(run_dir.parent, row) if row else None


def submit(run_dir: pathlib.Path, kind: str, payload: dict | None = None) -> Job:
    """Queue a job. If the same kind is already queued or running for this run, return that job."""
    if kind not in HANDLERS:
        raise KeyError(f"unknown job kind {kind}")
    job = Job(id=uuid.uuid4().hex[:12], run_id=run_dir.name, kind=kind, status="queued",
              payload=payload or {}, created_at=_now())
    row = store.get().job_add(run_dir, job.model_dump(exclude={"position", "waiting_for_worker", "seq"}))
    if mode() == "inline":
        ensure_inline(run_dir.parent)
    return _view(run_dir.parent, row)


def queue_state(root: pathlib.Path) -> dict:
    rows = store.get().job_list(root, ACTIVE)
    return {"mode": mode(), "workers": len(alive_workers(root)),
            "queued": sum(1 for r in rows if r["status"] == "queued"),
            "running": sum(1 for r in rows if r["status"] == "running")}


# ---- the worker ----

def _info(me: str, started_at: str) -> dict:
    return {"id": me, "host": socket.gethostname(), "pid": os.getpid(), "started_at": started_at, "seen": time.time()}


def work_once(root: pathlib.Path, me: str, st: store.Store | None = None) -> Job | None:
    """Claim and run one job. -> the finished job, or None when the queue is empty."""
    st = st or store.get()
    reclaim(root, st)
    row = st.job_claim(root, {"worker": me, "started_at": _now(), "heartbeat": time.time()})
    if row is None:
        return None
    run_dir, started, stop = root / row["run_id"], _now(), threading.Event()

    def beat() -> None:
        while not stop.wait(BEAT):
            try:
                st.job_update(run_dir, row["id"], {"heartbeat": time.time()}, worker=me)
                st.worker_beat(root, _info(me, started))
            except Exception:  # one missed heartbeat must not end them all: the next one recovers
                log.exception("heartbeat failed")

    ticker = threading.Thread(target=beat, name="triage-job-heartbeat", daemon=True)
    ticker.start()
    try:
        patch = {"status": "done", "result": HANDLERS[row["kind"]](run_dir, row.get("payload") or {})}
    except Exception as e:  # a failed job must not take the worker down
        log.warning("job %s failed: %s", row["id"], e)
        patch = {"status": "failed", "error": str(e)[:500]}
    finally:
        stop.set()
        ticker.join()
    patch["finished_at"] = _now()
    # The handler may have run for minutes; losing its result to a database that was away for a moment
    # would run the whole job again. Keep trying for about a minute before giving the job up to reclaim.
    kept = _retry(lambda: st.job_update(run_dir, row["id"], patch, worker=me))
    if not kept:
        log.warning("job %s was taken away from this worker; its result is dropped", row["id"])
    done = _retry(lambda: st.job_get(run_dir, row["id"]))
    return Job.model_validate(done) if done else None


def _retry(call: Callable[[], object], waits: tuple[float, ...] = RESULT_RETRY) -> object:
    for wait in waits:
        try:
            return call()
        except Exception:
            log.exception("could not reach the store; trying again in %ss", wait)
            time.sleep(wait)
    return call()


def serve(root: pathlib.Path, stop: threading.Event | None = None, poll: float = 1.0, me: str | None = None,
          once: bool = False) -> int:
    """The worker loop. -> jobs handled. With once=True it empties the queue and returns."""
    stop, me, started, handled = stop or threading.Event(), me or new_worker_id(), _now(), 0
    st = store.get()                      # the queue this worker belongs to, fixed for its lifetime
    planned = 0.0
    while not stop.is_set():
        job = None
        try:
            st.worker_beat(root, _info(me, started))
            if time.time() - planned >= SCHEDULE_EVERY:      # several workers asking at once queue one job
                planned = time.time()
                from . import services
                services.submit_due(root)
            job = work_once(root, me, st)
        except Exception:  # the store being away for a moment must not end the worker
            log.exception("worker pass failed")
        if job is not None:
            handled += 1
        elif once:
            break
        else:
            stop.wait(poll)
    return handled


_inline: dict[pathlib.Path, threading.Thread] = {}
_inline_lock = threading.Lock()


def ensure_inline(root: pathlib.Path) -> None:
    """Start the in-process worker for this root if it is not running (inline mode only)."""
    with _inline_lock:
        t = _inline.get(root)
        if t is not None and t.is_alive():
            return
        me = new_worker_id()
        store.get().worker_beat(root, _info(me, _now()))     # visible before the first poll
        t = threading.Thread(target=serve, args=(root,), kwargs={"me": me}, name="triage-worker", daemon=True)
        _inline[root] = t
        t.start()
