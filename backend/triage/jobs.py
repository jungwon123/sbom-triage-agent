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



def _agent(run_dir: pathlib.Path, payload: dict) -> dict:
    """The AI judgment for a run. Calls the configured model, so it is skipped (never downgraded to
    rule-only, which would overwrite earlier judgments) when no model can be called."""
    from . import cache, runner
    from .agent import llm as llm_mod
    run = runner.Run(run_dir)

    def skipped(why: str) -> dict:
        run.emit({"type": "stage", "stage": "agent", "status": "skipped", "why": why})
        return {"summary": run.meta.get("summary"), "skipped": why, "judged": 0}

    if cache.replay_mode() or llm_mod.provider() == "replay":
        return skipped("replay mode")
    if llm_mod.provider() == "none":
        return skipped("no model")
    scope, only = payload.get("scope") or "all", None
    if scope == "changed":
        only = {c["finding_id"] for c in run.meta.get("changes", []) if c["kind"] != "removed"}
    elif scope == "failed":
        only = {t.finding_id for t in run.triage() if t.decided_by == "agent_fallback"}
    if only is not None and not only:
        return skipped("nothing to judge")
    run = runner.agent(run, payload.get("limit"), only=only)
    triage = run.triage()
    return {"summary": run.meta.get("summary"), "skipped": None, "llm": run.meta.get("llm"),
            "judged": sum(1 for t in triage if t.decided_by == "agent" and (only is None or t.finding_id in only)),
            "fallbacks": sum(1 for t in triage if t.decided_by == "agent_fallback")}


# kind -> handler(run_dir, payload) -> result. Handlers get plain values, never a closure.
HANDLERS: dict[str, Callable[[pathlib.Path, dict], dict]] = {"export_together": _export_together,
                                                             "service_check": _service_check,
                                                             "verify": _verify,
                                                             "agent": _agent}


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def mode() -> str:
    return os.environ.get("TRIAGE_WORKER", "external" if store.kind() == "postgres" else "inline").lower()


def new_worker_id() -> str:
    return f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:6]}"


def alive_workers(root: pathlib.Path) -> list[dict]:
    return [w for w in store.get().workers(root) if w.get("seen", 0) >= time.time() - WORKER_ALIVE]


def reclaim(root: pathlib.Path, st: store.Store | None = None, announce_cut_off: bool = False) -> None:
    """Running jobs whose worker went silent: back to the queue, or interrupted once retried.

    Only a worker announces a job it found cut off (announce_cut_off): the API also calls this when
    someone reads a job, and the API process sends nothing outside.
    """
    st = st or store.get()
    for row in st.job_list(root, ("running",)):
        if (row.get("heartbeat") or 0) >= time.time() - STALE:
            continue
        if row.get("attempts", 0) < MAX_ATTEMPTS:
            patch = {"status": "queued", "worker": None, "started_at": None}
        else:
            patch = {"status": "interrupted", "error": CUT_OFF, "finished_at": _now()}
        changed = st.job_update(root / row["run_id"], row["id"], patch, worker=row.get("worker"))
        if announce_cut_off and changed and patch["status"] == "interrupted":
            announce(root, {**row, **patch}, st)


def announce(root: pathlib.Path, row: dict, st: store.Store | None = None) -> str | None:
    """Tell the team's channel that a job ended (notify.py). -> what happened to the alert, or None.

    Never raises: an alert that cannot be sent must not change the job. A re-check that ended normally
    is left out because services.py sends its own alert about what changed. TRIAGE_NOTIFY_JOBS=off
    turns these alerts off; without SLACK_WEBHOOK_URL nothing is sent anyway.
    """
    if os.environ.get("TRIAGE_NOTIFY_JOBS", "on").lower() in ("off", "0", "false", "no"):
        return None
    if row["kind"] == "service_check" and row["status"] == "done":
        return None
    try:
        from . import notify
        run_dir = root / row["run_id"]
        meta = (st or store.get()).get_doc(run_dir, "meta") or {}
        base = os.environ.get("TRIAGE_PUBLIC_URL", "").strip().rstrip("/")
        link = f"{base}/?run={row['run_id']}" if base and meta else None
        sent, detail = notify.send(notify.build_job_message(row, meta.get("name") or row["run_id"], link))
        return detail if sent else f"not sent: {detail}"
    except Exception:
        log.exception("job alert failed")
        return None


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
    reclaim(root, st, announce_cut_off=True)
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
    if kept and done:
        announce(root, done, st)
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
