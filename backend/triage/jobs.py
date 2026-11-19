"""A small work queue for slow steps started from the dashboard (HANDOFF D43).

One worker thread runs jobs in order, so only one sandbox pass uses Docker at a time. Each job's
state is a file under out/<run>/jobs/, which the API reads back for polling. The queue itself lives
in this process: a job that was queued or running when the server stopped is reported as
"interrupted" and has to be started again. The operating design replaces this with a real queue
and workers; the file format and the API stay the same.
"""
from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import pathlib
import threading
import uuid
from collections.abc import Callable

from .models import Job

BOOT = uuid.uuid4().hex[:12]
ACTIVE = ("queued", "running")
_executor = cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="triage-job")
_lock = threading.Lock()
_pending = 0


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def _path(run_dir: pathlib.Path, job_id: str) -> pathlib.Path:
    return run_dir / "jobs" / f"{job_id}.json"


def _save(run_dir: pathlib.Path, job: Job) -> None:
    path = _path(run_dir, job.id)
    path.parent.mkdir(exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(job.model_dump_json(indent=1))
    tmp.replace(path)                         # readers never see a half-written file


def _load(path: pathlib.Path) -> Job:
    job = Job.model_validate_json(path.read_text())
    if job.status in ACTIVE and job.boot != BOOT:
        job = job.model_copy(update={"status": "interrupted", "error": "서버가 다시 시작되어 작업이 중단됐습니다. 다시 실행하세요."})
    return job


def get(run_dir: pathlib.Path, job_id: str) -> Job | None:
    path = _path(run_dir, job_id)
    return _load(path) if job_id.isalnum() and path.is_file() else None


def latest(run_dir: pathlib.Path, kind: str) -> Job | None:
    jobs = [_load(p) for p in (run_dir / "jobs").glob("*.json")] if (run_dir / "jobs").is_dir() else []
    jobs = [j for j in jobs if j.kind == kind]
    return max(jobs, key=lambda j: j.created_at) if jobs else None


def submit(run_dir: pathlib.Path, kind: str, work: Callable[[], dict]) -> Job:
    """Queue `work`. If the same kind is already queued or running for this run, return that job."""
    global _pending
    with _lock:
        current = latest(run_dir, kind)
        if current is not None and current.status in ACTIVE:
            return current
        job = Job(id=uuid.uuid4().hex[:12], kind=kind, status="queued", created_at=_now(), position=_pending, boot=BOOT)
        _save(run_dir, job)
        _pending += 1

    def task() -> None:
        global _pending
        running = job.model_copy(update={"status": "running", "started_at": _now()})
        _save(run_dir, running)
        try:
            done = running.model_copy(update={"status": "done", "result": work(), "finished_at": _now()})
        except Exception as e:  # a failed job must not take the worker down
            done = running.model_copy(update={"status": "failed", "error": str(e)[:500], "finished_at": _now()})
        _save(run_dir, done)
        with _lock:
            _pending -= 1

    _executor.submit(task)
    return job
