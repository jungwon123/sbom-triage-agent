"""Work queue: jobs are records in the storage layer and a worker claims them. Same behaviour on
the file store and on PostgreSQL (skipped when the compose database is not reachable)."""
import threading
import time

import pytest

from tests.test_store import st  # noqa: F401  (the two-store fixture)
from triage import jobs

KIND = "export_together"


@pytest.fixture(autouse=True)
def external(monkeypatch):
    monkeypatch.setenv("TRIAGE_WORKER", "external")       # tests drive the worker by hand


def handler(monkeypatch, fn):
    monkeypatch.setitem(jobs.HANDLERS, KIND, fn)


def test_job_waits_for_a_worker_then_keeps_its_result(st, tmp_path, monkeypatch):
    handler(monkeypatch, lambda run_dir, payload: {"run": run_dir.name, "files": payload["files"]})
    run = tmp_path / "run-a"
    job = jobs.submit(run, KIND, {"files": ["combined.patch"]})
    assert job.status == "queued" and job.waiting_for_worker and job.run_id == "run-a"
    st.worker_beat(tmp_path, {"id": "w1", "seen": time.time()})
    assert not jobs.get(run, job.id).waiting_for_worker
    done = jobs.work_once(tmp_path, "w1")
    assert done.id == job.id and done.status == "done" and done.attempts == 1 and done.finished_at
    assert done.result == {"run": "run-a", "files": ["combined.patch"]}
    assert jobs.latest(run, KIND).status == "done" and jobs.work_once(tmp_path, "w1") is None


def test_failure_is_recorded_and_the_worker_goes_on(st, tmp_path, monkeypatch):
    def boom(run_dir, payload):
        raise RuntimeError("docker exploded")
    handler(monkeypatch, boom)
    jobs.submit(tmp_path / "run-a", KIND)
    bad = jobs.work_once(tmp_path, "w1")
    assert bad.status == "failed" and "docker exploded" in bad.error
    handler(monkeypatch, lambda run_dir, payload: {})
    jobs.submit(tmp_path / "run-a", KIND)
    assert jobs.work_once(tmp_path, "w1").status == "done"


def test_same_run_gets_the_active_job_instead_of_a_second_one(st, tmp_path, monkeypatch):
    handler(monkeypatch, lambda run_dir, payload: {})
    first, second = jobs.submit(tmp_path / "run-a", KIND), jobs.submit(tmp_path / "run-a", KIND)
    assert second.id == first.id and len(st.job_list(tmp_path, jobs.ACTIVE)) == 1
    jobs.work_once(tmp_path, "w1")
    assert jobs.submit(tmp_path / "run-a", KIND).id != first.id          # finished: a new one may start


def test_jobs_are_taken_in_the_order_they_were_queued(st, tmp_path, monkeypatch):
    order = []
    handler(monkeypatch, lambda run_dir, payload: order.append(run_dir.name) or {})
    ja, jb = jobs.submit(tmp_path / "run-a", KIND), jobs.submit(tmp_path / "run-b", KIND)
    assert (ja.position, jb.position) == (0, 1)
    assert jobs.queue_state(tmp_path) == {"mode": "external", "workers": 0, "queued": 2, "running": 0}
    assert jobs.serve(tmp_path, me="w1", once=True) == 2 and order == ["run-a", "run-b"]


def test_several_workers_never_run_the_same_job_twice(st, tmp_path, monkeypatch):
    ran, lock = [], threading.Lock()

    def work(run_dir, payload):
        with lock:
            ran.append(run_dir.name)
        time.sleep(0.02)
        return {}

    handler(monkeypatch, work)
    names = [f"run-{i:02d}" for i in range(12)]
    for n in names:
        jobs.submit(tmp_path / n, KIND)

    def worker(me):
        jobs.serve(tmp_path, me=me, once=True)
        getattr(st, "close", lambda: None)()

    threads = [threading.Thread(target=worker, args=(f"w{i}",)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert sorted(ran) == names
    assert all(jobs.latest(tmp_path / n, KIND).status == "done" for n in names)


def test_job_of_a_dead_worker_is_retried_once_then_reported(st, tmp_path, monkeypatch):
    handler(monkeypatch, lambda run_dir, payload: {"ok": True})
    run = tmp_path / "run-a"
    job = jobs.submit(run, KIND)
    held = st.job_claim(tmp_path, {"worker": "dead-1", "started_at": "t", "heartbeat": time.time() - 3600})
    assert held["id"] == job.id and held["attempts"] == 1
    seen = jobs.get(run, job.id)                                   # reading it notices the silence
    assert seen.status == "queued" and seen.worker is None
    # the worker that was only presumed dead comes back: its result must not land
    assert not st.job_update(run, job.id, {"status": "done", "result": {"stale": True}}, worker="dead-1")
    st.job_claim(tmp_path, {"worker": "dead-2", "started_at": "t", "heartbeat": time.time() - 3600})
    gone = jobs.get(run, job.id)
    assert gone.status == "interrupted" and gone.attempts == 2 and "다시 실행" in gone.error
    assert jobs.work_once(tmp_path, "w1") is None


def test_heartbeat_keeps_a_long_job_from_being_taken_away(st, tmp_path, monkeypatch):
    monkeypatch.setattr(jobs, "BEAT", 0.05)
    monkeypatch.setattr(jobs, "STALE", 0.3)
    stolen = []

    def slow(run_dir, payload):
        time.sleep(0.8)
        jobs.reclaim(tmp_path)                                     # what another worker would do meanwhile
        stolen.append(st.job_get(run_dir, payload["id"])["status"])
        return {}

    handler(monkeypatch, slow)
    run = tmp_path / "run-a"
    job = jobs.submit(run, KIND, {"id": "x"})
    st.job_update(run, job.id, {"payload": {"id": job.id}})
    assert jobs.work_once(tmp_path, "w1").status == "done" and stolen == ["running"]
    assert [w["id"] for w in jobs.alive_workers(tmp_path)] == ["w1"]


def test_job_id_cannot_point_outside_the_queue(st, tmp_path):
    assert jobs.get(tmp_path / "run-a", "../meta") is None and jobs.get(tmp_path / "run-a", "nope") is None


def test_unknown_kind_is_refused_when_queued(tmp_path):
    with pytest.raises(KeyError):
        jobs.submit(tmp_path / "run-a", "rm_rf")


def test_inline_mode_runs_the_job_inside_the_same_process(tmp_path, monkeypatch):
    monkeypatch.delenv("TRIAGE_WORKER")
    monkeypatch.delenv("TRIAGE_STORE", raising=False)
    handler(monkeypatch, lambda run_dir, payload: {"inline": True})
    assert jobs.mode() == "inline"
    run = tmp_path / "run-a"
    job = jobs.submit(run, KIND)
    assert not job.waiting_for_worker
    end = time.time() + 5
    while jobs.get(run, job.id).status in jobs.ACTIVE and time.time() < end:
        time.sleep(0.05)
    assert jobs.get(run, job.id).result == {"inline": True}
