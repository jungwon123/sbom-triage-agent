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


def test_one_failed_heartbeat_does_not_stop_the_next_ones(tmp_path, monkeypatch):
    """Critique 3, 2-3: the heartbeat thread used to end at its first error."""
    from triage import store
    from triage.store.files import FileStore
    st, beats, broken = FileStore(), [], []
    store.use(st)
    real = st.job_update

    def flaky(run_dir, job_id, patch, worker=None):
        if set(patch) == {"heartbeat"}:
            beats.append(patch["heartbeat"])
            if len(beats) == 2:
                broken.append(1)
                raise OSError("store away for a moment")
        return real(run_dir, job_id, patch, worker=worker)

    monkeypatch.setattr(st, "job_update", flaky)
    monkeypatch.setattr(jobs, "BEAT", 0.05)
    monkeypatch.setitem(jobs.HANDLERS, "export_together", lambda run_dir, payload: time.sleep(0.5) or {})
    try:
        jobs.submit(tmp_path / "r1", "export_together")
        done = jobs.work_once(tmp_path, "w1", st)
    finally:
        store.use(None)
    assert broken and len(beats) >= 5 and done.status == "done"


def test_result_is_kept_when_the_database_connections_die_during_the_job(tmp_path, monkeypatch):
    """Critique 3, 2-3: every connection is cut while the handler runs; the job must still end done, once."""
    from tests.test_store import postgres
    from triage import store
    pg, ran = postgres(), []
    store.use(pg)

    def handler(run_dir, payload):
        ran.append(1)
        with pg.connection() as conn:     # cut every other connection of this user, as a failover would
            conn.execute("SELECT pg_terminate_backend(pid) FROM pg_stat_activity"
                         " WHERE usename = current_user AND datname = current_database() AND pid <> pg_backend_pid()")
        return {"ok": True}

    monkeypatch.setitem(jobs.HANDLERS, "export_together", handler)
    monkeypatch.setattr(jobs, "RESULT_RETRY", (0.05, 0.05))
    try:
        jobs.submit(tmp_path / "r1", "export_together")
        done = jobs.work_once(tmp_path, "w1", pg)
        assert done.status == "done" and done.attempts == 1 and ran == [1]
    finally:
        store.use(None)
        pg.close()


def test_tables_can_be_created_by_several_processes_at_once():
    """Critique 3, 2-6: CREATE TABLE IF NOT EXISTS alone fails when two callers race."""
    pytest.importorskip("psycopg", reason="needs the postgres extra: uv sync --extra postgres")
    from tests.test_store import TEST_URL, postgres
    from triage.store.postgres import PostgresStore
    postgres().close()
    name = "triage_race"
    with __import__("psycopg").connect(TEST_URL, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {name} CASCADE")
    stores, errors = [PostgresStore(TEST_URL, schema=name) for _ in range(4)], []
    for s in stores:
        with s.connection():      # connect first so the four init() calls really overlap
            pass
    gate = threading.Barrier(4)

    def go(s):
        gate.wait()
        try:
            s.init()
        except Exception as e:
            errors.append(repr(e))

    threads = [threading.Thread(target=go, args=(s,)) for s in stores]
    [t.start() for t in threads]
    [t.join() for t in threads]
    for s in stores:
        s.close()
    with __import__("psycopg").connect(TEST_URL, autocommit=True) as conn:
        conn.execute(f"DROP SCHEMA IF EXISTS {name} CASCADE")
    assert errors == []


def test_verify_is_a_queued_job_and_reports_why_it_was_skipped(st, tmp_path, monkeypatch, make_finding):
    """Critique 3, 2-1: the dashboard starts verification through the queue."""
    from triage import runner
    monkeypatch.setenv("DEMO_MODE", "replay")
    run = runner.Run(tmp_path / "r1")
    run.dir.mkdir(exist_ok=True)
    st.put_doc(run.dir, "meta", {"name": "r1", "summary": {}, "stages": []})
    st.put_doc(run.dir, "findings", [])
    st.put_doc(run.dir, "triage", [])
    jobs.submit(run.dir, "verify", {"buckets": ["NOW"]})
    done = jobs.work_once(tmp_path, "w1", st)
    assert done.status == "done" and done.result["skipped"] == "replay mode"


def _empty_run(st, tmp_path, meta=None):
    from triage import runner
    run = runner.Run(tmp_path / "r1")
    run.dir.mkdir(exist_ok=True)
    st.put_doc(run.dir, "meta", {"name": "r1", "summary": {}, "stages": [], **(meta or {})})
    st.put_doc(run.dir, "findings", [])
    st.put_doc(run.dir, "triage", [])
    return run


@pytest.mark.parametrize("env,payload,why", [
    ({"DEMO_MODE": "replay", "LLM_PROVIDER": "anthropic"}, {"scope": "all"}, "replay mode"),
    ({"DEMO_MODE": "live", "LLM_PROVIDER": "none"}, {"scope": "all"}, "no model"),
    ({"DEMO_MODE": "live", "LLM_PROVIDER": "anthropic"}, {"scope": "changed"}, "nothing to judge"),
])
def test_agent_job_is_skipped_with_a_reason_instead_of_falling_back_to_rules(st, tmp_path, monkeypatch, env, payload, why):
    """Without a model the job must not run rule-only: that would overwrite earlier AI judgments."""
    from triage import runner
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(runner, "agent", lambda *a, **k: pytest.fail("the model step must not start"))
    run = _empty_run(st, tmp_path)
    jobs.submit(run.dir, "agent", payload)
    done = jobs.work_once(tmp_path, "w1", st)
    assert done.status == "done" and done.result["skipped"] == why and done.result["judged"] == 0


def test_agent_job_passes_scope_and_limit_as_values(st, tmp_path, monkeypatch):
    from triage import runner
    monkeypatch.setenv("DEMO_MODE", "live")
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")
    seen = {}

    def fake(run, limit=None, only=None, **kw):
        seen.update(limit=limit, only=only)
        return run
    monkeypatch.setattr(runner, "agent", fake)
    run = _empty_run(st, tmp_path, {"changes": [{"finding_id": "a", "kind": "added"}, {"finding_id": "b", "kind": "removed"}]})
    jobs.submit(run.dir, "agent", {"scope": "changed", "limit": 5})
    done = jobs.work_once(tmp_path, "w1", st)
    assert done.status == "done" and done.result["skipped"] is None
    assert seen == {"limit": 5, "only": {"a"}}


@pytest.fixture
def slack(monkeypatch):
    """Records what the worker would send, without a network call."""
    from triage import notify
    sent = []
    monkeypatch.setenv("DEMO_MODE", "live")
    monkeypatch.setattr(notify, "send", lambda payload, dry_run=False: (sent.append(payload), (True, "http 200"))[1])
    return sent


def test_a_finished_job_is_announced_once(st, tmp_path, monkeypatch, slack):
    handler(monkeypatch, lambda run_dir, payload: {"approved": 1, "combined": None, "combined_skipped": "docker unavailable"})
    run = _empty_run(st, tmp_path, {"name": "shop"})
    jobs.submit(run.dir, KIND)
    done = jobs.work_once(tmp_path, "w1", st)
    assert done.status == "done" and len(slack) == 1
    assert "shop" in slack[0]["text"] and "승인분 함께 검증" in slack[0]["text"]
    assert jobs.work_once(tmp_path, "w1", st) is None and len(slack) == 1


def test_a_failed_job_is_announced_without_its_error_text(st, tmp_path, monkeypatch, slack):
    def boom(run_dir, payload):
        raise RuntimeError("docker exploded at /repos/shop/secret.ts")
    handler(monkeypatch, boom)
    run = _empty_run(st, tmp_path, {"name": "shop"})
    jobs.submit(run.dir, KIND)
    assert jobs.work_once(tmp_path, "w1", st).status == "failed"
    assert len(slack) == 1 and "실패" in slack[0]["text"] and "secret.ts" not in str(slack[0])


def test_a_broken_alert_does_not_change_the_job(st, tmp_path, monkeypatch):
    from triage import notify
    monkeypatch.setenv("DEMO_MODE", "live")

    def broken(payload, dry_run=False):
        raise RuntimeError("slack is down")
    monkeypatch.setattr(notify, "send", broken)
    handler(monkeypatch, lambda run_dir, payload: {"approved": 0, "combined": None, "combined_skipped": None})
    run = _empty_run(st, tmp_path)
    jobs.submit(run.dir, KIND)
    done = jobs.work_once(tmp_path, "w1", st)
    assert done.status == "done" and done.result["approved"] == 0


def test_job_alerts_can_be_turned_off_and_skip_a_clean_service_check(st, tmp_path, monkeypatch, slack):
    handler(monkeypatch, lambda run_dir, payload: {"approved": 0, "combined": None, "combined_skipped": None})
    monkeypatch.setenv("TRIAGE_NOTIFY_JOBS", "off")
    run = _empty_run(st, tmp_path)
    jobs.submit(run.dir, KIND)
    assert jobs.work_once(tmp_path, "w1", st).status == "done" and slack == []
    monkeypatch.setenv("TRIAGE_NOTIFY_JOBS", "on")
    monkeypatch.setitem(jobs.HANDLERS, "service_check", lambda run_dir, payload: {"result": "no_change"})
    jobs.submit(tmp_path / "svc-shop", "service_check", {"service_id": "shop"})
    assert jobs.work_once(tmp_path, "w1", st).status == "done" and slack == []   # the re-check sends its own alert


def test_a_job_cut_off_twice_is_announced_by_the_worker_only(st, tmp_path, monkeypatch, slack):
    handler(monkeypatch, lambda run_dir, payload: {})
    run = _empty_run(st, tmp_path, {"name": "shop"})
    job = jobs.submit(run.dir, KIND)
    st.job_update(run.dir, job.id, {"status": "running", "worker": "dead", "attempts": jobs.MAX_ATTEMPTS, "heartbeat": time.time() - 999})
    assert jobs.get(run.dir, job.id).status == "interrupted" and slack == []      # the API reading it sends nothing
    job2 = jobs.submit(run.dir, KIND)
    st.job_update(run.dir, job2.id, {"status": "running", "worker": "dead", "attempts": jobs.MAX_ATTEMPTS, "heartbeat": time.time() - 999})
    assert jobs.work_once(tmp_path, "w1", st) is None
    assert len(slack) == 1 and "중단" in slack[0]["text"]
