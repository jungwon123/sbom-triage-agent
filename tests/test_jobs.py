"""Work queue for slow steps: one at a time, state on disk, cut-off jobs are reported as such."""
import threading
import time

from triage import jobs


def wait(run_dir, job_id, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        j = jobs.get(run_dir, job_id)
        if j.status not in jobs.ACTIVE:
            return j
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_job_runs_and_keeps_its_result(tmp_path):
    job = jobs.submit(tmp_path, "export_together", lambda: {"files": ["combined.patch"]})
    done = wait(tmp_path, job.id)
    assert done.status == "done" and done.result == {"files": ["combined.patch"]} and done.finished_at
    assert jobs.latest(tmp_path, "export_together").id == job.id


def test_failure_is_recorded_and_the_worker_survives(tmp_path):
    def boom():
        raise RuntimeError("docker exploded")
    bad = wait(tmp_path, jobs.submit(tmp_path, "export_together", boom).id)
    assert bad.status == "failed" and "docker exploded" in bad.error
    ok = wait(tmp_path, jobs.submit(tmp_path, "export_together", lambda: {}).id)
    assert ok.status == "done"


def test_same_run_gets_the_running_job_instead_of_a_second_one(tmp_path):
    gate, calls = threading.Event(), []

    def slow():
        calls.append(1)
        gate.wait(5)
        return {}

    first = jobs.submit(tmp_path, "export_together", slow)
    second = jobs.submit(tmp_path, "export_together", slow)
    gate.set()
    wait(tmp_path, first.id)
    assert second.id == first.id and calls == [1]


def test_jobs_of_two_runs_run_one_after_the_other(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir(); b.mkdir()
    gate, running = threading.Event(), []

    def work(name):
        def f():
            running.append(name)
            gate.wait(5)
            return {}
        return f

    ja, jb = jobs.submit(a, "export_together", work("a")), jobs.submit(b, "export_together", work("b"))
    time.sleep(0.2)
    assert running == ["a"] and jobs.get(b, jb.id).status == "queued" and jb.position == 1
    gate.set()
    wait(a, ja.id); wait(b, jb.id)
    assert running == ["a", "b"]


def test_job_from_an_earlier_server_process_is_interrupted(tmp_path, monkeypatch):
    gate = threading.Event()
    job = jobs.submit(tmp_path, "export_together", lambda: (gate.wait(5), {})[1])
    time.sleep(0.1)
    monkeypatch.setattr(jobs, "BOOT", "another-process")
    seen = jobs.get(tmp_path, job.id)
    assert seen.status == "interrupted" and "다시 실행" in seen.error
    gate.set()


def test_job_id_cannot_point_outside_the_jobs_folder(tmp_path):
    assert jobs.get(tmp_path, "../meta") is None and jobs.get(tmp_path, "nope") is None
