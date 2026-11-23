"""File store: the layout the project started with. One directory per run, one JSON file per cached response."""
from __future__ import annotations

import contextlib
import json
import pathlib
import time
from typing import Any

ROOT = pathlib.Path(__file__).resolve().parents[3]


def cache_dir() -> pathlib.Path:
    from .. import cache          # late import: cache.py uses the store
    return cache.CACHE_DIR


class FileStore:
    name = "file"

    def list_runs(self, root: pathlib.Path) -> list[dict]:
        out = []
        for p in sorted(root.glob("*/meta.json"), reverse=True):
            meta = json.loads(p.read_text())
            out.append({"id": p.parent.name, "name": meta.get("name"), "summary": meta.get("summary"),
                        "stages": meta.get("stages", [])})
        return out

    def has_run(self, run_dir: pathlib.Path) -> bool:
        return (run_dir / "meta.json").exists()

    def get_doc(self, run_dir: pathlib.Path, doc: str) -> Any:
        path = run_dir / f"{doc}.json"
        if not path.exists():
            raise KeyError(f"{run_dir.name} has no {doc}")
        return json.loads(path.read_text())

    def put_doc(self, run_dir: pathlib.Path, doc: str, data: Any) -> None:
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / f"{doc}.json").write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str))

    def _append(self, path: pathlib.Path, row: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a") as fh:
            fh.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

    def _lines(self, path: pathlib.Path) -> list[dict]:
        return [json.loads(x) for x in path.read_text().splitlines() if x.strip()] if path.exists() else []

    def append_event(self, run_dir: pathlib.Path, event: dict) -> None:
        self._append(run_dir / "events.jsonl", event)

    def events(self, run_dir: pathlib.Path) -> list[dict]:
        return self._lines(run_dir / "events.jsonl")

    def append_decision(self, run_dir: pathlib.Path, decision: dict) -> None:
        self._append(run_dir / "decisions.jsonl", decision)

    def decisions(self, run_dir: pathlib.Path) -> list[dict]:
        return self._lines(run_dir / "decisions.jsonl")

    def cache_get(self, key: str) -> tuple[Any, float] | None:
        path = cache_dir() / f"{key}.json"
        if not path.exists():
            return None
        return json.loads(path.read_text()), path.stat().st_mtime

    def cache_put(self, key: str, url: str, body: Any) -> None:
        cache_dir().mkdir(parents=True, exist_ok=True)
        (cache_dir() / f"{key}.json").write_text(json.dumps(body))

    # ---- work queue: one file per job under <run>/jobs/, one lock file for the whole queue ----
    @contextlib.contextmanager
    def _queue_lock(self, root: pathlib.Path):
        """Exclusive across threads and processes on this machine (flock)."""
        root.mkdir(parents=True, exist_ok=True)
        with (root / ".jobs.lock").open("w") as fh:
            try:
                import fcntl
                fcntl.flock(fh, fcntl.LOCK_EX)
            except ImportError:           # no flock on this platform: single process only
                pass
            yield

    def _job_write(self, run_dir: pathlib.Path, job: dict) -> None:
        path = run_dir / "jobs" / f"{job['id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(job, ensure_ascii=False, indent=1))
        tmp.replace(path)                 # readers never see a half-written file

    def _jobs(self, paths) -> list[dict]:
        return sorted((json.loads(p.read_text()) for p in paths), key=lambda j: j.get("seq", 0))

    def job_add(self, run_dir: pathlib.Path, job: dict) -> dict:
        with self._queue_lock(run_dir.parent):
            for j in self._jobs((run_dir / "jobs").glob("*.json")):
                if j["kind"] == job["kind"] and j["status"] in ("queued", "running"):
                    return j
            job = {**job, "seq": time.time_ns()}
            self._job_write(run_dir, job)
            return job

    def job_get(self, run_dir: pathlib.Path, job_id: str) -> dict | None:
        path = run_dir / "jobs" / f"{job_id}.json"
        return json.loads(path.read_text()) if path.is_file() else None

    def job_latest(self, run_dir: pathlib.Path, kind: str) -> dict | None:
        jobs = [j for j in self._jobs((run_dir / "jobs").glob("*.json")) if j["kind"] == kind]
        return jobs[-1] if jobs else None

    def job_claim(self, root: pathlib.Path, patch: dict) -> dict | None:
        with self._queue_lock(root):
            queued = [j for j in self._jobs(root.glob("*/jobs/*.json")) if j["status"] == "queued"]
            if not queued:
                return None
            job = {**queued[0], **patch, "status": "running", "attempts": queued[0].get("attempts", 0) + 1}
            self._job_write(root / job["run_id"], job)
            return job

    def job_update(self, run_dir: pathlib.Path, job_id: str, patch: dict, worker: str | None = None) -> bool:
        with self._queue_lock(run_dir.parent):
            job = self.job_get(run_dir, job_id)
            if job is None or (worker is not None and (job["status"] != "running" or job.get("worker") != worker)):
                return False
            self._job_write(run_dir, {**job, **patch})
            return True

    def job_list(self, root: pathlib.Path, statuses: tuple[str, ...]) -> list[dict]:
        return [j for j in self._jobs(root.glob("*/jobs/*.json")) if j["status"] in statuses]

    def worker_beat(self, root: pathlib.Path, worker: dict) -> None:
        path = root / ".workers" / f"{worker['id']}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(worker))
        tmp.replace(path)
        for old in path.parent.glob("*.json"):            # workers gone for a day
            if old.stat().st_mtime < time.time() - 86400:
                old.unlink(missing_ok=True)

    def workers(self, root: pathlib.Path) -> list[dict]:
        return [json.loads(p.read_text()) for p in (root / ".workers").glob("*.json")]

    # ---- registered services: one file each under <root>/.services/ ----
    def _service_path(self, root: pathlib.Path, service_id: str) -> pathlib.Path:
        return root / ".services" / f"svc-{service_id}.json"

    def _service_write(self, root: pathlib.Path, service: dict) -> None:
        path = self._service_path(root, service["id"])
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(service, ensure_ascii=False, indent=1))
        tmp.replace(path)

    def service_add(self, root: pathlib.Path, service: dict) -> bool:
        with self._queue_lock(root):
            if self._service_path(root, service["id"]).exists():
                return False
            self._service_write(root, service)
            return True

    def service_get(self, root: pathlib.Path, service_id: str) -> dict | None:
        path = self._service_path(root, service_id)
        return json.loads(path.read_text()) if path.is_file() else None

    def service_list(self, root: pathlib.Path) -> list[dict]:
        rows = [json.loads(p.read_text()) for p in (root / ".services").glob("svc-*.json")]
        return sorted(rows, key=lambda r: r["id"])

    def service_update(self, root: pathlib.Path, service_id: str, patch: dict) -> dict | None:
        with self._queue_lock(root):
            service = self.service_get(root, service_id)
            if service is None:
                return None
            service = {**service, **patch}
            self._service_write(root, service)
            return service

    def service_delete(self, root: pathlib.Path, service_id: str) -> bool:
        with self._queue_lock(root):
            path = self._service_path(root, service_id)
            if not path.exists():
                return False
            path.unlink()
            return True

    def search(self, root: pathlib.Path, package: str | None = None, vuln_id: str | None = None,
               limit: int = 200) -> list[dict]:
        """Reads every run from disk: fine for a laptop, the reason the operating store is a database."""
        out, seen = [], set()
        for run in self.list_runs(root):
            if run["name"] in seen:          # latest run of each service only
                continue
            seen.add(run["name"])
            run_dir = root / run["id"]
            try:
                findings, triage = self.get_doc(run_dir, "findings"), self.get_doc(run_dir, "triage")
            except KeyError:
                continue
            buckets = {t["finding_id"]: t["final_bucket"] for t in triage}
            for f in findings:
                ids = {f["vuln_id"], *f.get("aliases", [])}
                if (package and f["package"].lower() != package.lower()) or (vuln_id and vuln_id not in ids):
                    continue
                out.append({"run_id": run["id"], "run_name": run["name"], "finding_id": f["id"], "package": f["package"],
                            "version": f["version"], "vuln_id": f["vuln_id"], "final_bucket": buckets.get(f["id"]),
                            "kev": f["kev"]})
                if len(out) >= limit:
                    return out
        return out
