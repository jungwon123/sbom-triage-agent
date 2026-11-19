"""File store: the layout the project started with. One directory per run, one JSON file per cached response."""
from __future__ import annotations

import json
import pathlib
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
