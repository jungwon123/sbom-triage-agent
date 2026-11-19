"""The store interface. A run is addressed by its artifact directory; its id is the directory name."""
from __future__ import annotations

import pathlib
from typing import Any, Protocol

DOCS = ("meta", "findings", "triage")   # the three documents every run has


class Store(Protocol):
    name: str

    # ---- runs ----
    def list_runs(self, root: pathlib.Path) -> list[dict]:
        """Newest first: {"id", "name", "summary", "stages"}."""
    def has_run(self, run_dir: pathlib.Path) -> bool: ...
    def get_doc(self, run_dir: pathlib.Path, doc: str) -> Any:
        """doc is one of DOCS. Raises KeyError when the run has no such document yet."""
    def put_doc(self, run_dir: pathlib.Path, doc: str, data: Any) -> None: ...

    # ---- append-only logs ----
    def append_event(self, run_dir: pathlib.Path, event: dict) -> None: ...
    def events(self, run_dir: pathlib.Path) -> list[dict]: ...
    def append_decision(self, run_dir: pathlib.Path, decision: dict) -> None: ...
    def decisions(self, run_dir: pathlib.Path) -> list[dict]:
        """Oldest first."""

    # ---- HTTP response cache ----
    def cache_get(self, key: str) -> tuple[Any, float] | None:
        """-> (body, fetched_at as epoch seconds)."""
    def cache_put(self, key: str, url: str, body: Any) -> None: ...

    # ---- across runs ----
    def search(self, root: pathlib.Path, package: str | None = None, vuln_id: str | None = None,
               limit: int = 200) -> list[dict]:
        """Where a package or a vulnerability shows up, latest run of each service first:
        {"run_id", "run_name", "finding_id", "package", "version", "vuln_id", "final_bucket", "kev"}."""
