"""Where the service keeps its records (HANDOFF D45).

Two implementations behind one interface:
- "file": JSON files under out/<run_id>/ and fixtures/cache/. No server needed; this is what the
  offline demo and the tests use.
- "postgres": the operating store. Runs, findings, triage, decisions, events and the HTTP cache are
  rows that can be queried across runs and written by several processes at once.

Large artifacts (SBOM file, agent logs, patches, exports) stay on the artifact volume out/<run_id>/
in both modes; the database holds what people and other services query.

TRIAGE_STORE=file|postgres picks one (default file). postgres needs DATABASE_URL.
"""
from __future__ import annotations

import os

from . import base
from .base import Store

_store: Store | None = None


def kind() -> str:
    return os.environ.get("TRIAGE_STORE", "file").lower()


def get() -> Store:
    global _store
    if _store is None:
        if kind() == "postgres":
            from .postgres import PostgresStore
            url = os.environ.get("DATABASE_URL")
            if not url:
                raise RuntimeError("TRIAGE_STORE=postgres needs DATABASE_URL")
            _store = PostgresStore(url)
        elif kind() == "file":
            from .files import FileStore
            _store = FileStore()
        else:
            raise RuntimeError(f"unknown TRIAGE_STORE {kind()}")
    return _store


def use(store: Store | None) -> None:
    """Swap the store (tests, the import command). None resets to the environment's choice."""
    global _store
    _store = store
