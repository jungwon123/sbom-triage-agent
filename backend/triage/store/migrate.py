"""Copy what the file store holds into PostgreSQL (`triage db import`). Reading only on the file side."""
from __future__ import annotations

import pathlib

from .files import FileStore, cache_dir
from .postgres import PostgresStore


def import_run(src: FileStore, dst: PostgresStore, run_dir: pathlib.Path) -> dict:
    """Replace the run's rows with the file copy. Events and decisions are re-inserted in order."""
    if not src.has_run(run_dir):
        raise FileNotFoundError(f"{run_dir} has no meta.json")
    with dst.connection() as conn, conn.transaction():
        conn.execute("DELETE FROM runs WHERE id = %s", (run_dir.name,))     # cascades to the run's rows
    counts = {}
    for doc in ("meta", "findings", "triage"):
        try:
            data = src.get_doc(run_dir, doc)
        except KeyError:
            continue
        dst.put_doc(run_dir, doc, data)
        counts[doc] = len(data) if isinstance(data, list) else 1
    for name, rows, put in (("events", src.events(run_dir), dst.append_event),
                            ("decisions", src.decisions(run_dir), dst.append_decision)):
        for row in rows:
            put(run_dir, row)
        counts[name] = len(rows)
    return counts


def import_cache(dst: PostgresStore) -> int:
    """Seed the HTTP cache from fixtures/cache so replay works on the database too. Keys are the file names."""
    import json
    n = 0
    for path in sorted(cache_dir().glob("*.json")):
        dst.cache_put(path.stem, "imported:" + path.stem, json.loads(path.read_text()), path.stat().st_mtime)
        n += 1
    return n
