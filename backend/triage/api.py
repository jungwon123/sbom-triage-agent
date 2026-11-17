"""FastAPI: read-only access to out/<run_id>/ for the dashboard, SSE replay of the event log."""
from __future__ import annotations

import asyncio
import json
import re

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import runner
from .__main__ import load_env

load_env()
app = FastAPI(title="SBOM Triage")
RUN_ID = re.compile(r"^[A-Za-z0-9_.-]+$")


def _run(run_id: str) -> runner.Run:
    path = runner.OUT / run_id
    if not RUN_ID.match(run_id) or not (path / "meta.json").exists():
        raise HTTPException(404, "run not found")
    return runner.Run(path)


@app.get("/api/runs")
def runs() -> list[dict]:
    out = []
    for p in sorted(runner.OUT.glob("*/meta.json"), reverse=True):
        meta = json.loads(p.read_text())
        out.append({"id": p.parent.name, "name": meta["name"], "summary": meta["summary"], "stages": meta["stages"]})
    return out


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str) -> dict:
    run = _run(run_id)
    findings = {f.id: f for f in run.findings()}
    items = [{"finding": findings[t.finding_id].model_dump(), "triage": t.model_dump()} for t in run.triage()]
    return {"id": run_id, "meta": run.meta, "items": items}


@app.get("/api/runs/{run_id}/events")
async def events(run_id: str, speed: float = 20.0) -> StreamingResponse:
    run = _run(run_id)
    path = run.dir / "events.jsonl"

    async def stream():
        prev = None
        for line in path.read_text().splitlines() if path.exists() else []:
            ts = json.loads(line).get("ts")
            if prev is not None and ts is not None:
                await asyncio.sleep(min(max(ts - prev, 0) / max(speed, 0.1), 1.0))
            prev = ts
            yield f"data: {line}\n\n"
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


_dist = runner.ROOT / "web" / "dist"
if _dist.is_dir():
    app.mount("/", StaticFiles(directory=_dist, html=True), name="web")
