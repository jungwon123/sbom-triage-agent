"""FastAPI: serves runs to the dashboard, replays the event log over SSE, records the owner's
decisions on proposed changes and queues slow work. Writes go through the storage layer (decisions,
events, jobs) and to out/<run_id>/export/; the analysed repository is never touched. Slow work is
only queued here: a worker runs it (jobs.py). There is no login yet: the name on a decision is
whatever the person typed."""
from __future__ import annotations

import asyncio
import contextlib
import json
import re

from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles

from . import decide, jobs, runner, store
from .__main__ import load_env

load_env()


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    if jobs.mode() == "inline":          # pick up jobs left queued by an earlier server process
        jobs.ensure_inline(runner.OUT)
    yield


app = FastAPI(title="SBOM Triage", lifespan=lifespan)
RUN_ID = re.compile(r"^[A-Za-z0-9_.-]+$")


def _run(run_id: str) -> runner.Run:
    path = runner.OUT / run_id
    if not RUN_ID.match(run_id) or not store.get().has_run(path):
        raise HTTPException(404, "run not found")
    return runner.Run(path)


@app.get("/api/runs")
def runs() -> list[dict]:
    return store.get().list_runs(runner.OUT)


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str) -> dict:
    run = _run(run_id)
    findings = {f.id: f for f in run.findings()}
    items = [{"finding": findings[t.finding_id].model_dump(), "triage": t.model_dump()} for t in run.triage()]
    return {"id": run_id, "meta": run.meta, "items": items}


@app.get("/api/runs/{run_id}/events")
async def events(run_id: str, speed: float = 20.0) -> StreamingResponse:
    rows = _run(run_id).events()

    async def stream():
        prev = None
        for event in rows:
            ts = event.get("ts")
            if prev is not None and ts is not None:
                await asyncio.sleep(min(max(ts - prev, 0) / max(speed, 0.1), 1.0))
            prev = ts
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
        yield "event: end\ndata: {}\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


class DecisionIn(BaseModel):
    target: str = Field(max_length=300)
    status: str = Field(pattern="^(approved|rejected|held)$")
    by: str = Field(max_length=60)
    reason: str = Field(default="", max_length=600)


@app.get("/api/runs/{run_id}/proposals")
def proposals(run_id: str) -> list[dict]:
    return [p.model_dump() for p in decide.proposals(_run(run_id))]


@app.get("/api/runs/{run_id}/patch", response_class=PlainTextResponse)
def patch(run_id: str, target: str) -> str:
    text = decide.patch_text(_run(run_id), target)
    if text is None:
        raise HTTPException(404, "no patch for this proposal")
    return text


@app.post("/api/runs/{run_id}/decisions")
def decide_one(run_id: str, body: DecisionIn) -> dict:
    try:
        return decide.record(_run(run_id), body.target, body.status, body.by, body.reason).model_dump()
    except decide.DecisionError as e:
        raise HTTPException(422, str(e)) from e


@app.post("/api/runs/{run_id}/export")
def export(run_id: str) -> dict:
    """Per-change patches and the PR draft, written at once."""
    return decide.export_view(_run(run_id), together=False)


@app.post("/api/runs/{run_id}/export/together", status_code=202)
def export_together(run_id: str) -> dict:
    """Queue one sandbox pass with every approved change. Poll the returned job for the result."""
    return jobs.submit(_run(run_id).dir, "export_together").model_dump()


@app.get("/api/runs/{run_id}/jobs/latest")
def latest_job(run_id: str, kind: str = "export_together") -> dict | None:
    job = jobs.latest(_run(run_id).dir, kind)
    return job.model_dump() if job else None


@app.get("/api/runs/{run_id}/jobs/{job_id}")
def job(run_id: str, job_id: str) -> dict:
    found = jobs.get(_run(run_id).dir, job_id)
    if found is None:
        raise HTTPException(404, "job not found")
    return found.model_dump()


@app.get("/api/search")
def search(package: str | None = None, vuln_id: str | None = None) -> list[dict]:
    """Which services carry this package or this vulnerability, by the latest run of each."""
    if not package and not vuln_id:
        raise HTTPException(422, "give package or vuln_id")
    return store.get().search(runner.OUT, package, vuln_id)


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "store": store.get().name, "queue": jobs.queue_state(runner.OUT)}


_dist = runner.ROOT / "web" / "dist"
if _dist.is_dir():
    app.mount("/", StaticFiles(directory=_dist, html=True), name="web")
