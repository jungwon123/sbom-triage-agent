"""FastAPI: serves runs to the dashboard, replays the event log over SSE, records the owner's
decisions on proposed changes and queues slow work. Writes go through the storage layer (decisions,
events, jobs) and to out/<run_id>/export/; the analysed repository is never touched. Slow work is
only queued here: a worker runs it (jobs.py). Who may call what is decided by auth.py: reading
needs the viewer role, deciding, exporting and re-checking a service need approver, registering a
service needs admin. With login off (the default, for the
offline demo) everything is open and the name on a decision is whatever the person typed."""
from __future__ import annotations

import asyncio
import contextlib
import json
import re
from typing import Literal

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field
from fastapi.staticfiles import StaticFiles

from . import auth, decide, jobs, runner, services, store
from .models import ServiceContext
from .__main__ import load_env

load_env()


@contextlib.asynccontextmanager
async def lifespan(_: FastAPI):
    auth.settings()                      # refuse to start with half-configured login
    if jobs.mode() == "inline":          # pick up jobs left queued by an earlier server process
        jobs.ensure_inline(runner.OUT)
    yield


app = FastAPI(title="SBOM Triage", lifespan=lifespan)
app.include_router(auth.router)
RUN_ID = re.compile(r"^[A-Za-z0-9_.-]+$")
VIEW, APPROVE, ADMIN = [Depends(auth.viewer)], [Depends(auth.approver)], [Depends(auth.admin)]


def _run(run_id: str) -> runner.Run:
    path = runner.OUT / run_id
    if not RUN_ID.match(run_id) or not store.get().has_run(path):
        raise HTTPException(404, "run not found")
    return runner.Run(path)


@app.get("/api/runs", dependencies=VIEW)
def runs() -> list[dict]:
    return store.get().list_runs(runner.OUT)


@app.get("/api/runs/{run_id}", dependencies=VIEW)
def run_detail(run_id: str) -> dict:
    run = _run(run_id)
    findings = {f.id: f for f in run.findings()}
    items = [{"finding": findings[t.finding_id].model_dump(), "triage": t.model_dump()} for t in run.triage()]
    return {"id": run_id, "meta": run.meta, "items": items}


@app.get("/api/runs/{run_id}/events", dependencies=VIEW)
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
    by: str = Field(default="", max_length=60)        # used only when login is off
    reason: str = Field(default="", max_length=600)


@app.get("/api/runs/{run_id}/proposals", dependencies=VIEW)
def proposals(run_id: str) -> list[dict]:
    return [p.model_dump() for p in decide.proposals(_run(run_id))]


@app.get("/api/runs/{run_id}/patch", response_class=PlainTextResponse, dependencies=VIEW)
def patch(run_id: str, target: str) -> str:
    text = decide.patch_text(_run(run_id), target)
    if text is None:
        raise HTTPException(404, "no patch for this proposal")
    return text


@app.post("/api/runs/{run_id}/decisions")
def decide_one(run_id: str, body: DecisionIn, user: auth.User = Depends(auth.approver)) -> dict:
    # Signed in: the decision carries the session's identity and the typed name is ignored.
    by, by_id = (body.by, None) if user.local else (user.name, user.email or user.sub)
    try:
        return decide.record(_run(run_id), body.target, body.status, by, body.reason, by_id=by_id).model_dump()
    except decide.DecisionError as e:
        raise HTTPException(422, str(e)) from e


@app.post("/api/runs/{run_id}/export", dependencies=APPROVE)
def export(run_id: str) -> dict:
    """Per-change patches and the PR draft, written at once."""
    return decide.export_view(_run(run_id), together=False)


@app.post("/api/runs/{run_id}/export/together", status_code=202)
def export_together(run_id: str, user: auth.User = Depends(auth.approver)) -> dict:
    """Queue one sandbox pass with every approved change. Poll the returned job for the result."""
    payload = {} if user.local else {"requested_by": user.email or user.sub}
    return jobs.submit(_run(run_id).dir, "export_together", payload).model_dump()


class VerifyIn(BaseModel):
    buckets: list[Literal["NOW", "NEXT", "MONITOR"]] = Field(default=["NOW"], min_length=1, max_length=3)


@app.post("/api/runs/{run_id}/verify", status_code=202, dependencies=APPROVE)
def verify_start(run_id: str, body: VerifyIn | None = None, user: auth.User = Depends(auth.approver)) -> dict:
    """Queue the sandbox verification of a run's items. The worker runs it; poll the returned job."""
    payload: dict = {"buckets": (body or VerifyIn()).buckets}
    if not user.local:
        payload["requested_by"] = user.email or user.sub
    return jobs.submit(_run(run_id).dir, "verify", payload).model_dump()


class AgentIn(BaseModel):
    scope: Literal["all", "changed", "failed"] = "all"   # changed: what a re-check reported; failed: earlier model errors
    limit: int | None = Field(default=None, ge=1, le=500)


@app.post("/api/runs/{run_id}/agent", status_code=202, dependencies=APPROVE)
def agent_start(run_id: str, body: AgentIn | None = None, user: auth.User = Depends(auth.approver)) -> dict:
    """Queue the AI judgment of a run. The worker calls the model (the API process never does); poll the job."""
    body = body or AgentIn()
    payload: dict = {"scope": body.scope}
    if body.limit:
        payload["limit"] = body.limit
    if not user.local:
        payload["requested_by"] = user.email or user.sub
    return jobs.submit(_run(run_id).dir, "agent", payload).model_dump()


@app.get("/api/runs/{run_id}/jobs/latest", dependencies=VIEW)
def latest_job(run_id: str, kind: str = "export_together") -> dict | None:
    job = jobs.latest(_run(run_id).dir, kind)
    return job.model_dump() if job else None


@app.get("/api/runs/{run_id}/jobs/{job_id}", dependencies=VIEW)
def job(run_id: str, job_id: str) -> dict:
    found = jobs.get(_run(run_id).dir, job_id)
    if found is None:
        raise HTTPException(404, "job not found")
    return found.model_dump()


class ServiceIn(BaseModel):
    id: str = Field(max_length=40)
    name: str = Field(max_length=80)
    target: str = Field(max_length=500)                # must be under TRIAGE_SERVICE_ROOTS
    owner: str | None = Field(default=None, max_length=80)
    check_hours: int | None = Field(default=24, ge=1, le=720)
    context: ServiceContext = ServiceContext()
    current_run: str | None = Field(default=None, max_length=200)


def _service_view(svc) -> dict:
    """The record plus what the list needs: the current run's summary and the check in progress, if any."""
    st, summary = store.get(), None
    if svc.current_run and RUN_ID.match(svc.current_run) and st.has_run(runner.OUT / svc.current_run):
        summary = st.get_doc(runner.OUT / svc.current_run, "meta").get("summary")
    job = services.latest_job(runner.OUT, svc.id)
    return {**svc.model_dump(), "summary": summary, "job": job.model_dump(exclude={"result", "payload"}) if job else None}


def _service(service_id: str):
    svc = services.get(runner.OUT, service_id) if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,39}", service_id) else None
    if svc is None:
        raise HTTPException(404, "service not found")
    return svc


@app.get("/api/services", dependencies=VIEW)
def service_list() -> list[dict]:
    return [_service_view(s) for s in services.list_all(runner.OUT)]


@app.post("/api/services", status_code=201, dependencies=ADMIN)
def service_add(body: ServiceIn, user: auth.User = Depends(auth.admin)) -> dict:
    """Register a service. The target is a path on the server, so this needs the admin role."""
    if body.current_run is not None and not RUN_ID.match(body.current_run):
        raise HTTPException(422, "실행 식별자가 올바르지 않습니다.")
    try:
        svc = services.register(runner.OUT, body.id, body.name, body.target, body.context, body.owner, body.check_hours,
                                created_by=None if user.local else (user.email or user.sub),
                                current_run=body.current_run, restricted=True)
    except services.ServiceError as e:
        raise HTTPException(422, str(e)) from e
    return _service_view(svc)


@app.delete("/api/services/{service_id}", dependencies=ADMIN)
def service_remove(service_id: str) -> dict:
    """Removes the registration only; the service's runs stay."""
    services.remove(runner.OUT, _service(service_id).id)
    return {"ok": True}


@app.post("/api/services/{service_id}/check", status_code=202, dependencies=APPROVE)
def service_check(service_id: str, user: auth.User = Depends(auth.approver)) -> dict:
    """Queue a re-check now (scan and compare, no model call). The service list shows the job."""
    svc = _service(service_id)
    services.submit(runner.OUT, svc.id, None if user.local else (user.email or user.sub))
    return _service_view(svc)


@app.get("/api/search", dependencies=VIEW)
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
