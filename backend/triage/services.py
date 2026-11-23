"""Registered services and automatic re-triage (HANDOFF D48).

A service is a record in the storage layer: where its repository or SBOM file is, who owns it and
how often it is re-checked. A check scans the target again (①~④, no model call), compares the
result with the service's current run and then does one of three things:

- no earlier run: the scan becomes the current run ("first").
- nothing that matters moved: no run is recorded, only the time of the check ("no_change").
- something moved: the scan is recorded as a new run, AI judgments of the unchanged findings are
  replayed from the earlier run's recorded answers (no model call), the moved and new findings keep
  the rule result until someone starts the AI step, and an alert goes out when anything is new on the
  KEV list or new in NOW or NEXT ("changed").

"Moved" means: a finding appeared or went away, its rule bucket changed, it was added to KEV, or a
fixed version was released. A score that drifts without leaving its bucket is not a change.

Checks are jobs (kind "service_check") so the API never scans by itself. Sandbox verification and
the owner's decisions belong to a run and are not carried to the new one: the lockfile the patch
was made for may be gone.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import pathlib
import time

from . import cache, jobs, notify, runner, store
from .models import BUCKET_ORDER, Change, Finding, Service, ServiceCheck, ServiceContext, Triage

log = logging.getLogger(__name__)
KIND = "service_check"
MAX_CHANGES = 200            # changes kept on the record; counts are always complete
ALERT_KINDS = ("added", "raised", "kev_added")
OSV_MAX_AGE = 3600.0         # a check asks OSV again when its cached answer is older than this (live mode only)


class ServiceError(Exception):
    """A registration or a check that cannot go ahead; the message is shown to the person."""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def scope(root: pathlib.Path, service_id: str) -> pathlib.Path:
    """Where the service's jobs are queued. The queue keys jobs by a directory name; a service is not a run."""
    return root / f"svc-{service_id}"


# ---------- registry ----------

def allowed_roots() -> list[pathlib.Path]:
    """Directories a target registered over the API must be inside (TRIAGE_SERVICE_ROOTS, os.pathsep separated)."""
    raw = os.environ.get("TRIAGE_SERVICE_ROOTS", "")
    roots = [pathlib.Path(p).expanduser() for p in raw.split(os.pathsep) if p.strip()] or [runner.ROOT / "fixtures"]
    return [r.resolve() for r in roots]


def resolve_target(text: str, restricted: bool) -> pathlib.Path:
    """A repo directory or an SBOM JSON file that exists. With `restricted` it must sit under an allowed root
    after symlinks are resolved, so a caller of the API cannot point the scanner at any directory on the host."""
    path = pathlib.Path(text).expanduser()
    if not path.is_absolute():
        path = runner.ROOT / path
    path = path.resolve()
    if not (path.is_dir() or path.is_file()):
        raise ServiceError("대상은 저장소 디렉터리이거나 입력 파일(SBOM, 스캐너 결과, lock 파일, 표)이어야 합니다.")
    if restricted and not any(path == r or r in path.parents for r in allowed_roots()):
        raise ServiceError("허용된 위치 밖의 경로입니다. TRIAGE_SERVICE_ROOTS에 등록된 디렉터리 아래만 등록할 수 있습니다.")
    return path


def get(root: pathlib.Path, service_id: str) -> Service | None:
    row = store.get().service_get(root, service_id)
    return Service.model_validate(row) if row else None


def list_all(root: pathlib.Path) -> list[Service]:
    return [Service.model_validate(r) for r in store.get().service_list(root)]


def register(root: pathlib.Path, service_id: str, name: str, target: str, context: ServiceContext | None = None,
             owner: str | None = None, check_hours: int | None = 24, created_by: str | None = None,
             current_run: str | None = None, restricted: bool = False) -> Service:
    """Add a service. `current_run` adopts an existing run (one that already has AI judgments, say) as the baseline."""
    from pydantic import ValidationError
    path = resolve_target(target, restricted)
    if current_run is not None and not store.get().has_run(root / current_run):
        raise ServiceError(f"실행 {current_run}이(가) 없습니다.")
    try:
        svc = Service(id=service_id, name=name.strip(), target=str(path), context=context or ServiceContext(),
                      owner=(owner or "").strip() or None, check_hours=check_hours, created_at=_now(),
                      created_by=created_by, current_run=current_run)
    except ValidationError as e:
        raise ServiceError("등록 값이 올바르지 않습니다: " + "; ".join(
            f"{'.'.join(str(p) for p in err['loc'])} {err['msg']}" for err in e.errors())) from e
    if not store.get().service_add(root, svc.model_dump()):
        raise ServiceError(f"이미 등록된 식별자입니다: {service_id}")
    return svc


def remove(root: pathlib.Path, service_id: str) -> bool:
    return store.get().service_delete(root, service_id)


# ---------- what changed (pure) ----------

def diff(old_findings: list[Finding], old_triage: list[Triage], new_findings: list[Finding],
         new_triage: list[Triage]) -> list[Change]:
    """Rule bucket against rule bucket: the comparison never depends on whether an AI step ran."""
    old_f, new_f = {f.id: f for f in old_findings}, {f.id: f for f in new_findings}
    old_b, new_b = {t.finding_id: t.rule_bucket for t in old_triage}, {t.finding_id: t.rule_bucket for t in new_triage}
    out: list[Change] = []

    def add(f: Finding, kind: str, before, after) -> None:
        out.append(Change(finding_id=f.id, package=f.package, version=f.version, vuln_id=f.vuln_id, kind=kind,
                          before=before, after=after, kev=f.kev))

    for fid, f in new_f.items():
        after = new_b.get(fid)
        if fid not in old_f:
            add(f, "added", None, after)
            continue
        before, was = old_b.get(fid), old_f[fid]
        if before and after and before != after:
            add(f, "raised" if BUCKET_ORDER.index(after) > BUCKET_ORDER.index(before) else "lowered", before, after)
        if f.kev and not was.kev:
            add(f, "kev_added", before, after)
        if f.fixed_in and not was.fixed_in:
            add(f, "fix_released", before, after)
    for fid, f in old_f.items():
        if fid not in new_f:
            add(f, "removed", old_b.get(fid), None)
    rank = {"kev_added": 0, "raised": 1, "added": 2, "fix_released": 3, "lowered": 4, "removed": 5}
    return sorted(out, key=lambda c: (rank[c.kind], -BUCKET_ORDER.index(c.after or c.before or "MONITOR"), c.finding_id))


def worth_alerting(changes: list[Change]) -> list[Change]:
    """New on the KEV list, or new in or raised into NOW or NEXT by rule. NEXT counts because the rule
    alone rarely says NOW: most NOW items got there through the AI step, which a check does not run."""
    return [c for c in changes if c.kind == "kev_added" or (c.kind in ALERT_KINDS and c.after in ("NOW", "NEXT"))]


# ---------- one check ----------

def _carry(base: runner.Run, run: runner.Run, keep: set[str]) -> int:
    """Replay the earlier run's recorded AI answers for findings that did not move. -> judgments reused."""
    path = base.dir / "agent_answers.json"
    if not path.exists() or not keep:
        return 0
    answers = {k: v for k, v in json.loads(path.read_text()).items() if v and k.removeprefix("code:") in keep}
    answered = {k for k in answers if not k.startswith("code:")}
    if not answered:
        return 0
    (run.dir / "agent_answers.json").write_text(json.dumps(answers, ensure_ascii=False, indent=1))
    runner.agent(run, writer="replay", code_reader="none", only=answered)
    meta = run.meta          # the answers still come from the model that wrote them
    meta["llm"] = base.meta.get("llm")
    run.write("meta.json", meta)
    return sum(t.decided_by == "agent" and t.finding_id in answered for t in run.triage())


def _alert(svc: Service, run_id: str, changes: list[Change]) -> str | None:
    hot = worth_alerting(changes)
    if not hot:
        return None
    base = os.environ.get("TRIAGE_PUBLIC_URL", "").strip().rstrip("/")
    link = f"{base}/?run={run_id}" if base else None
    sent, detail = notify.send(notify.build_change_message(svc.name, hot, len(changes), link))
    return detail if sent else f"not sent: {detail}"


def check(root: pathlib.Path, service_id: str) -> ServiceCheck:
    """Scan the service's target again and compare with its current run. Never raises for a failed scan:
    the failure is the result, recorded on the service like any other."""
    st = store.get()
    svc = get(root, service_id)
    if svc is None:
        raise ServiceError(f"등록되지 않은 서비스입니다: {service_id}")
    started, events = time.time(), []
    base = runner.Run(root / svc.current_run) if svc.current_run and st.has_run(root / svc.current_run) else None
    try:
        target = pathlib.Path(svc.target)
        if not target.exists():
            raise ServiceError(f"대상 경로가 없습니다: {svc.target}")
        # Same way of building the SBOM as the run it is compared with: Syft and the lock file parser
        # disagree on a few components, and that difference is not a change in the service.
        same_as_base = base is None or base.meta.get("sbom_source") != "lockfile"
        fresh = runner.collect(target, lambda e: events.append({"ts": round(time.time(), 3), **e}),
                               use_syft=same_as_base, osv_max_age=OSV_MAX_AGE)
        changes = diff(base.findings(), base.triage(), fresh.findings, fresh.triage) if base else []
        if base is not None and not changes:
            result = ServiceCheck(at=_now(), result="no_change", run_id=base.id, compared_to=base.id)
        else:
            run = runner.new_run(runner.safe_name(svc.id), root)
            for e in events:
                run.emit(e)
            extra = {"service": svc.id}
            if base is not None:
                extra |= {"previous_run": base.id, "changes": [c.model_dump() for c in changes[:MAX_CHANGES]]}
            runner.record(run, fresh, svc.id, svc.context, extra)
            carried, pending = 0, 0
            if base is not None:
                moved = {c.finding_id for c in changes}
                carried = _carry(base, run, {f.id for f in fresh.findings} - moved)
                pending = sum(t.finding_id in moved and t.rule_bucket in ("NOW", "NEXT") for t in run.triage())
                run.emit({"type": "service_check", "previous_run": base.id, "changes": len(changes), "carried": carried})
            counts = {k: sum(c.kind == k for c in changes) for k in sorted({c.kind for c in changes})}
            result = ServiceCheck(at=_now(), result="changed" if base else "first", run_id=run.id,
                                  compared_to=base.id if base else None, changes=changes[:MAX_CHANGES], counts=counts,
                                  carried=carried, needs_judgment=pending,
                                  notified=_alert(svc, run.id, changes) if base else None)
    except Exception as e:  # a target that cannot be scanned must not stop the other services
        log.warning("check of service %s failed: %s", service_id, e)
        result = ServiceCheck(at=_now(), result="failed", run_id=svc.current_run, compared_to=base.id if base else None,
                              error=str(e)[:500])
    result.seconds = round(time.time() - started, 1)
    st.service_update(root, service_id, {"last_check": result.model_dump(), "current_run": result.run_id})
    return result


# ---------- schedule ----------

def due(root: pathlib.Path, now: dt.datetime | None = None) -> list[Service]:
    """Services whose interval has passed since the last check. One that was never checked is due at
    once, unless it was registered with a run to start from: that run was just chosen by a person, so
    its first check waits one interval from the registration."""
    now = now or dt.datetime.now(dt.timezone.utc)
    out = []
    for svc in list_all(root):
        if svc.check_hours is None:
            continue
        last = dt.datetime.fromisoformat(svc.last_check.at) if svc.last_check else None
        if last is None and svc.current_run:
            last = dt.datetime.fromisoformat(svc.created_at)
        if last is None or now - last >= dt.timedelta(hours=svc.check_hours):
            out.append(svc)
    return out


def submit(root: pathlib.Path, service_id: str, requested_by: str | None = None):
    """Queue a check. A service that already has one queued or running gets that job back."""
    payload = {"service_id": service_id} | ({"requested_by": requested_by} if requested_by else {})
    return jobs.submit(scope(root, service_id), KIND, payload)


def submit_due(root: pathlib.Path) -> int:
    """Queue a check for every service that is due. Replay mode has nothing new to compare against."""
    if cache.replay_mode():
        return 0
    n = 0
    for svc in due(root):
        submit(root, svc.id, "schedule")
        n += 1
    return n


def latest_job(root: pathlib.Path, service_id: str):
    return jobs.latest(scope(root, service_id), KIND)
