"""Stage order and event log, shared by the CLI and the API (CLAUDE.md §3).

out/<run_id>/: sbom.cdx.json, findings.json, triage.json, meta.json, events.jsonl, agent_log.jsonl, verify/
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import pathlib
import re
import time

from . import cache, sbom, scan as scan_mod, score
from .agent import llm as llm_mod, run as agent_run
from .models import Finding, ServiceContext, Triage
from .verify import run as verify_run, sandbox

log = logging.getLogger(__name__)
ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "out"


class Run:
    def __init__(self, run_dir: pathlib.Path):
        self.dir = run_dir.resolve()
        self.dir.mkdir(parents=True, exist_ok=True)

    def emit(self, event: dict) -> None:
        event = {"ts": round(time.time(), 3), **event}
        with (self.dir / "events.jsonl").open("a") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")

    def write(self, name: str, data) -> None:
        (self.dir / name).write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str))

    def read(self, name: str):
        return json.loads((self.dir / name).read_text())

    @property
    def meta(self) -> dict:
        return self.read("meta.json")

    def findings(self) -> list[Finding]:
        return [Finding.model_validate(x) for x in self.read("findings.json")]

    def triage(self) -> list[Triage]:
        return [Triage.model_validate(x) for x in self.read("triage.json")]

    def save_triage(self, items: list[Triage]) -> None:
        self.write("triage.json", [t.model_dump() for t in items])

    def repo(self) -> pathlib.Path | None:
        p = self.meta.get("repo")
        return pathlib.Path(p) if p and pathlib.Path(p).is_dir() else None


def summarize(findings: list[Finding], triage: list[Triage]) -> dict:
    count = lambda key: {b: sum(getattr(t, key) == b for t in triage) for b in ("NOW", "NEXT", "MONITOR")}  # noqa: E731
    return {"findings": len(findings), "cvss_ge_7": sum((f.cvss or 0) >= 7 for f in findings),
            "rule": count("rule_bucket"), "final": count("final_bucket"),
            "needs_review": sum(t.needs_review for t in triage),
            "verified": sum(bool(t.verification and t.verification.verdict == "verified") for t in triage)}


def scan(target: pathlib.Path, name: str | None = None, context: ServiceContext | None = None,
         use_syft: bool = True) -> Run:
    """①~④. target is a repo directory or an SBOM file (CycloneDX / SPDX JSON)."""
    target = target.resolve()
    name = name or re.sub(r"[^A-Za-z0-9_.-]", "_", target.stem if target.is_file() else target.name)
    run = Run(OUT / f"{dt.datetime.now():%Y%m%d-%H%M%S}-{name}")
    start = time.time()
    run.emit({"type": "stage", "stage": "sbom", "status": "start"})
    if target.is_file():
        bom, source = sbom.load_file(target)
        repo = None
    else:
        bom, source = sbom.generate(target, use_syft=use_syft and not cache.replay_mode())
        repo = target
    run.write("sbom.cdx.json", bom)
    components = sbom.components_from_cyclonedx(bom)
    run.emit({"type": "stage", "stage": "sbom", "status": "done", "source": source, "components": len(components)})

    run.emit({"type": "stage", "stage": "scan", "status": "start"})
    findings, coverage = scan_mod.scan(components, repo)
    run.write("findings.json", [f.model_dump() for f in findings])
    run.emit({"type": "stage", "stage": "scan", "status": "done", **coverage})

    triage = agent_run.run(findings, repo, None, run.dir)   # rule only
    run.save_triage(triage)
    meta = {"name": name, "target": str(target), "repo": str(repo) if repo else None, "sbom_source": source,
            "coverage": coverage, "context": (context or ServiceContext()).model_dump(),
            "seconds": round(time.time() - start, 1), "summary": summarize(findings, triage),
            "stages": ["sbom", "scan", "score"]}
    run.write("meta.json", meta)
    run.emit({"type": "stage", "stage": "score", "status": "done", **meta["summary"]})
    return run


def agent(run: Run, limit: int | None = None) -> Run:
    """⑤. LLM_PROVIDER=none keeps the rule result."""
    findings = run.findings()
    llm = llm_mod.make(str(run.dir))
    run.emit({"type": "stage", "stage": "agent", "status": "start", "provider": llm.name if llm else "none"})
    triage = agent_run.run(findings, run.repo(), llm, run.dir, limit=limit, emit=run.emit)
    old = {t.finding_id: t for t in run.triage()}
    for t in triage:   # keep earlier verification results
        t.verification = old[t.finding_id].verification if t.finding_id in old else None
    run.save_triage(triage)
    meta = run.meta
    meta["summary"] = summarize(findings, triage)
    meta["llm"] = {"provider": llm.name if llm else "none", "model": getattr(llm, "model", None)}
    meta["stages"] = sorted(set(meta["stages"]) | {"agent"})
    run.write("meta.json", meta)
    run.emit({"type": "stage", "stage": "agent", "status": "done", **meta["summary"]})
    return run


def verify(run: Run, setup_cmd: str | None = None) -> Run:
    """⑥ NOW items only. Skipped in replay mode (recorded results stay)."""
    findings, triage, repo = run.findings(), run.triage(), run.repo()
    if cache.replay_mode():
        run.emit({"type": "stage", "stage": "verify", "status": "skipped", "why": "replay mode"})
        return run
    if repo is None or not sandbox.available():
        run.emit({"type": "stage", "stage": "verify", "status": "skipped",
                  "why": "no repo" if repo is None else "docker unavailable"})
        return run
    run.emit({"type": "stage", "stage": "verify", "status": "start"})
    llm = llm_mod.make(str(run.dir)) if llm_mod.provider() not in ("none", "replay") else None

    def agent_log(event: dict) -> None:
        with (run.dir / "agent_log.jsonl").open("a") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")

    revise = (lambda f, prev, steps: agent_run.revise(llm, f, prev, steps, agent_log)) if llm else None
    triage = verify_run.run(repo, findings, triage, run.dir, setup_cmd, revise, run.emit)
    run.save_triage(triage)
    meta = run.meta
    meta["summary"] = summarize(findings, triage)
    meta["stages"] = sorted(set(meta["stages"]) | {"verify"})
    run.write("meta.json", meta)
    run.emit({"type": "stage", "stage": "verify", "status": "done", **meta["summary"]})
    return run
