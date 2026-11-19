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

    def set_context(self, context: ServiceContext) -> None:
        """Owner-stated values replace earlier ones; fields left out keep what the run already has."""
        meta = self.meta
        meta["context"] = {**(meta.get("context") or {}), **context.model_dump(exclude_none=True)}
        self.write("meta.json", meta)

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
    skipped = sbom.unsupported_purls(bom)
    if skipped:
        log.warning("SBOM components not scanned (unsupported or missing purl): %s", skipped)
    run.emit({"type": "stage", "stage": "sbom", "status": "done", "source": source, "components": len(components),
              "unsupported": skipped})

    run.emit({"type": "stage", "stage": "scan", "status": "start"})
    findings, coverage = scan_mod.scan(components, repo)
    coverage["unsupported"] = skipped
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


def _llm_meta(llm, code_llm) -> dict:
    describe = lambda m: {"provider": m.name, "model": getattr(m, "model", None)} if m else None  # noqa: E731
    return {"provider": llm.name if llm else "none", "model": getattr(llm, "model", None),
            "code_reader": describe(code_llm), "mode": "two_stage" if code_llm else "single"}


def agent(run: Run, limit: int | None = None, writer: str | None = None, code_reader: str | None = None,
          tag: str = "", only: set[str] | None = None) -> Run:
    """⑤. writer "none" keeps the rule bucket. code_reader set = two-stage: only that model reads source code.

    With a tag the result goes to triage.<tag>.json and the main triage.json stays as it is (for comparisons).
    """
    findings = run.findings()
    llm = llm_mod.make(str(run.dir), writer)
    reader_name = code_reader if code_reader is not None else llm_mod.code_provider()
    code_llm = llm_mod.make(str(run.dir), reader_name) if reader_name and reader_name != "none" else None
    info = _llm_meta(llm, code_llm)
    run.emit({"type": "stage", "stage": "agent", "status": "start", "tag": tag, **info})
    triage = agent_run.run(findings, run.repo(), llm, run.dir, limit=limit, emit=run.emit, code_llm=code_llm, tag=tag,
                           only=only, context=run.meta.get("context"))
    if tag:
        run.write(f"triage.{tag}.json", [t.model_dump() for t in triage])
        run.emit({"type": "stage", "stage": "agent", "status": "done", "tag": tag, **summarize(findings, triage)})
        return run
    old = {t.finding_id: t for t in run.triage()}
    if only is not None:   # partial run: items outside `only` keep their earlier judgment
        triage = [t if t.finding_id in only or t.finding_id not in old else old[t.finding_id] for t in triage]
    for t in triage:   # keep earlier verification results
        t.verification = old[t.finding_id].verification if t.finding_id in old else None
    run.save_triage(triage)
    meta = run.meta
    meta["summary"] = summarize(findings, triage)
    meta["llm"] = info
    meta["stages"] = sorted(set(meta["stages"]) | {"agent"})
    run.write("meta.json", meta)
    run.emit({"type": "stage", "stage": "agent", "status": "done", **meta["summary"]})
    return run


def log_stats(run: Run, tag: str) -> dict:
    """Tool-call reliability of one configuration, from its agent log (matters most for small local models)."""
    path = run.dir / f"agent_log.{tag}.jsonl"
    events = [json.loads(x) for x in path.read_text().splitlines() if x.strip()] if path.exists() else []
    calls = [e for e in events if e.get("type") == "tool_call"]
    return {"llm_responses": sum(e.get("type") == "llm_response" for e in events),
            "tool_calls": len(calls), "tool_errors": sum(bool(e.get("is_error")) for e in calls),
            "contract_violations": sum(e.get("type") == "contract_violation" for e in events),
            "llm_errors": sum(e.get("type") == "llm_error" for e in events),
            "input_tokens": sum(e.get("input_tokens") or 0 for e in events),
            "output_tokens": sum(e.get("output_tokens") or 0 for e in events)}


CONFIGS = {   # name -> (writer, code reader). "api" resolves to LLM_PROVIDER from .env
    "rule": ("none", "none"),
    "api": ("api", "none"),
    "local": ("local", "none"),
    "split": ("api", "local"),
    "local_reader": ("none", "local"),
}


def compare(run: Run, names: list[str], golden: dict[str, str], limit: int | None = None) -> dict:
    """Step 4: run the agent under several LLM configurations on the same findings and score each."""
    from . import eval as eval_mod
    findings = run.findings()
    api = llm_mod.provider()
    result: dict = {}
    for name in names:
        writer, reader = CONFIGS[name]
        writer = api if writer == "api" else writer
        for stale in (f"agent_log.{name}.jsonl", f"agent_answers.{name}.json"):
            (run.dir / stale).unlink(missing_ok=True)
        started = time.time()
        try:
            agent(run, limit, writer, reader, tag=name)
        except llm_mod.LLMError as e:
            result[name] = {"error": str(e)}
            continue
        triage = [Triage.model_validate(x) for x in run.read(f"triage.{name}.json")]
        ev = eval_mod.evaluate(findings, triage, golden)
        row = {"writer": writer, "code_reader": reader,
               "judged": sum(t.decided_by == "agent" for t in triage),
               "fell_back": sum(t.decided_by == "agent_fallback" for t in triage),
               "reachability": {k: sum(t.reachability == k and t.decided_by != "rule" for t in triage)
                                for k in ("used_symbol", "imported_only", "unused", "unknown")},
               "moved": sum(t.final_bucket != t.rule_bucket for t in triage),
               "buckets": summarize(findings, triage)["final"],
               "seconds": round(time.time() - started, 1), **log_stats(run, name)}
        if ev.get("matched"):
            row.update(agreement_pct=ev["rule_plus_agent"]["agreement_pct"],
                       now_missed=len(ev["rule_plus_agent"]["now_missed"]), matched=ev["matched"])
        else:
            row["agreement_pct"] = None
        result[name] = row
    run.write("compare.json", result)
    return result


def verify(run: Run, setup_cmd: str | None = None, buckets: tuple[str, ...] = ("NOW",)) -> Run:
    """⑥ NOW items by default. Skipped in replay mode (recorded results stay)."""
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
    triage = verify_run.run(repo, findings, triage, run.dir, setup_cmd, revise, run.emit, buckets)
    run.save_triage(triage)
    meta = run.meta
    meta["summary"] = summarize(findings, triage)
    meta["stages"] = sorted(set(meta["stages"]) | {"verify"})
    meta["verify_setup"] = setup_cmd   # the combined check on export reuses it
    run.write("meta.json", meta)
    run.emit({"type": "stage", "stage": "verify", "status": "done", **meta["summary"]})
    return run
