"""Stage order and event log, shared by the CLI and the API (CLAUDE.md §3).

out/<run_id>/: sbom.cdx.json, findings.json, triage.json, meta.json, events.jsonl, agent_log.jsonl, verify/
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import json
import logging
import pathlib
import re
import time
from collections.abc import Callable

from . import cache, sbom, scan as scan_mod, score, store
from .agent import llm as llm_mod, run as agent_run
from .enrich import kev as kev_mod
from .models import Finding, ServiceContext, Triage
from .verify import run as verify_run, sandbox

log = logging.getLogger(__name__)
ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT = ROOT / "out"


class Run:
    def __init__(self, run_dir: pathlib.Path):
        self.dir = run_dir.resolve()
        self.dir.mkdir(parents=True, exist_ok=True)

    @property
    def id(self) -> str:
        return self.dir.name

    def emit(self, event: dict) -> None:
        event = json.loads(json.dumps({"ts": round(time.time(), 3), **event}, ensure_ascii=False, default=str))
        store.get().append_event(self.dir, event)

    def events(self) -> list[dict]:
        return store.get().events(self.dir)

    def write(self, name: str, data) -> None:
        """meta, findings and triage are records and go to the store; anything else is an artifact file."""
        doc = name.removesuffix(".json")
        if doc in store.base.DOCS:
            store.get().put_doc(self.dir, doc, json.loads(json.dumps(data, ensure_ascii=False, default=str)))
        else:
            (self.dir / name).write_text(json.dumps(data, ensure_ascii=False, indent=1, default=str))

    def read(self, name: str):
        doc = name.removesuffix(".json")
        if doc in store.base.DOCS:
            return store.get().get_doc(self.dir, doc)
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


@dataclasses.dataclass
class Scanned:
    """What ①~④ produce before anything is recorded (services.py decides whether it becomes a run)."""
    target: pathlib.Path
    repo: pathlib.Path | None
    bom: dict
    source: str
    findings: list[Finding]
    triage: list[Triage]            # rule only
    coverage: dict
    seconds: float


def collect(target: pathlib.Path, emit: Callable[[dict], None], use_syft: bool = True,
            columns: dict[str, str] | None = None, ecosystem: str | None = None,
            osv_max_age: float | None = None) -> Scanned:
    """①~④ without recording a run. target is a repo directory or an input file (SBOM, scanner result,
    lock file, table). osv_max_age: see scan.scan."""
    target = target.resolve()
    start = time.time()
    emit({"type": "stage", "stage": "sbom", "status": "start"})
    notes: list[str] = []
    if target.is_file():
        bom, source, notes = sbom.load_file_notes(target, columns, ecosystem)
        repo = None
    else:
        bom, source = sbom.generate(target, use_syft=use_syft and not cache.replay_mode())
        repo = target
        from . import ingest
        notes = ingest.repo_components(target)[1]   # which dependency files were read and what they lack
    components = sbom.components_from_cyclonedx(bom)
    skipped = sbom.unsupported_purls(bom)
    if skipped:
        log.warning("SBOM components not scanned (unsupported or missing purl): %s", skipped)
    emit({"type": "stage", "stage": "sbom", "status": "done", "source": source, "components": len(components),
          "unsupported": skipped})

    emit({"type": "stage", "stage": "scan", "status": "start"})
    findings, coverage = scan_mod.scan(components, repo, osv_max_age)
    coverage["unsupported"] = skipped
    coverage["kev_list"] = kev_mod.version()
    if notes:
        coverage["input_notes"] = notes        # what the input file lacks, shown as-is
    emit({"type": "stage", "stage": "scan", "status": "done", **coverage})
    triage = agent_run.run(findings, repo, None, target)   # rule only: no model, nothing written
    return Scanned(target, repo, bom, source, findings, triage, coverage, round(time.time() - start, 1))


def new_run(name: str, root: pathlib.Path | None = None) -> Run:
    """A run directory named by the clock; a second one in the same second gets a suffix."""
    root = root or OUT
    stem, n = f"{dt.datetime.now():%Y%m%d-%H%M%S}-{name}", 1
    path = root / stem
    while path.exists() or store.get().has_run(path):
        n += 1
        path = root / f"{stem}-{n}"
    return Run(path)


def record(run: Run, s: Scanned, name: str, context: ServiceContext | None = None, extra: dict | None = None) -> Run:
    """Write a collected scan as the run's SBOM, findings, rule triage and meta."""
    run.write("sbom.cdx.json", s.bom)
    run.write("findings.json", [f.model_dump() for f in s.findings])
    run.save_triage(s.triage)
    meta = {"name": name, "target": str(s.target), "repo": str(s.repo) if s.repo else None, "sbom_source": s.source,
            "coverage": s.coverage, "context": (context or ServiceContext()).model_dump(),
            "seconds": s.seconds, "summary": summarize(s.findings, s.triage),
            "stages": ["sbom", "scan", "score"], **(extra or {})}
    run.write("meta.json", meta)
    run.emit({"type": "stage", "stage": "score", "status": "done", **meta["summary"]})
    return run


def safe_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", text)


def scan(target: pathlib.Path, name: str | None = None, context: ServiceContext | None = None,
         use_syft: bool = True, columns: dict[str, str] | None = None, ecosystem: str | None = None) -> Run:
    """①~④, recorded as a new run."""
    target = target.resolve()
    name = name or safe_name(target.stem if target.is_file() else target.name)
    run = new_run(name)
    return record(run, collect(target, run.emit, use_syft, columns, ecosystem), name, context)


def _llm_meta(llm, code_llm) -> dict:
    describe = lambda m: {"provider": m.name, "model": getattr(m, "model", None)} if m else None  # noqa: E731
    return {"provider": llm.name if llm else "none", "model": getattr(llm, "model", None),
            "code_reader": describe(code_llm), "mode": "two_stage" if code_llm else "single"}


def rescore(run: Run) -> Run:
    """Bring a stored run in line with the current rules without calling any model.

    Rule buckets are recomputed for every finding, recorded AI answers are replayed through the
    current contract checks, and items with no recorded answer get the plain rule result. Use it
    after a scoring or contract change so the dashboard does not show buckets from older rules.
    """
    path = run.dir / "agent_answers.json"
    answered = {k for k, v in json.loads(path.read_text()).items() if v and not k.startswith("code:")} if path.exists() else set()
    before = run.meta
    run = agent(run, writer="replay" if answered else "none", code_reader="none", only=answered, keep_others=False)
    meta = run.meta   # the answers still come from the model that wrote them; rescoring is not a new judgment
    meta["llm"], meta["stages"] = before.get("llm"), before.get("stages", meta["stages"])
    run.write("meta.json", meta)
    return run


def agent(run: Run, limit: int | None = None, writer: str | None = None, code_reader: str | None = None,
          tag: str = "", only: set[str] | None = None, keep_others: bool = True) -> Run:
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
    if only is not None and keep_others:   # partial run: items outside `only` keep their earlier judgment
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

    logs_ok = llm_mod.code_provider() is None   # two-stage: the writer model must not see build or test logs
    revise = (lambda f, prev, steps: agent_run.revise(llm, f, prev, steps, agent_log, logs_ok)) if llm else None
    triage = verify_run.run(repo, findings, triage, run.dir, setup_cmd, revise, run.emit, buckets)
    run.save_triage(triage)
    meta = run.meta
    meta["summary"] = summarize(findings, triage)
    meta["stages"] = sorted(set(meta["stages"]) | {"verify"})
    meta["verify_setup"] = setup_cmd   # the combined check on export reuses it
    run.write("meta.json", meta)
    run.emit({"type": "stage", "stage": "verify", "status": "done", **meta["summary"]})
    return run
