"""⑤ Agent judgment (HARNESS 4): per NOW/NEXT candidate, ask the LLM for an AgentVerdict,
check the contract in code and assemble Triage. Any failure falls back to the rule result.
"""
from __future__ import annotations

import concurrent.futures as cf
import json
import pathlib
import re
import threading
from collections.abc import Callable

from pydantic import ValidationError

from .. import score
from ..models import BUCKET_ORDER, AgentVerdict, Bucket, CodeVerdict, Finding, Reachability, RemediationProposal, Triage
from ..verify import apply
from . import prompts
from .llm import LLM, LLMError
from .tools import SPECS, RepoTools, ToolError

MAX_TOOL_CALLS = 6
PLACEHOLDER = re.compile(r"\{(\w+)\}")


# ---------- rationale ----------

def fill_values(f: Finding, risk: float) -> dict[str, str]:
    pct = f"상위 {max(1, round((1 - f.epss_percentile) * 100))}%" if f.epss_percentile is not None else "데이터 없음"
    return {
        "cvss": f"{f.cvss:.1f}" if f.cvss is not None else "데이터 없음", "epss_percentile": pct,
        "kev": "등재" if f.kev else "미등재", "package": f.package, "version": f.version,
        "fixed_in": f.fixed_in or "없음", "fixed_max": f.fixed_max or "없음", "risk": str(round(risk)),
        "scope": "운영" if f.scope == "prod" else "개발", "vuln_id": f.vuln_id,
        "bump": {"patch": "패치", "minor": "마이너", "major": "메이저", "none": "수정 버전 없음"}[f.bump],
    }


def rationale_violations(lines: list[str]) -> list[str]:
    out = []
    if not 1 <= len(lines) <= 3:
        out.append("rationale must have 1 to 3 sentences")
    for line in lines:
        unknown = [p for p in PLACEHOLDER.findall(line) if p not in prompts.PLACEHOLDERS]
        if unknown:
            out.append(f"unknown placeholder {unknown}")
        if re.search(r"\d", PLACEHOLDER.sub("", line)):
            out.append("rationale contains a number outside a placeholder")
    return out


def fill(lines: list[str], values: dict[str, str]) -> list[str]:
    return [PLACEHOLDER.sub(lambda m: values.get(m.group(1), m.group(0)), line) for line in lines]


def rule_rationale(f: Finding, r: score.RuleResult, reach: Reachability | None = None) -> list[str]:
    v = fill_values(f, r.risk)
    usage = {"imported_only": "운영 코드에서 import합니다", "unused": "운영 코드에서 import하지 않습니다",
             "unknown": "코드 사용 여부를 판단하지 못했습니다",
             "used_symbol": "취약한 코드를 운영 코드에서 사용합니다"}[reach or r.reachability]
    lines = [f"CVSS {v['cvss']}, EPSS {v['epss_percentile']}, KEV {v['kev']}이며 {v['scope']} 의존성입니다.",
             f"{f.package}은(는) {usage}."]
    if f.missing:
        lines.append("확보하지 못한 데이터: " + ", ".join(f.missing))
    return lines


# ---------- contract ----------

def contract_violations(v: AgentVerdict, f: Finding, rule_bucket: Bucket) -> list[str]:
    out = []
    a, b = BUCKET_ORDER.index(rule_bucket), BUCKET_ORDER.index(v.proposed_bucket)
    if abs(a - b) > 1:
        out.append("bucket moved more than one step")
    if a != b and not (v.override_reason or "").strip():
        out.append("override_reason missing")
    if f.kev and b < a:
        out.append("KEV item downgraded")
    out += rationale_violations(v.rationale)
    out += apply.violations(v.remediation, f)
    return out


def merge(f: Finding, r: score.RuleResult, v: AgentVerdict | None, decided_by: str,
          code: CodeVerdict | None = None) -> Triage:
    """Triage is assembled by code. v must already have passed contract_violations.

    In two-stage mode `code` comes from the model inside the network and always decides
    reachability, whatever the writer model answered.
    """
    review = score.needs_review(f)
    final, reason, held = r.bucket, None, False
    if v is not None:
        down = BUCKET_ORDER.index(v.proposed_bucket) < BUCKET_ORDER.index(r.bucket)
        if down and review:
            held = True   # F6-9: keep the rule bucket, mark for the owner
        else:
            final = v.proposed_bucket
        reason = v.override_reason if final != r.bucket else None
    proposal = v.remediation if v is not None else apply.default_proposal(f)
    reach: Reachability = code.reachability if code is not None else v.reachability if v is not None else r.reachability
    return Triage(
        finding_id=f.id, risk=round(r.risk), risk_breakdown=r.risk_breakdown, effort=r.effort,
        rule_bucket=r.bucket, reachability=reach,
        final_bucket=final, override_reason=reason,
        rationale=fill(v.rationale, fill_values(f, r.risk)) if v is not None else rule_rationale(f, r, reach),
        remediation=apply.build(proposal, f), needs_review=held,
        decided_by=decided_by,
        evidence_files=code.evidence_files[:10] if code is not None else [],
        code_read_by="local_agent" if code is not None else "agent" if v is not None else "rule",
    )


# ---------- loop ----------

def judge_code(llm: LLM, f: Finding, r: score.RuleResult, tools: RepoTools,
               log: Callable[[dict], None]) -> tuple[CodeVerdict | None, list[str]]:
    """Stage 1 of two-stage mode: the in-network model reads code and returns reachability only.

    A verdict counts only if the model actually inspected something: with no successful tool call
    it gets one reminder, and if it still answers without looking, the rule result is used.
    """
    looked = 0

    def call_tool(name: str, args: dict) -> tuple[str, bool]:
        nonlocal looked
        try:
            out = tools.call(name, args)
        except (ToolError, TypeError, ValueError) as e:
            return f"tool error: {e}", True
        looked += 1
        return out, False

    answers: list[str] = []
    key = f"code:{f.id}"
    try:
        session = llm.start(prompts.CODE_SYSTEM, prompts.user_prompt(f, r), SPECS, prompts.CODE_SCHEMA,
                            MAX_TOOL_CALLS, log, key)
        text = session.run(call_tool)
        for attempt in (1, 2):
            answers.append(text)
            problem = None
            try:
                v = CodeVerdict.model_validate_json(_json_part(text))
            except ValidationError as e:
                v, problem = None, f"invalid JSON: {e.errors()[0]['msg']}"
            if problem is None and looked == 0:
                problem = "no file was inspected; call search_usages or read_file before answering"
            if problem is None:
                return v, answers
            log({"type": "contract_violation", "key": key, "attempt": attempt, "problems": [problem]})
            if attempt == 2:
                return None, answers
            text = session.followup(f"Your answer was rejected: {problem}. Then return the JSON only.", call_tool)
    except LLMError as e:
        log({"type": "llm_error", "key": key, "error": str(e)})
    return None, answers


def judge_one(llm: LLM, f: Finding, r: score.RuleResult, tools: RepoTools | None,
              log: Callable[[dict], None], code: CodeVerdict | None = None) -> tuple[AgentVerdict | None, list[str]]:
    """-> (verdict or None, final answers). One retry with the error message, then give up.

    With `code` set this is the writer of two-stage mode: no tools, no source code in the prompt.
    """
    def call_tool(name: str, args: dict) -> tuple[str, bool]:
        if code is not None or tools is None:
            return "no tools in this stage", True
        try:
            return tools.call(name, args), False
        except (ToolError, TypeError, ValueError) as e:
            return f"tool error: {e}", True

    answers: list[str] = []
    try:
        if code is None:
            session = llm.start(prompts.SYSTEM, prompts.user_prompt(f, r), SPECS, prompts.VERDICT_SCHEMA,
                                MAX_TOOL_CALLS, log, f.id)
        else:
            session = llm.start(prompts.SYSTEM + prompts.WRITER_NOTE, prompts.writer_prompt(f, r, code.reachability),
                                [], prompts.VERDICT_SCHEMA, 0, log, f.id)
        text = session.run(call_tool)
        for attempt in (1, 2):
            answers.append(text)
            try:
                v = AgentVerdict.model_validate_json(_json_part(text))
                problems = contract_violations(v, f, r.bucket)
            except ValidationError as e:
                v, problems = None, [f"schema: {e.errors()[0]['loc']} {e.errors()[0]['msg']}"]
            if not problems:
                return v, answers
            log({"type": "contract_violation", "key": f.id, "attempt": attempt, "problems": problems})
            if attempt == 2:
                return None, answers
            text = session.followup("Your answer was rejected: " + "; ".join(problems) +
                                    ". Return the corrected JSON verdict only.", call_tool)
    except LLMError as e:
        log({"type": "llm_error", "key": f.id, "error": str(e)})
    return None, answers


def _json_part(text: str) -> str:
    start, end = text.find("{"), text.rfind("}")
    return text[start:end + 1] if 0 <= start < end else text


def run(findings: list[Finding], repo: pathlib.Path | None, llm: LLM | None, run_dir: pathlib.Path,
        limit: int | None = None, workers: int = 4, emit: Callable[[dict], None] = lambda e: None,
        code_llm: LLM | None = None, tag: str = "") -> list[Triage]:
    """llm writes the verdict. code_llm, when given, is the only model that reads source code (two-stage)."""
    by_id = {f.id: f for f in findings}
    rules = {f.id: score.score(f) for f in findings}
    candidates = sorted((f for f in findings if rules[f.id].bucket in ("NOW", "NEXT")),
                        key=lambda f: -rules[f.id].risk)
    if limit is not None:
        candidates = candidates[:limit]
    lock = threading.Lock()
    suffix = f".{tag}" if tag else ""
    log_path = run_dir / f"agent_log{suffix}.jsonl"
    answers: dict[str, list[str]] = {}

    def log(event: dict) -> None:
        with lock, log_path.open("a") as fh:
            fh.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")

    verdicts: dict[str, AgentVerdict | None] = {}
    codes: dict[str, CodeVerdict | None] = {}
    judged: set[str] = set()
    if (llm is not None or code_llm is not None) and candidates:
        tools = RepoTools(repo, by_id)

        def one(f: Finding) -> None:
            code, v = None, None
            if code_llm is not None:
                code, raw_code = judge_code(code_llm, f, rules[f.id], tools, log)
                with lock:
                    answers[f"code:{f.id}"] = raw_code
                if code is not None and llm is not None:
                    v, raw = judge_one(llm, f, rules[f.id], None, log, code=code)
                    with lock:
                        answers[f.id] = raw
            elif llm is not None:
                v, raw = judge_one(llm, f, rules[f.id], tools, log)
                with lock:
                    answers[f.id] = raw
            with lock:
                verdicts[f.id], codes[f.id] = v, code
                judged.add(f.id)
            emit({"type": "agent_item", "finding_id": f.id, "ok": v is not None or code is not None})

        with cf.ThreadPoolExecutor(workers if code_llm is None else min(workers, 2)) as ex:
            list(ex.map(one, candidates))
        if "replay" not in {getattr(llm, "name", None), getattr(code_llm, "name", None)}:
            (run_dir / f"agent_answers{suffix}.json").write_text(json.dumps(answers, ensure_ascii=False, indent=1))

    out = []
    for f in findings:
        if f.id in judged:
            v, code = verdicts[f.id], codes[f.id]
            wanted_writer = llm is not None
            ok = (v is not None) if wanted_writer else (code is not None)
            out.append(merge(f, rules[f.id], v, "agent" if ok else "agent_fallback", code))
        else:
            out.append(merge(f, rules[f.id], None, "rule"))
    return out


def revise(llm: LLM, f: Finding, previous: dict, failure: list[dict],
           log: Callable[[dict], None]) -> RemediationProposal | None:
    """F8-5: ask for another remediation after a failed verification."""
    from ..enrich import semver
    from .. import cache
    d = cache.fetch_json(f"https://api.osv.dev/v1/vulns/{f.vuln_id}") or {}
    fixes = sorted({x for x in semver.fixes_for(d, f.ecosystem, f.package) if semver.lt(f.version, x)}, key=semver.parse)
    candidates = fixes or [x for x in (f.fixed_in, f.fixed_max) if x]
    try:
        session = llm.start(prompts.REVISE_SYSTEM, prompts.revise_prompt(f, previous, failure, candidates),
                            [], prompts.REMEDIATION_SCHEMA, 0, log, f"revise:{f.id}")
        p = RemediationProposal.model_validate_json(_json_part(session.run(lambda n, a: ("no tools", True))))
    except (LLMError, ValidationError) as e:
        log({"type": "revise_error", "key": f.id, "error": str(e)[:300]})
        return None
    problems = apply.violations(p, f)
    if problems:
        log({"type": "contract_violation", "key": f"revise:{f.id}", "problems": problems})
        return None
    return p
