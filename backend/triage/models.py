"""Single source of truth for backend, dashboard and agent output (CLAUDE.md rule 1).

`web/lib/types.ts` is generated from `schema_json()`; change both in the same commit.
"""
from __future__ import annotations

import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Ecosystem = Literal["npm", "Maven", "PyPI", "Go", "crates.io", "NuGet", "RubyGems", "Packagist"]
Bucket = Literal["NOW", "NEXT", "MONITOR"]
Reachability = Literal["used_symbol", "imported_only", "unused", "unknown"]
RemediationKind = Literal["upgrade_direct", "override_transitive", "mitigation_only"]

BUCKET_ORDER: tuple[Bucket, ...] = ("MONITOR", "NEXT", "NOW")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CodeRef(Strict):
    file: str
    line: int
    kind: Literal["runtime", "test"]
    snippet: str


class Component(Strict):
    """One package@version from the SBOM, with lockfile metadata attached by purl (F2-3, F2-5)."""
    name: str
    version: str
    ecosystem: Ecosystem
    purl: str
    scope: Literal["prod", "dev"] = "prod"
    direct: bool = False
    paths: list[list[str]] = Field(default_factory=list)


class ServiceContext(Strict):
    """Never scored (F1-5, F7-8). The agent may use it for its one-step adjustment (D40)."""
    service_criticality: Literal["high", "medium", "low"] | None = None
    internet_facing: bool | None = None
    note: str | None = Field(default=None, max_length=600)   # owner's words: what the service does, who reaches it


class Finding(Strict):
    id: str                      # "<vuln_id>@<package>@<version>"
    vuln_id: str
    aliases: list[str]
    ecosystem: Ecosystem
    package: str
    version: str
    scope: Literal["prod", "dev"]
    direct: bool
    paths: list[list[str]]
    summary: str | None = None
    cvss: float | None
    cvss_source: Literal["vector", "label", "none"] = "none"
    epss: float | None
    epss_percentile: float | None
    kev: bool
    fixed_in: str | None          # lowest fix above the current version
    fixed_max: str | None = None  # version fixing every known finding of this package@version (D29)
    bump: Literal["patch", "minor", "major", "none"]
    import_sites: list[CodeRef]
    missing: list[str] = Field(default_factory=list)   # external data we could not get


class RemediationProposal(Strict):     # what the LLM may propose
    kind: RemediationKind
    to_version: str | None
    mitigation: str | None
    breaking_risk: Literal["low", "medium", "high"]
    notes: str | None


class CodeVerdict(Strict):             # stage 1 of two-stage mode: stays inside the network
    reachability: Reachability
    evidence_files: list[str]


class AgentVerdict(Strict):            # LLM output: no score fields
    reachability: Reachability
    proposed_bucket: Bucket
    override_reason: str | None
    rationale: list[str]               # placeholders such as {cvss}
    remediation: RemediationProposal


class Remediation(Strict):             # built by code from a validated proposal
    kind: RemediationKind
    package: str
    from_version: str
    to_version: str | None
    commands: list[str]
    package_json_patch: dict | None
    mitigation: str | None
    breaking_risk: Literal["low", "medium", "high"]
    notes: str | None


class VerifyStep(Strict):
    name: Literal["copy", "apply", "install", "setup", "build", "test", "rescan"]
    status: Literal["passed", "failed", "skipped"]
    duration_ms: int
    log_tail: str
    failed_tests: list[str] = Field(default_factory=list)
    tests_run: int = 0
    timed_out: bool = False


class VerificationBaseline(Strict):
    steps: list[VerifyStep]


class Verification(Strict):
    finding_id: str
    attempt: int                       # 1..3
    remediation_applied: Remediation
    steps: list[VerifyStep]
    target_resolved: bool
    new_findings: list[str]
    new_now_findings: list[str]
    regressions: list[str]
    tests_run: int
    verdict: Literal["verified", "failed", "inconclusive"]
    reason: str
    # the change itself, taken from the sandbox copy after the commands ran (never written by the LLM)
    patch_file: str | None = None            # file name under out/<run>/verify/
    package_json_diff: str | None = None     # unified diff, small enough to show inline
    lockfile_lines_changed: int = 0


class Decision(Strict):
    """The owner's call on one proposed change (package@version). Append-only log; the latest entry wins."""
    target: str                              # "<package>@<version>"
    status: Literal["approved", "rejected", "held"]
    by: str = Field(min_length=1, max_length=60)
    reason: str = Field(default="", max_length=600)
    at: str                                  # ISO 8601, set by the server
    to_version: str | None = None            # what was on screen when the call was made
    verdict: Literal["verified", "failed", "inconclusive"] | None = None


class CombinedCheck(Strict):
    """Every approved change applied together in one sandbox pass, and the single patch that results."""
    targets: list[str]                       # proposal targets that went in
    finding_ids: list[str]                   # findings the changes are meant to remove
    steps: list[VerifyStep]
    remaining: list[str]                     # target findings still reported after the change
    new_findings: list[str]
    regressions: list[str]
    tests_run: int
    verdict: Literal["verified", "failed", "inconclusive"]
    reason: str
    patch_file: str | None = None            # file name under out/<run>/export/
    package_json_diff: str | None = None
    lockfile_lines_changed: int = 0


class Job(Strict):
    """One queued piece of slow work (a sandbox pass). State lives in out/<run>/jobs/<id>.json."""
    id: str
    kind: Literal["export_together"]
    status: Literal["queued", "running", "done", "failed", "interrupted"]
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    position: int = 0                        # jobs ahead of this one when it was queued
    result: dict | None = None
    error: str | None = None
    boot: str = ""                           # server process that owns it; a different one means it was cut off


class Proposal(Strict):
    """One change set shown to the owner: every finding of a package@version shares it."""
    target: str
    package: str
    from_version: str
    finding_ids: list[str]
    bucket: Bucket                           # highest final bucket among the findings
    remediation: Remediation
    verification: Verification | None
    decision: Decision | None


class Triage(Strict):
    finding_id: str
    risk: int
    risk_breakdown: dict[str, float]
    effort: Literal["low", "medium", "high"]
    rule_bucket: Bucket
    reachability: Reachability
    final_bucket: Bucket
    override_reason: str | None
    rationale: list[str]
    remediation: Remediation | None
    verification: Verification | None = None
    needs_review: bool = False
    decided_by: Literal["rule", "agent", "agent_fallback"] = "rule"
    evidence_files: list[str] = Field(default_factory=list)   # files the code-reading model relied on
    code_read_by: Literal["rule", "agent", "local_agent"] = "rule"  # who set reachability


def schema_json() -> str:
    models = [Component, Finding, AgentVerdict, Remediation, Verification, Triage, ServiceContext, Decision, Proposal, CombinedCheck, Job]
    return json.dumps({m.__name__: m.model_json_schema() for m in models}, ensure_ascii=False, indent=1)
