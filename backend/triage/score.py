"""④ Rule score -> first bucket. Pure functions only (CLAUDE.md rule 2, REQUIREMENTS F5).

risk = severity 25 + exploit 25 + exposure 50. Same input, same output.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Bucket, Finding, Reachability

NOW_AT = 60
NEXT_AT = 30
REACH_W: dict[str, float] = {"used_symbol": 1.0, "imported_only": 0.6, "unused": 0.2, "unknown": 0.6}
SCOPE_W = {"prod": 1.0, "dev": 0.2}
PATH_W = {True: 1.0, False: 0.7}
DEFAULT_CVSS = 5.0       # severity unknown: middle of the scale, recorded in Finding.missing
DEFAULT_EXPLOIT = 0.5    # EPSS unknown
EPSS_FLOOR = 0.8         # D38: percentiles below this score 0. The scale is skewed: the 80th percentile is
                         # roughly a 2% chance of exploitation, so the raw percentile rated almost everything high
NO_SOURCE_W = 0.4        # D38: reachability unknown because there is no source to search (SBOM-only input)


@dataclass(frozen=True)
class Guards:
    """F6-9 thresholds, kept out of the agent's reach."""
    epss_review_percentile: float = 0.9


def rule_reachability(f: Finding) -> Reachability:
    if not f.direct or "source" in f.missing:
        return "unknown"   # transitive, or no source code (SBOM-only input): never call it unused
    return "imported_only" if any(s.kind == "runtime" for s in f.import_sites) else "unused"


def exploit_weight(percentile: float | None) -> float:
    """EPSS percentile -> 0..1, counting only the part above EPSS_FLOOR."""
    if percentile is None:
        return DEFAULT_EXPLOIT
    return max(0.0, (percentile - EPSS_FLOOR) / (1 - EPSS_FLOOR))


def breakdown(f: Finding, reach: Reachability) -> dict[str, float]:
    sev = (f.cvss if f.cvss is not None else DEFAULT_CVSS) / 10 * 25
    exploit_raw = 1.0 if f.kev else exploit_weight(f.epss_percentile)
    reach_w = NO_SOURCE_W if reach == "unknown" and "source" in f.missing else REACH_W[reach]
    exp = SCOPE_W[f.scope] * PATH_W[f.direct] * reach_w * 50
    return {"severity": round(sev, 2), "exploit": round(exploit_raw * 25, 2), "exposure": round(exp, 2)}


def effort(f: Finding) -> str:
    if f.bump == "none":
        return "high"
    if f.bump == "major" or not f.direct:
        return "medium"
    return "low"


def bucket(risk: float, eff: str) -> Bucket:
    if risk >= NOW_AT:
        return "NEXT" if eff == "high" else "NOW"
    return "NEXT" if risk >= NEXT_AT else "MONITOR"


def needs_review(f: Finding, rule_bucket: Bucket | None = None, guards: Guards = Guards()) -> bool:
    """Items the agent must not downgrade on its own (F6-9).

    KEV always. High EPSS when runtime code imports the package, or when the rule bucket is NOW:
    "no import found" is not enough to lower an item that is both urgent by rule and actively exploited.
    """
    runtime = any(s.kind == "runtime" for s in f.import_sites)
    hot = (f.epss_percentile or 0) >= guards.epss_review_percentile
    return f.kev or (hot and (runtime or rule_bucket == "NOW"))


@dataclass(frozen=True)
class RuleResult:
    finding_id: str
    risk: float
    risk_breakdown: dict[str, float]
    effort: str
    reachability: Reachability
    bucket: Bucket


def score(f: Finding) -> RuleResult:
    reach = rule_reachability(f)
    parts = breakdown(f, reach)
    risk = sum(parts.values())
    eff = effort(f)
    return RuleResult(f.id, round(risk, 2), parts, eff, reach, bucket(risk, eff))


def cvss_bucket(f: Finding) -> Bucket:
    """Baseline for evaluation: what a CVSS-sorted list implies."""
    c = f.cvss or 0
    return "NOW" if c >= 9 else "NEXT" if c >= 7 else "MONITOR"
