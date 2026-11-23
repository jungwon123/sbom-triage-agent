"""④ Rule score -> first bucket. Pure functions only (CLAUDE.md rule 2, REQUIREMENTS F5).

risk = severity 25 + exploit 25 + exposure 50. Same input, same output.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import BUCKET_ORDER, Bucket, Finding, Reachability

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


def unconfirmed(f: Finding) -> bool:
    """Only the input file claims this, and the advisory it names is about another package (scan.py)."""
    return "osv_mismatch" in f.missing


def breakdown(f: Finding, reach: Reachability) -> dict[str, float]:
    sev = (f.cvss if f.cvss is not None else DEFAULT_CVSS) / 10 * 25
    # an unconfirmed claim does not get the advisory's KEV listing for free: a scanner false positive
    # naming a famous CVE would otherwise land in NOW by itself
    exploit_raw = 1.0 if f.kev and not unconfirmed(f) else exploit_weight(f.epss_percentile)
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


def is_malicious(f: Finding) -> bool:
    """OSV malicious-package advisories (MAL-...): the package itself is the attack, not a flaw in it."""
    return any(i.startswith("MAL-") for i in (f.vuln_id, *f.aliases))


def floor(f: Finding) -> Bucket | None:
    """Lowest bucket the facts allow, whatever the score says (D44).

    A malicious package, or a known-exploited flaw in something that ships to production, is urgent even
    with no fixed version: "no patch" makes it harder, not less pressing. Known-exploited in a dev-only
    dependency is at least NEXT.
    """
    if is_malicious(f):
        return "NOW"
    if f.kev and not unconfirmed(f):
        return "NOW" if f.scope == "prod" else "NEXT"
    return None


def blocks_monitor(f: Finding, guards: Guards = Guards()) -> bool:
    """The agent may not move an item with very high EPSS down to MONITOR on its own (F6-9, D44).

    Without source code there is no import evidence either way, so the import-based guard never fires;
    this one depends on the exploitation signal alone.
    """
    return (f.epss_percentile or 0) >= guards.epss_review_percentile


def needs_review(f: Finding, rule_bucket: Bucket | None = None, guards: Guards = Guards()) -> bool:
    """Items the agent must not downgrade on its own (F6-9).

    KEV always. High EPSS when runtime code imports the package, or when the rule bucket is NOW:
    "no import found" is not enough to lower an item that is both urgent by rule and actively exploited.
    """
    runtime = any(s.kind == "runtime" for s in f.import_sites)
    hot = (f.epss_percentile or 0) >= guards.epss_review_percentile
    return f.kev or is_malicious(f) or unconfirmed(f) or (hot and (runtime or rule_bucket == "NOW"))


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
    b, least = bucket(risk, eff), floor(f)
    if least is not None and BUCKET_ORDER.index(b) < BUCKET_ORDER.index(least):
        b = least
    return RuleResult(f.id, round(risk, 2), parts, eff, reach, b)


def cvss_bucket(f: Finding) -> Bucket:
    """Baseline for evaluation: what a CVSS-sorted list implies."""
    c = f.cvss or 0
    return "NOW" if c >= 9 else "NEXT" if c >= 7 else "MONITOR"
