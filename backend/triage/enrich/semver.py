"""Version comparison and fix-version selection from OSV affected ranges (pure functions)."""
from __future__ import annotations

import re

_PRE = re.compile(r"[-+]")


def parse(v: str) -> tuple[int, int, int, int, str]:
    """(major, minor, patch, is_release, prerelease). Works for npm and most Maven versions."""
    core, _, pre = _PRE.split(v, 1)[0], None, ""
    m = _PRE.search(v)
    if m:
        pre = v[m.end():]
    nums = [int(n) for n in re.findall(r"\d+", core)[:3]]
    nums += [0] * (3 - len(nums))
    # Maven qualifiers like .RELEASE / .Final count as releases
    release = 0 if pre and not re.fullmatch(r"(?i)(release|final|ga)", pre) else 1
    return nums[0], nums[1], nums[2], release, pre


def lt(a: str, b: str) -> bool:
    return parse(a) < parse(b)


def fixes_for(detail: dict, ecosystem: str, name: str) -> list[str]:
    return [e["fixed"] for a in detail.get("affected", [])
            if a.get("package", {}).get("name") == name and a.get("package", {}).get("ecosystem") == ecosystem
            for r in a.get("ranges", []) if r.get("type") in ("SEMVER", "ECOSYSTEM")
            for e in r.get("events", []) if "fixed" in e]


def fixed_in(fixes: list[str], version: str) -> str | None:
    later = [f for f in fixes if lt(version, f)]
    return min(later, key=parse) if later else None


def fixed_max(fixes: list[str], version: str) -> str | None:
    later = [f for f in fixes if lt(version, f)]
    return max(later, key=parse) if later else None


def bump(version: str, fixed: str | None) -> str:
    if not fixed:
        return "none"
    a, b = parse(version), parse(fixed)
    return "major" if a[0] != b[0] else "minor" if a[1] != b[1] else "patch"


def valid(v: str) -> bool:
    return bool(re.fullmatch(r"\d+(\.\d+){0,3}([-.][0-9A-Za-z.-]+)?", v or ""))
