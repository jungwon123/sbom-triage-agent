"""Environment check for the finals laptop. Prints status only, never secret values."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

from . import cache
from .agent import llm as llm_mod
from .verify import sandbox


def _version(cmd: list[str]) -> str | None:
    if not shutil.which(cmd[0]):
        return None
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return (out.stdout or out.stderr).strip().splitlines()[0][:60]
    except (subprocess.TimeoutExpired, IndexError):
        return "?"


def checks(test_llm: bool = False) -> list[tuple[str, str, str]]:
    """-> [(name, ok|warn|fail, detail)]"""
    rows: list[tuple[str, str, str]] = []
    rows.append(("python", "ok" if sys.version_info[:2] == (3, 12) else "warn", sys.version.split()[0]))
    for name, cmd, need in (("uv", ["uv", "--version"], True), ("node", ["node", "--version"], True),
                            ("npm", ["npm", "--version"], True), ("syft", ["syft", "version"], False),
                            ("git", ["git", "--version"], True)):
        v = _version(cmd)
        rows.append((name, "ok" if v else ("fail" if need else "warn"), v or "없음" + ("" if need else " (lockfile 파싱으로 대체)")))
    docker = sandbox.available()
    rows.append(("docker", "ok" if docker else "warn", "실행 중" if docker else "꺼져 있음 (검증 단계는 건너뜀)"))
    if docker:
        img = subprocess.run(["docker", "image", "inspect", sandbox.IMAGE], capture_output=True).returncode == 0
        rows.append(("sandbox image", "ok" if img else "warn", sandbox.IMAGE if img else f"docker pull {sandbox.IMAGE} 필요"))
    n = len(list(cache.CACHE_DIR.glob("*.json"))) if cache.CACHE_DIR.exists() else 0
    rows.append(("response cache", "ok" if n else "warn", f"{n}개 ({cache.CACHE_DIR.name})"))
    rows.append(("DEMO_MODE", "ok", os.environ.get("DEMO_MODE", "live")))
    p = llm_mod.provider()
    key = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}.get(p)
    has_key = bool(key and os.environ.get(key))
    model = os.environ.get("OPENAI_MODEL" if p == "openai" else "LLM_MODEL", "claude-fable-5-2" if p == "anthropic" else "")
    rows.append(("LLM_PROVIDER", "ok", f"{p} / model={model or '미설정'}"))
    if key:
        rows.append((key, "ok" if has_key else "warn", "설정됨" if has_key else "없음 (.env에 입력, 없으면 규칙 결과만 사용)"))
    if test_llm and p in ("anthropic", "openai"):
        try:
            session = llm_mod.make().start("Reply with JSON only.", 'Return {"ok": true}.', [],
                                            {"type": "object", "properties": {"ok": {"type": "boolean"}},
                                             "required": ["ok"], "additionalProperties": False}, 0, lambda e: None, "doctor")
            rows.append(("LLM call", "ok", session.run(lambda n, a: ("", True))[:40]))
        except Exception as e:
            rows.append(("LLM call", "fail", str(e)[:120]))
    return rows


def main(test_llm: bool = False) -> int:
    rows = checks(test_llm)
    mark = {"ok": "✅", "warn": "⚠️ ", "fail": "❌"}
    for name, status, detail in rows:
        print(f"{mark[status]} {name:18} {detail}")
    return 1 if any(s == "fail" for _, s, _ in rows) else 0
