"""Read-only agent tools (REQUIREMENTS F6 tools, CLAUDE.md rule 4).

No writes, no command execution, nothing outside the repo. Every result is plain text the
model reads as data; repo files and advisories are untrusted input.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
from typing import Any

from .. import cache, score
from ..enrich import usages
from ..models import Finding

MAX_LINES = 200
MAX_CHARS = 12_000

SPECS: list[dict[str, Any]] = [
    {"name": "get_finding",
     "description": "Normalized vulnerability finding with enrichment data and the rule score for one finding_id. Read-only.",
     "input_schema": {"type": "object", "properties": {"finding_id": {"type": "string"}},
                      "required": ["finding_id"], "additionalProperties": False}},
    {"name": "search_usages",
     "description": "Find where the repository imports a package, optionally also lines that mention a symbol in those files. "
                    "Returns file, line, runtime/test and a code snippet. Repository only.",
     "input_schema": {"type": "object", "properties": {
         "package": {"type": "string"},
         "symbol": {"type": "string", "description": "Optional function or property name to look for, e.g. 'merge'."}},
         "required": ["package"], "additionalProperties": False}},
    {"name": "read_file",
     "description": f"Read up to {MAX_LINES} lines of a repository file (relative path). Repository only, size-limited.",
     "input_schema": {"type": "object", "properties": {
         "path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}},
         "required": ["path"], "additionalProperties": False}},
    {"name": "get_advisory",
     "description": "Advisory text for a vulnerability id (CVE or GHSA): summary, details, affected functions if listed. Cached.",
     "input_schema": {"type": "object", "properties": {"vuln_id": {"type": "string"}},
                      "required": ["vuln_id"], "additionalProperties": False}},
]


class ToolError(Exception):
    pass


def safe_path(repo: pathlib.Path, rel: str) -> pathlib.Path:
    """Resolve rel inside repo; reject absolute paths, '..' and symlink escapes."""
    if not rel or os.path.isabs(rel) or "\x00" in rel:
        raise ToolError("path must be relative to the repository")
    root = repo.resolve()
    target = (root / rel).resolve()
    if target != root and root not in target.parents:
        raise ToolError("path is outside the repository")
    if not target.is_file():
        raise ToolError("file not found")
    return target


class RepoTools:
    def __init__(self, repo: pathlib.Path | None, findings: dict[str, Finding]):
        self.repo = repo
        self.findings = findings
        self._files: dict[str, list[tuple[str, str]]] = {}

    def call(self, name: str, args: dict) -> str:
        fn = {"get_finding": self.get_finding, "search_usages": self.search_usages,
              "read_file": self.read_file, "get_advisory": self.get_advisory}.get(name)
        if fn is None:
            raise ToolError(f"unknown tool {name}")
        if not isinstance(args, dict):
            raise ToolError("arguments must be an object")
        out = fn(**{k: v for k, v in args.items() if v is not None})
        return out[:MAX_CHARS]

    def get_finding(self, finding_id: str) -> str:
        f = self.findings.get(finding_id)
        if not f:
            raise ToolError("unknown finding_id")
        r = score.score(f)
        data = f.model_dump(exclude={"import_sites"})
        data["import_sites"] = [s.model_dump() for s in f.import_sites[:15]]
        data["rule"] = {"risk": r.risk, "breakdown": r.risk_breakdown, "effort": r.effort,
                        "reachability": r.reachability, "bucket": r.bucket}
        return json.dumps(data, ensure_ascii=False)

    def _source(self, ecosystem: str) -> list[tuple[str, str]]:
        if ecosystem not in self._files:
            self._files[ecosystem] = usages.files_for(self.repo, ecosystem)
        return self._files[ecosystem]

    def search_usages(self, package: str, symbol: str | None = None) -> str:
        if self.repo is None:
            return "no source code available for this run"
        eco = "Maven" if ":" in package else "npm"
        files = self._source(eco)
        refs = usages.find(package, eco, files, limit=30)
        lines = [f"{r.file}:{r.line} [{r.kind}] {r.snippet}" for r in refs]
        if symbol:
            if not re.fullmatch(r"[A-Za-z_$][\w$]{0,60}", symbol):
                raise ToolError("symbol must be an identifier")
            sym = re.compile(rf"\b{re.escape(symbol)}\b")
            hit_files = {r.file for r in refs}
            for rel, text in files:
                if rel not in hit_files:
                    continue
                for no, line in enumerate(text.splitlines(), 1):
                    if sym.search(line):
                        lines.append(f"{rel}:{no} [symbol] {line.strip()[:200]}")
        return "\n".join(lines[:80]) or "no imports found"

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        if self.repo is None:
            raise ToolError("no source code available for this run")
        target = safe_path(self.repo, path)
        if target.stat().st_size > 2_000_000:
            raise ToolError("file too large")
        lines = target.read_text(errors="ignore").splitlines()
        start = max(1, int(start_line))
        end = min(len(lines), int(end_line) if end_line else start + MAX_LINES - 1, start + MAX_LINES - 1)
        return "\n".join(f"{i}: {lines[i - 1]}" for i in range(start, end + 1))

    def get_advisory(self, vuln_id: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9-]{4,40}", vuln_id):
            raise ToolError("invalid vuln_id")
        d = cache.fetch_json(f"https://api.osv.dev/v1/vulns/{vuln_id}")
        if not d:
            return "advisory not available"
        funcs = [s for a in d.get("affected", []) for s in a.get("ecosystem_specific", {}).get("affected_functions", [])]
        return json.dumps({"id": d.get("id"), "summary": d.get("summary"), "details": (d.get("details") or "")[:4000],
                           "affected_functions": funcs[:20]}, ensure_ascii=False)
