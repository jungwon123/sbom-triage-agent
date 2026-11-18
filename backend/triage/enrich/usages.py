"""Static import search (F4-4). Read-only; never executes repo code.

npm: import / require / dynamic import, with comments and string literals ignored.
Maven: Java/Kotlin `import` of the package prefix derived from the groupId (approximate).
"""
from __future__ import annotations

import pathlib
import re
from collections.abc import Iterator

from ..models import CodeRef

TEST_PATH = re.compile(
    r"(^|/)(e2e|tests?|__tests__|__mocks__|cypress|spec|src/test)(/|$)|\.(spec|test)\.[cm]?[jt]sx?$|Test\.(java|kt)$")
JS_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
JVM_EXT = {".java", ".kt", ".kts", ".scala"}
SKIP_DIRS = {"node_modules", ".git", "dist", "build", "vendor", "assets", "target", ".gradle", "out", "coverage"}
MAX_FILE_BYTES = 512_000


def source_files(repo: pathlib.Path, exts: set[str]) -> Iterator[tuple[str, str]]:
    for f in repo.rglob("*"):
        try:
            rel = f.relative_to(repo)
        except ValueError:
            continue
        if f.suffix not in exts or SKIP_DIRS & set(rel.parts) or ".min." in f.name:
            continue
        if f.is_symlink() or not f.is_file() or f.stat().st_size > MAX_FILE_BYTES:
            continue
        yield rel.as_posix(), f.read_text(errors="ignore")


def strip_comments(text: str) -> str:
    """Blank out // and /* */ comments while keeping line numbers and string contents."""
    out, i, n = [], 0, len(text)
    quote = None
    while i < n:
        c = text[i]
        if quote:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1]); i += 2; continue
            if c == quote:
                quote = None
            i += 1
        elif c in "'\"`":
            quote = c; out.append(c); i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:j])); i = j
        else:
            out.append(c); i += 1
    return "".join(out)


def _inside_string(line: str, pos: int) -> bool:
    quote = None
    i = 0
    while i < pos:
        c = line[i]
        if quote:
            if c == "\\":
                i += 2; continue
            if c == quote:
                quote = None
        elif c in "'\"`":
            quote = c
        i += 1
    return quote is not None


def js_pattern(pkg: str) -> re.Pattern:
    return re.compile(rf"""(\bfrom\s+|\brequire\(\s*|\bimport\(\s*|\bimport\s+)(['"]){re.escape(pkg)}(/[^'"]*)?\2""")


def jvm_prefix(maven_name: str) -> str:
    group = maven_name.split(":", 1)[0]
    parts = group.split(".")
    return ".".join(parts[:3]) if len(parts) > 3 else group


SEARCHABLE = ("npm", "Maven")   # ecosystems with an import search; others are reported as source missing


def find(pkg: str, ecosystem: str, files: list[tuple[str, str]], limit: int = 50) -> list[CodeRef]:
    refs: list[CodeRef] = []
    if ecosystem not in SEARCHABLE:
        return refs
    if ecosystem == "npm":
        pat = js_pattern(pkg)
    else:
        pat = re.compile(rf"^\s*import\s+(static\s+)?{re.escape(jvm_prefix(pkg))}[.;\s]")
    for rel, text in files:
        clean = strip_comments(text)
        if pkg not in clean and ecosystem == "npm":
            continue
        for no, line in enumerate(clean.splitlines(), 1):
            m = pat.search(line)
            if not m or (ecosystem == "npm" and _inside_string(line, m.start())):
                continue
            refs.append(CodeRef(file=rel, line=no, kind="test" if TEST_PATH.search(rel) else "runtime",
                                snippet=text.splitlines()[no - 1].strip()[:200]))
            if len(refs) >= limit:
                return refs
    return refs


def files_for(repo: pathlib.Path | None, ecosystem: str) -> list[tuple[str, str]]:
    if repo is None or ecosystem not in SEARCHABLE:
        return []
    return list(source_files(repo, JS_EXT if ecosystem == "npm" else JVM_EXT))
