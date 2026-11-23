#!/usr/bin/env python3
"""본선 제공 자료가 무엇인지 요약한다. 파일 내용을 통째로 출력하지 않고 종류와 개수만 본다.

사용: python3 kit/scripts/profile_input.py <폴더 또는 파일> [--out out/profile.md]
찾는 것: 레포(lockfile 종류), SBOM 파일(CycloneDX, SPDX), 스캐너 결과(Trivy, Grype, npm audit),
         표 형식 자료(CSV), 그리고 현재 파이프라인이 바로 읽을 수 있는지 여부.
읽기 전용이다. 표준 라이브러리만 쓴다.
"""
import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path

SKIP = {".git", "node_modules", "target", "build", "dist", ".gradle", ".venv", "__pycache__"}
LOCKS = {
    "package-lock.json": ("npm", "지원"),
    "pom.xml": ("Maven", "직접 의존성만 지원, 샌드박스 미지원"),
    "yarn.lock": ("npm(yarn)", "지원 (직접과 간접 구분 없음), 샌드박스 미지원"),
    "pnpm-lock.yaml": ("npm(pnpm)", "지원, 샌드박스 미지원"),
    "gradle.lockfile": ("Gradle", "지원, 샌드박스 미지원"),
    "build.gradle": ("Gradle", "버전이 고정되지 않음: gradle.lockfile, SBOM 파일 또는 Syft 필요"),
    "build.gradle.kts": ("Gradle", "버전이 고정되지 않음: gradle.lockfile, SBOM 파일 또는 Syft 필요"),
    "requirements.txt": ("PyPI", "지원 (== 로 고정된 줄만), import 검색과 샌드박스 미지원"),
    "poetry.lock": ("PyPI", "지원, import 검색과 샌드박스 미지원"),
    "uv.lock": ("PyPI", "지원, import 검색과 샌드박스 미지원"),
    "Pipfile.lock": ("PyPI", "지원, import 검색과 샌드박스 미지원"),
    "go.mod": ("Go", "지원, import 검색과 샌드박스 미지원"),
    "go.sum": ("Go", "지원 (go.mod가 있으면 그쪽을 씀)"),
    "Cargo.lock": ("Rust", "지원, import 검색과 샌드박스 미지원"),
    "Gemfile.lock": ("Ruby", "지원, import 검색과 샌드박스 미지원"),
    "composer.lock": ("PHP", "지원, import 검색과 샌드박스 미지원"),
    "packages.lock.json": ("NuGet", "지원, import 검색과 샌드박스 미지원"),
}


def classify_json(path: Path) -> str | None:
    try:
        if path.stat().st_size > 80_000_000:
            return "JSON (80MB 초과, 열지 않음)"
        doc = json.loads(path.read_text(errors="ignore"))
    except (ValueError, OSError):
        return None
    if not isinstance(doc, dict):
        return None
    if doc.get("bomFormat") == "CycloneDX":
        eco = Counter((c.get("purl") or "pkg:?/").split("/")[0].replace("pkg:", "") for c in doc.get("components", []))
        graph = "의존 그래프 있음" if doc.get("dependencies") else "의존 그래프 없음(직접 의존성 구분 불가)"
        return f"CycloneDX SBOM: 컴포넌트 {len(doc.get('components', []))}개 {dict(eco.most_common(4))}, {graph} → `triage scan <파일>` 지원"
    if str(doc.get("spdxVersion", "")).startswith("SPDX"):
        return f"SPDX SBOM: 패키지 {len(doc.get('packages', []))}개 → `triage scan <파일>` 지원"
    if "Results" in doc and "SchemaVersion" in doc:
        n = sum(len(r.get("Vulnerabilities") or []) for r in doc.get("Results", []))
        return f"Trivy 결과: 취약점 {n}건 → `triage scan <파일>` 지원"
    if "matches" in doc and "descriptor" in doc:
        return f"Grype 결과: {len(doc['matches'])}건 → `triage scan <파일>` 지원"
    if "auditReportVersion" in doc or "advisories" in doc:
        return "npm audit 결과 → 설치 버전이 없어 미지원. 같은 프로젝트의 package-lock.json을 입력으로 쓴다"
    if "vulnerabilities" in doc and "catalogVersion" in doc:
        return f"CISA KEV 스냅샷: {len(doc['vulnerabilities'])}건 → `triage seed --kev <파일>`로 넣어 오프라인 사용"
    return None


def profile(root: Path) -> list[str]:
    out = [f"# 자료 요약: {root}", ""]
    files = [root] if root.is_file() else [p for p in sorted(root.rglob("*")) if p.is_file() and not SKIP & set(p.parts)]
    ext = Counter(p.suffix.lower() or "(없음)" for p in files)
    out += [f"- 파일 {len(files)}개. 확장자 상위: " + ", ".join(f"{k} {v}" for k, v in ext.most_common(10)), ""]

    repos = [(p, *LOCKS[p.name]) for p in files if p.name in LOCKS]
    out.append("## 레포 단서 (lockfile, 빌드 파일)")
    out += [f"- `{p}`: {eco}, {state}" for p, eco, state in repos[:40]] or ["- 없음"]
    out.append("")

    out.append("## SBOM, 스캐너 결과")
    found = [(p, c) for p in files if p.suffix.lower() == ".json" and p.name not in LOCKS for c in [classify_json(p)] if c]
    out += [f"- `{p}`: {c}" for p, c in found[:40]] or ["- 없음"]
    out.append("")

    out.append("(정확한 판별은 `uv run python -m triage inspect <경로>`: Snyk, OSV-Scanner, Dependency-Check, CycloneDX XML, SPDX tag-value도 읽는다)")
    out.append("")
    out.append("## 표 형식 자료 (`triage scan <파일> --columns name=<열>,version=<열> --ecosystem <이름>`으로 읽는다)")
    tables = [p for p in files if p.suffix.lower() in (".csv", ".tsv")]
    for p in tables[:20]:
        try:
            with p.open(encoding="utf-8-sig", errors="ignore") as fh:
                sample = fh.readline()
                delim = max(",|\t;", key=sample.count)
                fh.seek(0)
                header = next(csv.reader(fh, delimiter=delim), [])
                rows = sum(1 for _ in fh)
            out.append(f"- `{p}`: {rows}행, 구분자 `{delim}`, 열 {len(header)}개: {', '.join(header[:12])}")
        except OSError:
            out.append(f"- `{p}`: 읽지 못함")
    if not tables:
        out.append("- 없음")
    out.append("")

    src = Counter(p.suffix for p in files if p.suffix in {".java", ".kt", ".js", ".ts", ".tsx", ".py", ".go"})
    out += ["## 소스 코드", "- " + (", ".join(f"{k} {v}" for k, v in src.most_common()) or "없음 (SBOM만 있으면 코드 사용 여부는 unknown으로 처리된다)"), ""]
    docs = [p for p in files if p.suffix.lower() in (".md", ".pdf", ".docx", ".hwp", ".pptx", ".txt")]
    out += ["## 문서 (사람이 직접 읽을 것)"] + ([f"- `{p}`" for p in docs[:30]] or ["- 없음"])
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("target", type=Path)
    ap.add_argument("--out", type=Path)
    a = ap.parse_args()
    if not a.target.exists():
        print(f"없는 경로: {a.target}", file=sys.stderr)
        return 2
    text = "\n".join(profile(a.target)) + "\n"
    if a.out:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
