#!/usr/bin/env python3
"""발표와 질의응답용 근거 수집. 코드, 테스트, 커밋, 실행 결과에서 사실만 모아 out/evidence.md에 쓴다.

사용: python3 kit/scripts/evidence.py [--out out/evidence.md]
모으는 것: 커밋 흐름, 테스트 이름과 실행 결과, 실행(run)별 수치, 에이전트 로그 통계, 검증 판정.
에이전트가 레포를 통째로 읽지 않고 이 파일 하나로 발표 수치를 확인하게 하려는 용도다. 읽기 전용.
"""
import argparse
import json
import re
import subprocess
from collections import Counter
from pathlib import Path


def sh(cmd: list[str], timeout: int = 300) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "(실행 실패)"


def runs() -> list[str]:
    out = ["| run | SBOM | 컴포넌트 | 취약점 | CVSS≥7 | 규칙 NOW/NEXT/MONITOR | 최종 NOW/NEXT/MONITOR | 담당자 확인 | verified | LLM |",
           "|---|---|---|---|---|---|---|---|---|---|"]
    for meta_path in sorted(Path("out").glob("*/meta.json")):
        m = json.loads(meta_path.read_text())
        s, c = m["summary"], m["coverage"]
        b = lambda d: f"{d['NOW']}/{d['NEXT']}/{d['MONITOR']}"  # noqa: E731
        llm = (m.get("llm") or {}).get("model") or (m.get("llm") or {}).get("provider") or "규칙만"
        out.append(f"| {meta_path.parent.name} | {m['sbom_source']} | {c['components']} | {s['findings']} | {s['cvss_ge_7']} | "
                   f"{b(s['rule'])} | {b(s['final'])} | {s['needs_review']} | {s['verified']} | {llm} |")
    return out if len(out) > 2 else ["실행 결과 없음 (`uv run python -m triage scan ...`)"]


def agent_stats() -> list[str]:
    out = []
    for log in sorted(Path("out").glob("*/agent_log.jsonl")):
        events = [json.loads(line) for line in log.read_text().splitlines() if line.strip()]
        kinds = Counter(e.get("type") for e in events)
        tools = Counter(e.get("tool") for e in events if e.get("type") == "tool_call")
        tin = sum(e.get("input_tokens") or 0 for e in events)
        tout = sum(e.get("output_tokens") or 0 for e in events)
        out.append(f"- {log.parent.name}: 응답 {kinds['llm_response']}회, 도구 호출 {kinds['tool_call']}회 {dict(tools)}, "
                   f"계약 위반 {kinds['contract_violation']}건, 오류 {kinds['llm_error']}건, 토큰 입력 {tin} / 출력 {tout}")
    return out or ["에이전트 실행 기록 없음"]


def verifications() -> list[str]:
    out = []
    for path in sorted(Path("out").glob("*/verify/*@*.json")):
        v = json.loads(path.read_text())
        r = v["remediation_applied"]
        out.append(f"- {path.parent.parent.name}: {r['package']} {r['from_version']} → {r['to_version']} = **{v['verdict']}** "
                   f"({v['reason']}), 시도 {v['attempt']}회, 실행된 테스트 {v['tests_run']}개, 새 취약점 {len(v['new_findings'])}건")
    return out or ["검증 기록 없음"]


def evals() -> list[str]:
    out = []
    for path in sorted(Path("out").glob("*/eval.json")):
        e = json.loads(path.read_text())
        if not e.get("matched"):
            out.append(f"- {path.parent.name}: 라벨 {e.get('labeled', 0)}건, 일치하는 항목 없음")
            continue
        parts = [f"{k} {e[k]['agreement_pct']}% (NOW 누락 {len(e[k]['now_missed'])})" for k in ("cvss_sort", "rule_only", "rule_plus_agent")]
        out.append(f"- {path.parent.name}: 대상 {e['matched']}건. " + ", ".join(parts))
    return out or ["평가 기록 없음 (`uv run python -m triage eval out/<run>`)"]


def tests() -> list[str]:
    names = []
    for p in sorted(Path("tests").glob("test_*.py")):
        found = re.findall(r"^def (test_\w+)", p.read_text(), re.M)
        names.append(f"- `{p.name}` ({len(found)}): " + ", ".join(found))
    result = sh(["uv", "run", "pytest", "-q"]).splitlines()
    return names + ["", f"실행 결과: `{result[-1] if result else '(없음)'}`"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path("out/evidence.md"))
    a = ap.parse_args()
    sections = [
        ("커밋 흐름 (최근 30개)", sh(["git", "log", "--date=format:%m-%d %H:%M", "--format=- %ad %h %s", "-30"]).splitlines()),
        ("실행별 수치", runs()),
        ("에이전트 실행 통계", agent_stats()),
        ("샌드박스 검증", verifications()),
        ("정답 일치율", evals()),
        ("테스트", tests()),
    ]
    text = "# evidence\n\n발표 자료의 수치는 이 파일과 일치해야 한다.\n"
    for title, lines in sections:
        text += f"\n## {title}\n" + "\n".join(lines) + "\n"
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(text)
    print(f"{a.out} ({len(text.splitlines())}줄)")


if __name__ == "__main__":
    main()
