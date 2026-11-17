"""Golden-set agreement (REQUIREMENTS 9): CVSS sort vs rule only vs rule + agent, and NOW misses."""
from __future__ import annotations

import csv
import pathlib

import yaml

from . import score
from .models import Finding, Triage

LABEL_COL = "label(NOW/NEXT/MONITOR)"
BUCKETS = {"NOW", "NEXT", "MONITOR"}


def load_golden(path: pathlib.Path) -> dict[str, str]:
    """finding id -> label. Accepts golden.yaml or the labeling sheet CSV. Unlabeled rows are skipped."""
    out: dict[str, str] = {}
    if path.suffix in (".yaml", ".yml"):
        for row in yaml.safe_load(path.read_text()) or []:
            fid = row.get("finding_id") or f"{row['advisory']}@{row['package']}@{row['version']}"
            if str(row.get("label", "")).upper() in BUCKETS:
                out[fid] = row["label"].upper()
        return out
    with path.open(encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            label = (row.get(LABEL_COL) or "").strip().upper()
            if label in BUCKETS:
                out[f"{row['advisory']}@{row['package']}@{row['version']}"] = label
    return out


def evaluate(findings: list[Finding], triage: list[Triage], golden: dict[str, str]) -> dict:
    by_f = {f.id: f for f in findings}
    by_t = {t.finding_id: t for t in triage}
    rows = [(fid, label) for fid, label in golden.items() if fid in by_t]
    if not rows:
        return {"labeled": len(golden), "matched": 0, "note": "이 실행에 해당하는 정답 라벨이 없습니다"}
    methods = {
        "cvss_sort": lambda fid: score.cvss_bucket(by_f[fid]),
        "rule_only": lambda fid: by_t[fid].rule_bucket,
        "rule_plus_agent": lambda fid: by_t[fid].final_bucket,
    }
    result: dict = {"labeled": len(golden), "matched": len(rows)}
    for name, pred in methods.items():
        hits = sum(pred(fid) == label for fid, label in rows)
        misses = [fid for fid, label in rows if label == "NOW" and pred(fid) == "MONITOR"]
        wrong = [{"finding_id": fid, "golden": label, "got": pred(fid)} for fid, label in rows if pred(fid) != label]
        result[name] = {"agreement_pct": round(hits / len(rows) * 100, 1), "now_missed": misses, "wrong": wrong}
    result["agent_judged"] = sum(by_t[fid].decided_by == "agent" for fid, _ in rows)
    return result
