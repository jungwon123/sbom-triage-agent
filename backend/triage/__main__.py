"""CLI: python -m triage <scan|agent|verify|run|eval|doctor|schema> ..."""
from __future__ import annotations

import argparse
import json
import logging
import os
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]


def load_env(path: pathlib.Path = ROOT / ".env") -> None:
    """Minimal .env loader. Values are never printed."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            if v.strip():
                os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def main(argv: list[str] | None = None) -> int:
    load_env()
    from . import doctor, eval as eval_mod, models, runner
    from .models import ServiceContext

    ap = argparse.ArgumentParser(prog="triage")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("scan", "run"):
        p = sub.add_parser(name, help="①~④ scan" if name == "scan" else "①~⑥ scan + agent + verify")
        p.add_argument("target", type=pathlib.Path, help="repo directory or SBOM file (CycloneDX/SPDX JSON)")
        p.add_argument("--name")
        p.add_argument("--no-syft", action="store_true")
        p.add_argument("--criticality", choices=["high", "medium", "low"])
        p.add_argument("--internet-facing", choices=["yes", "no"])
        if name == "run":
            p.add_argument("--limit", type=int, help="max findings sent to the LLM")
            p.add_argument("--setup", help="extra setup command in the sandbox, e.g. 'npx prisma generate'")
            p.add_argument("--no-verify", action="store_true")
    p = sub.add_parser("agent"); p.add_argument("run_dir", type=pathlib.Path); p.add_argument("--limit", type=int)
    p = sub.add_parser("verify"); p.add_argument("run_dir", type=pathlib.Path); p.add_argument("--setup")
    p = sub.add_parser("notify", help="send the run summary to Slack (SLACK_WEBHOOK_URL)")
    p.add_argument("run_dir", type=pathlib.Path)
    p.add_argument("--dry-run", action="store_true", help="print the message instead of sending it")
    p.add_argument("--link", help="dashboard URL to include, e.g. http://triage.internal/?run=<id>")
    p = sub.add_parser("compare", help="run several LLM configurations on one run and score each")
    p.add_argument("run_dir", type=pathlib.Path)
    p.add_argument("--configs", default="rule,api,local,split", help="comma list of: " + ", ".join(runner.CONFIGS))
    p.add_argument("--limit", type=int); p.add_argument("--golden", type=pathlib.Path, default=None)
    p = sub.add_parser("eval"); p.add_argument("run_dir", type=pathlib.Path)
    p.add_argument("--golden", type=pathlib.Path, default=None)
    p = sub.add_parser("doctor"); p.add_argument("--llm", action="store_true", help="also make one small LLM call")
    sub.add_parser("schema")
    a = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    if a.cmd == "doctor":
        return doctor.main(a.llm)
    if a.cmd == "schema":
        print(models.schema_json()); return 0
    if a.cmd in ("scan", "run"):
        ctx = ServiceContext(service_criticality=a.criticality,
                             internet_facing={"yes": True, "no": False}.get(a.internet_facing))
        run = runner.scan(a.target, a.name, ctx, use_syft=not a.no_syft)
        if a.cmd == "run":
            runner.agent(run, a.limit)
            if not a.no_verify:
                runner.verify(run, a.setup)
    elif a.cmd == "notify":
        from . import notify
        run = runner.Run(a.run_dir)
        payload = notify.build_message(run.meta["name"], run.findings(), run.triage(), a.link)
        sent, detail = notify.send(payload, a.dry_run)
        run.emit({"type": "notify", "channel": "slack", "sent": sent, "detail": detail})
        if not sent:
            print(json.dumps(payload, ensure_ascii=False, indent=1))
        print(f"sent={sent} ({detail})")
        return 0 if sent or a.dry_run else 1
    elif a.cmd == "agent":
        run = runner.agent(runner.Run(a.run_dir), a.limit)
    elif a.cmd == "verify":
        run = runner.verify(runner.Run(a.run_dir), a.setup)
    else:  # eval, compare
        run = runner.Run(a.run_dir)
        golden = a.golden or next((p for p in (ROOT / "fixtures/golden.yaml", ROOT / "fixtures/golden-sheet.csv") if p.exists()), None)
        if a.cmd == "compare":
            names = [n.strip() for n in a.configs.split(",") if n.strip()]
            unknown = [n for n in names if n not in runner.CONFIGS]
            if unknown:
                print(f"unknown config: {unknown}"); return 2
            labels = eval_mod.load_golden(golden) if golden else {}
            print(json.dumps(runner.compare(run, names, labels, a.limit), ensure_ascii=False, indent=1)); return 0
        if golden is None:
            print("정답 파일이 없습니다 (fixtures/golden.yaml 또는 golden-sheet.csv)"); return 1
        result = eval_mod.evaluate(run.findings(), run.triage(), eval_mod.load_golden(golden))
        run.write("eval.json", result)
        print(json.dumps(result, ensure_ascii=False, indent=1)); return 0
    meta = run.meta
    print(json.dumps({"run_dir": str(run.dir.relative_to(ROOT)), "sbom_source": meta["sbom_source"],
                      "coverage": meta["coverage"], "summary": meta["summary"], "llm": meta.get("llm"),
                      "seconds": meta["seconds"]}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
