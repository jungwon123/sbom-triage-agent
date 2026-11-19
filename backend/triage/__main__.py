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


def context_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--criticality", choices=["high", "medium", "low"])
    p.add_argument("--internet-facing", choices=["yes", "no"])
    p.add_argument("--service-note", help="a few words on what the service does and who can reach it")


def context_of(a: argparse.Namespace):
    from .models import ServiceContext
    return ServiceContext(service_criticality=a.criticality, note=a.service_note,
                          internet_facing={"yes": True, "no": False}.get(a.internet_facing))


def db_command(a: argparse.Namespace) -> int:
    from . import runner
    from .store import migrate
    from .store.files import FileStore
    from .store.postgres import PostgresStore
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("DATABASE_URL이 없습니다. .env에 넣거나 deploy/docker-compose.yml의 예시를 참고하세요."); return 1
    pg = PostgresStore(url)
    if a.action == "init":
        print(json.dumps({"schema_version": pg.init()})); return 0
    if a.action == "status":
        conn = pg._conn()
        counts = {t: conn.execute(f"SELECT count(*) AS n FROM {t}").fetchone()["n"]
                  for t in ("runs", "findings", "triage", "events", "decisions", "http_cache")}
        print(json.dumps(counts, indent=1)); return 0
    pg.init()
    src = FileStore()
    dirs = a.run_dirs or [p.parent for p in sorted(runner.OUT.glob("*/meta.json"))]
    out = {d.name: migrate.import_run(src, pg, d.resolve()) for d in dirs}
    if a.cache:
        out["http_cache"] = migrate.import_cache(pg)
    print(json.dumps(out, ensure_ascii=False, indent=1)); return 0


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
        context_args(p)
        if name == "run":
            p.add_argument("--limit", type=int, help="max findings sent to the LLM")
            p.add_argument("--setup", help="extra setup command in the sandbox, e.g. 'npx prisma generate'")
            p.add_argument("--no-verify", action="store_true")
    p = sub.add_parser("agent"); p.add_argument("run_dir", type=pathlib.Path); p.add_argument("--limit", type=int)
    p.add_argument("--labeled", action="store_true", help="judge only the findings that have a golden label")
    p.add_argument("--retry-failed", action="store_true", help="judge only the findings whose last LLM call failed")
    context_args(p)
    p = sub.add_parser("db", help="operating store (PostgreSQL): create tables, import file runs")
    p.add_argument("action", choices=["init", "import", "status"])
    p.add_argument("run_dirs", nargs="*", type=pathlib.Path, help="for import: run directories (default: every run under out/)")
    p.add_argument("--cache", action="store_true", help="for import: also copy fixtures/cache into the database")
    p = sub.add_parser("rescore", help="re-apply the current rules and checks to a stored run (no model calls)")
    p.add_argument("run_dir", type=pathlib.Path)
    p = sub.add_parser("verify"); p.add_argument("run_dir", type=pathlib.Path); p.add_argument("--setup")
    p.add_argument("--buckets", default="NOW", help="comma list of buckets to verify, e.g. NOW,NEXT")
    p = sub.add_parser("decide", help="record the owner's call on one proposed change")
    p.add_argument("run_dir", type=pathlib.Path); p.add_argument("target", help="<package>@<version>")
    p.add_argument("status", choices=["approved", "rejected", "held"])
    p.add_argument("--by", required=True); p.add_argument("--reason", default="")
    p = sub.add_parser("export", help="write patches and a PR draft for the approved changes (nothing is pushed)")
    p.add_argument("run_dir", type=pathlib.Path)
    p.add_argument("--together", action="store_true", help="apply every approved change in one sandbox pass and export one patch")
    p.add_argument("--setup", help="setup command for the sandbox; defaults to the one used by verify")
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

    if a.cmd == "db":
        return db_command(a)
    if a.cmd == "doctor":
        return doctor.main(a.llm)
    if a.cmd == "schema":
        print(models.schema_json()); return 0
    if a.cmd in ("scan", "run"):
        run = runner.scan(a.target, a.name, context_of(a), use_syft=not a.no_syft)
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
        run = runner.Run(a.run_dir)
        if context_of(a).model_dump(exclude_none=True):
            run.set_context(context_of(a))
        only = None
        if a.labeled:
            sheet = next((p for p in (ROOT / "fixtures/golden.yaml", ROOT / "fixtures/golden-sheet.csv") if p.exists()), None)
            only = set(eval_mod.load_golden(sheet, run.meta.get("name"))) if sheet else set()
        if a.retry_failed:
            failed = {t.finding_id for t in run.triage() if t.decided_by == "agent_fallback"}
            only = failed if only is None else only & failed
        run = runner.agent(run, a.limit, only=only)
    elif a.cmd == "rescore":
        run = runner.rescore(runner.Run(a.run_dir))
    elif a.cmd == "verify":
        buckets = tuple(b.strip().upper() for b in a.buckets.split(",") if b.strip())
        run = runner.verify(runner.Run(a.run_dir), a.setup, buckets)
    elif a.cmd == "decide":
        from . import decide
        try:
            d = decide.record(runner.Run(a.run_dir), a.target, a.status, a.by, a.reason)
        except decide.DecisionError as e:
            print(f"거절: {e}"); return 1
        print(d.model_dump_json(indent=1)); return 0
    elif a.cmd == "export":
        from . import decide
        out = decide.export(runner.Run(a.run_dir), a.together, a.setup)
        print(json.dumps(out, ensure_ascii=False, indent=1)); return 0
    else:  # eval, compare
        run = runner.Run(a.run_dir)
        golden = a.golden or next((p for p in (ROOT / "fixtures/golden.yaml", ROOT / "fixtures/golden-sheet.csv") if p.exists()), None)
        if a.cmd == "compare":
            names = [n.strip() for n in a.configs.split(",") if n.strip()]
            unknown = [n for n in names if n not in runner.CONFIGS]
            if unknown:
                print(f"unknown config: {unknown}"); return 2
            labels = eval_mod.load_golden(golden, run.meta.get("name")) if golden else {}
            print(json.dumps(runner.compare(run, names, labels, a.limit), ensure_ascii=False, indent=1)); return 0
        if golden is None:
            print("정답 파일이 없습니다 (fixtures/golden.yaml 또는 golden-sheet.csv)"); return 1
        result = eval_mod.evaluate(run.findings(), run.triage(), eval_mod.load_golden(golden, run.meta.get("name")))
        run.write("eval.json", result)
        print(json.dumps(result, ensure_ascii=False, indent=1)); return 0
    meta = run.meta
    print(json.dumps({"run_dir": str(run.dir.relative_to(ROOT)), "sbom_source": meta["sbom_source"],
                      "coverage": meta["coverage"], "summary": meta["summary"], "llm": meta.get("llm"),
                      "seconds": meta["seconds"]}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
