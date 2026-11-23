"""CLI: python -m triage <scan|agent|verify|run|services|worker|db|eval|doctor|schema> ..."""
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
        with pg.connection() as conn:
            counts = {t: conn.execute(f"SELECT count(*) AS n FROM {t}").fetchone()["n"]
                      for t in ("runs", "findings", "triage", "events", "decisions", "http_cache", "jobs", "workers", "services")}
        print(json.dumps(counts, indent=1)); return 0
    pg.init()
    src = FileStore()
    dirs = a.run_dirs or [p.parent for p in sorted(runner.OUT.glob("*/meta.json"))]
    out = {d.name: migrate.import_run(src, pg, d.resolve()) for d in dirs}
    if not a.run_dirs:     # a full import also brings the registered services; ones already there are kept
        out["services"] = sum(pg.service_add(runner.OUT, s) for s in src.service_list(runner.OUT))
    if a.cache:
        out["http_cache"] = migrate.import_cache(pg)
    print(json.dumps(out, ensure_ascii=False, indent=1)); return 0


def services_command(a: argparse.Namespace) -> int:
    """Register services and re-check them. `check` runs here, in this process (handy for cron)."""
    from . import runner, services
    root = runner.OUT
    try:
        if a.action == "add":
            if not a.id or not a.target:
                print("사용: triage services add <id> <target> [--name ...]"); return 2
            baseline = a.baseline.resolve().name if a.baseline else None
            svc = services.register(root, a.id, a.name or a.id, a.target, context_of(a), a.owner,
                                    None if a.every == 0 else a.every, created_by="cli", current_run=baseline)
            print(svc.model_dump_json(indent=1)); return 0
        if a.action == "remove":
            ok = services.remove(root, a.id or "")
            print("등록을 지웠습니다. 실행 기록은 그대로 있습니다." if ok else "등록되지 않은 서비스입니다."); return 0 if ok else 1
        if a.action == "check":
            ids = [s.id for s in (services.due(root) if a.due else services.list_all(root))] if (a.all or a.due) else [a.id]
            if ids == [None]:
                print("사용: triage services check <id> | --all | --due"); return 2
            out = {i: services.check(root, i).model_dump(exclude={"changes"}) for i in ids}
            print(json.dumps(out, ensure_ascii=False, indent=1))
            return 1 if any(r["result"] == "failed" for r in out.values()) else 0
    except services.ServiceError as e:
        print(f"거절: {e}"); return 1
    rows = [{"id": s.id, "name": s.name, "target": s.target, "check_hours": s.check_hours, "current_run": s.current_run,
             "last_check": s.last_check and {"at": s.last_check.at, "result": s.last_check.result, **s.last_check.counts}}
            for s in services.list_all(root)]
    print(json.dumps(rows, ensure_ascii=False, indent=1)); return 0


def columns_of(text: str | None) -> dict[str, str] | None:
    """"name=Package,version=Ver" -> {"name": "Package", "version": "Ver"}."""
    if not text:
        return None
    pairs = [p.split("=", 1) for p in text.split(",") if "=" in p]
    return {k.strip(): v.strip() for k, v in pairs}


def inspect_command(a: argparse.Namespace) -> int:
    """What is this file or folder, and can the pipeline read it? Reads only; prints no file content."""
    from . import ingest
    if not a.target.exists():
        print(f"없는 경로: {a.target}"); return 2
    if a.target.is_file():
        rows = [ingest.describe(a.target, columns_of(a.columns), a.ecosystem)]
    else:
        rows = ingest.survey(a.target)
        repo = ingest.repo_files(a.target)
        if repo:
            print("저장소로 스캔할 때 읽는 의존성 파일: " + ", ".join(str(p.relative_to(a.target)) for p in repo))
    if a.json:
        print(json.dumps(rows, ensure_ascii=False, indent=1)); return 0
    if not rows:
        print("입력으로 쓸 수 있는 파일을 찾지 못했습니다."); return 1
    for r in rows:
        if not r["supported"]:
            print(f"[미지원] {r['file']}\n         {r['why']}"); continue
        eco = ", ".join(f"{k} {v}" for k, v in r["ecosystems"].items()) or "없음"
        print(f"[지원]   {r['file']}\n         형식 {r['format']}, 컴포넌트 {r['components']}개 ({eco}), 직접 {r['direct']}, 개발용 {r['dev']}, "
              f"입력이 보고한 취약점 {r['reported_vulnerabilities']}건")
        if r["not_scannable"]:
            print(f"         조회하지 못하는 컴포넌트: {r['not_scannable']}")
        for n in r["notes"]:
            print(f"         - {n}")
    return 0


def seed_command(a: argparse.Namespace) -> int:
    """Load vulnerability data files handed over on site, for places with no network."""
    import gzip
    from . import cache
    from .enrich import epss, kev
    out = {}
    read = lambda p: gzip.decompress(p.read_bytes()).decode() if p.suffix == ".gz" else p.read_text()  # noqa: E731
    if a.kev:
        body = json.loads(read(a.kev))
        if not isinstance(body.get("vulnerabilities"), list):
            print("KEV 파일이 아닙니다 (vulnerabilities 목록이 없음)"); return 1
        cache.seed(kev.URL, body)
        out["kev"] = len(body["vulnerabilities"])
    if a.epss:
        rows = epss.parse_csv(read(a.epss))
        if not rows:
            print("EPSS 파일에서 읽은 행이 없습니다 (cve,epss,percentile 형식이어야 함)"); return 1
        cache.snapshot_put("epss", rows)
        out["epss"] = len(rows)
    if not out:
        print("사용: triage seed --kev <known_exploited_vulnerabilities.json> --epss <epss_scores.csv[.gz]>"); return 2
    print(json.dumps(out)); return 0


def worker_command(a: argparse.Namespace) -> int:
    """Run queued jobs until told to stop. The job in hand is finished before the process exits."""
    import signal
    import threading
    from . import jobs, runner, store
    logging.getLogger().setLevel(logging.INFO)
    stop, me = threading.Event(), jobs.new_worker_id()

    def ask_to_stop(signum, _frame) -> None:
        if stop.is_set():                 # second signal: give up on the job in hand
            raise SystemExit(1)
        logging.info("worker %s: stopping after the job in hand", me)
        stop.set()

    signal.signal(signal.SIGTERM, ask_to_stop)
    signal.signal(signal.SIGINT, ask_to_stop)
    logging.info("worker %s: store=%s, watching the queue", me, store.get().name)
    handled = jobs.serve(runner.OUT, stop, a.poll, me, once=a.once)
    logging.info("worker %s: stopped after %d job(s)", me, handled)
    return 0


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
        p.add_argument("--columns", help="for a table or JSON record list: name=<column>,version=<column>[,ecosystem=,group=,vuln=,...]")
        p.add_argument("--ecosystem", help="for a table with no ecosystem column: npm, Maven, PyPI, Go, ...")
        context_args(p)
        if name == "run":
            p.add_argument("--limit", type=int, help="max findings sent to the LLM")
            p.add_argument("--setup", help="extra setup command in the sandbox, e.g. 'npx prisma generate'")
            p.add_argument("--no-verify", action="store_true")
    p = sub.add_parser("agent"); p.add_argument("run_dir", type=pathlib.Path); p.add_argument("--limit", type=int)
    p.add_argument("--labeled", action="store_true", help="judge only the findings that have a golden label")
    p.add_argument("--retry-failed", action="store_true", help="judge only the findings whose last LLM call failed")
    p.add_argument("--changed", action="store_true", help="judge only the findings a service re-check reported as new or moved")
    context_args(p)
    p = sub.add_parser("db", help="operating store (PostgreSQL): create tables, import file runs")
    p.add_argument("action", choices=["init", "import", "status"])
    p.add_argument("run_dirs", nargs="*", type=pathlib.Path, help="for import: run directories (default: every run under out/)")
    p.add_argument("--cache", action="store_true", help="for import: also copy fixtures/cache into the database")
    p = sub.add_parser("inspect", help="say what a file or folder is and whether the pipeline can read it")
    p.add_argument("target", type=pathlib.Path); p.add_argument("--json", action="store_true")
    p.add_argument("--columns"); p.add_argument("--ecosystem")
    p = sub.add_parser("seed", help="load KEV and EPSS data files for use without network")
    p.add_argument("--kev", type=pathlib.Path); p.add_argument("--epss", type=pathlib.Path)
    p = sub.add_parser("services", help="registered services: add, list, check (re-triage), remove")
    p.add_argument("action", choices=["add", "list", "check", "remove"])
    p.add_argument("id", nargs="?"); p.add_argument("target", nargs="?", help="for add: repo directory or SBOM file")
    p.add_argument("--name", help="for add: display name (default: the id)")
    p.add_argument("--owner", help="for add: team or person responsible")
    p.add_argument("--every", type=int, default=24, help="for add: hours between automatic checks, 0 = only on request")
    p.add_argument("--baseline", type=pathlib.Path, help="for add: an existing run directory to use as the current run")
    p.add_argument("--all", action="store_true", help="for check: every registered service")
    p.add_argument("--due", action="store_true", help="for check: only services whose interval has passed")
    context_args(p)
    p = sub.add_parser("worker", help="run queued jobs (sandbox passes started from the dashboard)")
    p.add_argument("--once", action="store_true", help="empty the queue and exit")
    p.add_argument("--poll", type=float, default=1.0, help="seconds between looks at an empty queue")
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
    if a.cmd == "worker":
        return worker_command(a)
    if a.cmd == "inspect":
        return inspect_command(a)
    if a.cmd == "seed":
        return seed_command(a)
    if a.cmd == "services":
        return services_command(a)
    if a.cmd == "doctor":
        return doctor.main(a.llm)
    if a.cmd == "schema":
        print(models.schema_json()); return 0
    if a.cmd in ("scan", "run"):
        from . import ingest
        try:
            run = runner.scan(a.target, a.name, context_of(a), use_syft=not a.no_syft, columns=columns_of(a.columns),
                              ecosystem=a.ecosystem)
        except ingest.UnsupportedInput as e:
            print(f"입력을 읽지 못했습니다: {e}\n형식 확인: uv run python -m triage inspect {a.target}"); return 1
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
        if a.changed:
            moved = {c["finding_id"] for c in run.meta.get("changes", []) if c["kind"] != "removed"}
            only = moved if only is None else only & moved
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
    shown = run.dir.relative_to(ROOT) if run.dir.is_relative_to(ROOT) else run.dir   # a run kept outside the repository
    print(json.dumps({"run_dir": str(shown), "sbom_source": meta["sbom_source"],
                      "coverage": meta["coverage"], "summary": meta["summary"], "llm": meta.get("llm"),
                      "seconds": meta["seconds"]}, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
