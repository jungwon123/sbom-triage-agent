"""Compare a sandbox attempt against the baseline: rescan its lockfile and diff tests."""
import importlib.util, json, pathlib, shutil, sys
spec = importlib.util.spec_from_file_location("rule_poc", "poc/rule_poc.py")
rp = importlib.util.module_from_spec(spec); spec.loader.exec_module(rp)
rp.CACHE.mkdir(parents=True, exist_ok=True)
base = {(f["id"], f["pkg"], f["ver"]): f for f in json.load(open("out/poc/realworld.json"))}
sb = pathlib.Path("out/poc/sandbox")
step = lambda steps, n: next(s for s in steps if s["name"] == n)
b_steps = json.load(open(sb / "baseline.json"))
for label in sys.argv[1:]:
    tmp = pathlib.Path(f"out/poc/tmp-{label}")
    shutil.rmtree(tmp, ignore_errors=True)
    shutil.copytree("fixtures/demo-repo", tmp, ignore=shutil.ignore_patterns(".git", "node_modules"))
    shutil.copy(sb / f"{label}.lock.json", tmp / "package-lock.json")
    shutil.copy(sb / f"{label}.package.json", tmp / "package.json")
    summary = rp.analyze(f"after-{label}", tmp)
    shutil.rmtree(tmp)
    after = {(f["id"], f["pkg"], f["ver"]): f for f in json.load(open(f"out/poc/after-{label}.json"))}
    now_before = {k for k, f in base.items() if f["bucket"] == "NOW"}
    steps = json.load(open(sb / f"{label}.json"))
    t0, t1 = step(b_steps, "test"), step(steps, "test")
    print(json.dumps({"label": label, "findings_before": len(base), "findings_after": len(after),
        "removed": len(set(base) - set(after)), "added": len(set(after) - set(base)),
        "now_after": summary["NOW"], "now_pkgs_after": summary["now_pkg_list"], "now_resolved": sorted({k[1] for k in now_before - set(after)}),
        "new_now": [k for k in set(after) - set(base) if after[k]["bucket"] == "NOW"],
        "build": step(steps, "build")["status"], "tests_base": t0["summary"], "tests_after": t1["summary"],
        "new_test_failures": sorted(set(t1["failed_tests"]) - set(t0["failed_tests"])),
        "fixed_tests": sorted(set(t0["failed_tests"]) - set(t1["failed_tests"])),
        "seconds": round(sum(s["seconds"] for s in steps), 1)}, ensure_ascii=False, indent=1))
