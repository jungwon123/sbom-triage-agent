"""Scenario 1: verify every NOW package with the minimum and the highest fix version.
Apply commands are built here from validated lockfile data, as verify/apply.py will."""
import concurrent.futures as cf, importlib.util, json, os, pathlib, re, shutil, subprocess, sys, threading, time

spec = importlib.util.spec_from_file_location("rule_poc", "poc/rule_poc.py")
rp = importlib.util.module_from_spec(spec); spec.loader.exec_module(rp)
rp.CACHE.mkdir(parents=True, exist_ok=True)
REPOS = {"realworld": ("fixtures/demo-repo", "npx prisma generate"),
         "mongoose": ("fixtures/eval/node-express-mongoose", ""),
         "nodegoat": ("fixtures/eval/NodeGoat", "")}
SB = pathlib.Path("out/poc/sandbox")
SAFE = re.compile(r"^(@[a-z0-9._-]+/)?[a-z0-9._-]+$|^\d+\.\d+\.\d+[0-9A-Za-z.-]*$")
NPM = "--package-lock-only --ignore-scripts --no-audit --no-fund"
lock = threading.Lock()


def sandbox(repo, setup, label, apply_cmd=""):
    env = {**os.environ, "SETUP_CMD": setup}
    if apply_cmd and os.environ.get("RETRY_FILE"):
        env["INSTALL_CMD"] = "npm install"
    subprocess.run([sys.executable, "poc/sandbox_poc.py", repo, label, apply_cmd], env=env, capture_output=True)
    return json.load(open(SB / f"{label}.json"))


def apply_cmd(pkg, old, new, direct):
    """Remove stale lock entries of the old version too: npm otherwise keeps hoisted copies."""
    assert SAFE.match(pkg) and SAFE.match(new) and SAFE.match(old)
    prune = ("const s=require('fs'),l=JSON.parse(s.readFileSync('package-lock.json'));"
             f"for(const k of Object.keys(l.packages))if(k.endsWith('node_modules/{pkg}')&&l.packages[k].version==='{old}')delete l.packages[k];"
             "delete l.dependencies;s.writeFileSync('package-lock.json',JSON.stringify(l,null,2))")
    if direct:
        return f"npm install {pkg}@{new} {NPM} && node -e \"{prune}\" && npm install {NPM}"
    js = ("const f='package.json',s=require('fs'),p=JSON.parse(s.readFileSync(f));"
          f"p.overrides={{...p.overrides,'{pkg}@{old}':'{new}'}};s.writeFileSync(f,JSON.stringify(p,null,2))")
    return f"node -e \"{js}\" && node -e \"{prune}\" && npm install {NPM}"


def step(steps, name):
    return next((s for s in steps if s["name"] == name), None)


def verdict(steps, base_steps, target_left, new_now):
    for name in ("copy", "apply", "install", "setup"):
        s = step(steps, name)
        if s and s["status"] == "failed":
            return "failed", f"{name}_failed"
    if target_left:
        return "failed", "target_remains"
    if new_now:
        return "failed", "new_now"
    b0, b1 = step(base_steps, "build"), step(steps, "build")
    if b0["status"] == "passed" and b1["status"] == "failed":
        return "failed", "build_regression"
    t0, t1 = step(base_steps, "test"), step(steps, "test")
    if t0["status"] == "passed" and t1["status"] == "failed":
        return "failed", "test_regression"
    if t0["status"] == "failed":
        if not t0["failed_tests"]:
            return "inconclusive", "baseline_test_uncomparable"
        if set(t1["failed_tests"]) - set(t0["failed_tests"]):
            return "failed", "test_regression"
    if b0["status"] == "failed":
        return "inconclusive", "baseline_build_failed"
    return "verified", "ok"


def attempt(name, repo, setup, job, base_steps, base):
    label = f"{name}-{job['variant']}-{job['pkg'].replace('/', '_')}-{job['old']}"
    start = time.time()
    steps = sandbox(repo, setup, label, apply_cmd(job["pkg"], job["old"], job["new"], job["direct"]))
    rec = {**job, "repo": name, "steps": {s["name"]: s["status"] for s in steps}, "seconds": round(time.time() - start, 1)}
    lockfile = SB / f"{label}.lock.json"
    try:
        json.loads(lockfile.read_text())
        with lock:
            tmp = pathlib.Path(f"out/poc/tmp-{label}")
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.copytree(repo, tmp, ignore=shutil.ignore_patterns(".git", "node_modules"))
            shutil.copy(lockfile, tmp / "package-lock.json")
            shutil.copy(SB / f"{label}.package.json", tmp / "package.json")
            rp.analyze(f"after-{label}", tmp)
            shutil.rmtree(tmp)
        after = {(f["id"], f["pkg"], f["ver"]): f for f in json.load(open(f"out/poc/after-{label}.json"))}
    except Exception as e:
        rec.update(verdict="failed", reason=f"rescan_error:{type(e).__name__}")
        return rec
    left = [k for k in job["targets"] if tuple(k) in after]
    added = [k for k in after if k not in base]
    new_now = [list(k) for k in added if after[k]["bucket"] == "NOW"]
    same_pkg = [f for k, f in after.items() if k[1] == job["pkg"] and (f["cvss"] or 0) >= 7]
    v, why = verdict(steps, base_steps, left, new_now)
    rec.update(verdict=v, reason=why, findings_before=len(base), findings_after=len(after), new_findings=len(added),
               new_now=new_now, residual_high_same_pkg=len(same_pkg), new_test_failures=sorted(set((step(steps, "test") or {}).get("failed_tests", [])) - set((step(base_steps, "test") or {}).get("failed_tests", []))))
    return rec


def main():
    jobs = []
    for name, (repo, setup) in REPOS.items():
        base_list = json.load(open(f"out/poc/{name}.json"))
        by = {}
        for f in base_list:
            by.setdefault((f["pkg"], f["ver"]), []).append(f)
        for (pkg, old), fs in by.items():
            now = [f for f in fs if f["bucket"] == "NOW"]
            if not now:
                continue
            need = [f["fixed"] for f in now if f["fixed"]]
            allf = [f["fixed"] for f in fs if f["fixed"]]
            lo, hi = max(need, key=rp.semver), max(allf, key=rp.semver)
            base_job = {"pkg": pkg, "old": old, "direct": now[0]["direct"], "targets": [[f["id"], pkg, old] for f in now]}
            jobs.append((name, repo, setup, {**base_job, "variant": "min", "new": lo}))
            if hi != lo:
                jobs.append((name, repo, setup, {**base_job, "variant": "max", "new": hi}))
    retry = os.environ.get("RETRY_FILE")
    if retry:
        todo = {(r["repo"], r["pkg"], r["old"], r["variant"]) for r in map(json.loads, open(retry)) if r["reason"] == "install_failed"}
        jobs = [j for j in jobs if (j[0], j[3]["pkg"], j[3]["old"], j[3]["variant"]) in todo]
    print("jobs", len(jobs), flush=True)
    base_steps = {}
    with cf.ThreadPoolExecutor(3) as ex:
        for name, res in zip(REPOS, ex.map(lambda n: sandbox(REPOS[n][0], REPOS[n][1], f"{n}-baseline"), REPOS)):
            base_steps[name] = res
            print(name, {s["name"]: s["status"] for s in res}, res[-1]["summary"], flush=True)
        results = []
        out = open(os.environ.get("OUT_FILE", "out/poc/verify_all.jsonl"), "w")
        def one(j):
            name, repo, setup, job = j
            base = {(f["id"], f["pkg"], f["ver"]): f for f in json.load(open(f"out/poc/{name}.json"))}
            try:
                return attempt(name, repo, setup, job, base_steps[name], base)
            except Exception as e:
                return {**job, "repo": name, "verdict": "failed", "reason": f"runner_error:{e!r}"}
        for r in ex.map(one, jobs):
            out.write(json.dumps(r, ensure_ascii=False) + "\n"); out.flush()
            print(r["repo"], r["pkg"], r["variant"], r["new"], r["verdict"], r["reason"], r.get("seconds"), flush=True)


if __name__ == "__main__":
    main()
