"""Sandbox PoC: run a repo copy in throwaway containers.
usage: python poc/sandbox_poc.py <repo_dir> <label> [apply-shell-command]
The apply command is written by a person here; the product builds it in verify/apply.py."""
import json, pathlib, re, subprocess, sys, time, uuid

repo = pathlib.Path(sys.argv[1]).resolve()
label = sys.argv[2]
apply_cmd = sys.argv[3] if len(sys.argv) > 3 else ""
IMAGE = "public.ecr.aws/docker/library/node:20-slim"
vol = f"poc-{uuid.uuid4().hex[:8]}"
LIMITS = ["--rm", "--memory", "2g", "--cpus", "2", "--pids-limit", "512", "--cap-drop", "ALL",
          "--security-opt", "no-new-privileges", "-e", "NX_DAEMON=false", "-e", "CI=1"]
out = pathlib.Path("out/poc/sandbox"); out.mkdir(parents=True, exist_ok=True)
steps = []


def run(name, cmd, network, limit=300):
    args = ["docker", "run", *LIMITS, "-v", f"{vol}:/work", "-v", f"{repo}:/src:ro", "-w", "/work"]
    if network == "none":
        args += ["--network", "none"]
    start = time.time()
    try:
        r = subprocess.run([*args, IMAGE, "sh", "-c", cmd], capture_output=True, text=True, timeout=limit)
        code, text = r.returncode, r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        code, text = 124, "timeout"
    steps.append({"name": name, "status": "passed" if code == 0 else "failed", "code": code, "network": network,
                  "seconds": round(time.time() - start, 1), "log_tail": "\n".join(text.splitlines()[-12:])[-1500:],
                  "failed_tests": sorted(set(re.findall(r"●\s+(.+ › .+)", text))),
                  "summary": next(iter(re.findall(r"^Tests:.*$", text, re.M)), "")})
    print(name, steps[-1]["status"], steps[-1]["seconds"], flush=True)
    return code == 0


subprocess.run(["docker", "volume", "create", vol], capture_output=True)
try:
    ok = run("copy", "cp -a /src/. /work/ && rm -rf /work/.git", "none")
    if apply_cmd:
        ok = run("apply", apply_cmd, "bridge") and ok
    ok = run("install", "npm ci --ignore-scripts --no-audit --no-fund", "bridge", 420) and ok
    run("prisma_generate", "npx prisma generate", "bridge", 180)
    run("no_network_check", "node -e \"fetch('https://registry.npmjs.org').then(()=>process.exit(0),()=>process.exit(7))\"", "none", 60)
    run("build", "npm run build", "none", 300)
    run("test", "npm test", "none", 300)
    lock = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{vol}:/work", IMAGE, "cat", "/work/package-lock.json"], capture_output=True, text=True).stdout
    (out / f"{label}.lock.json").write_text(lock)
    manifest = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{vol}:/work", IMAGE, "cat", "/work/package.json"], capture_output=True, text=True).stdout
    (out / f"{label}.package.json").write_text(manifest)
finally:
    subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True)
(out / f"{label}.json").write_text(json.dumps(steps, ensure_ascii=False, indent=1))
