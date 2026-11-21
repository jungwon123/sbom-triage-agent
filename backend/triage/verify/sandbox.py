"""⑥ Throwaway Docker sandbox (F8). Called by runner.py, never by the agent.

The original repo is mounted read-only and copied into a volume; only the copy changes.
Install may use the network with --ignore-scripts; build and test run with --network none.
No environment variables from the host (API keys included) are passed in.
"""
from __future__ import annotations

import re
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from ..models import VerifyStep

IMAGE = "public.ecr.aws/docker/library/node:20-slim"
LIMITS = ["--rm", "--memory", "2g", "--cpus", "2", "--pids-limit", "512", "--cap-drop", "ALL",
          "--security-opt", "no-new-privileges", "-e", "NX_DAEMON=false", "-e", "CI=1"]
NPM = "--ignore-scripts --no-audit --no-fund"
STEP_LIMIT = {"copy": 60, "apply": 240, "install": 420, "setup": 180, "build": 300, "test": 300}
SAFE_SETUP = re.compile(r"^[A-Za-z0-9 ._:/@=-]+$")


def available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=15).returncode == 0
    except subprocess.TimeoutExpired:
        return False


def parse_tests(text: str) -> tuple[list[str], int]:
    """-> (failed test names, tests run). Jest and Mocha summaries."""
    failed = sorted(set(re.findall(r"●\s+(.+ › .+)", text)))
    m = re.search(r"^Tests:.*?(\d+) total", text, re.M)
    if m:
        return failed, int(m.group(1))
    passing = re.search(r"(\d+) passing", text)
    failing = re.search(r"(\d+) failing", text)
    return failed, (int(passing.group(1)) if passing else 0) + (int(failing.group(1)) if failing else 0)


@dataclass
class Result:
    steps: list[VerifyStep] = field(default_factory=list)
    lockfile: str | None = None
    package_json: str | None = None

    def step(self, name: str) -> VerifyStep | None:
        return next((s for s in self.steps if s.name == name), None)


def run(repo: Path, apply_cmd: str | None = None, setup_cmd: str | None = None,
        scale: float = 1.0) -> Result:
    """One full pass in a fresh volume. apply_cmd comes from verify/apply.py only."""
    if setup_cmd and not SAFE_SETUP.match(setup_cmd):
        raise ValueError("setup command has unexpected characters")
    repo = repo.resolve()
    vol = f"triage-{uuid.uuid4().hex[:10]}"
    res = Result()

    def step(name: str, cmd: str, network: str) -> bool:
        container = f"{vol}-{name}"
        args = ["docker", "run", "--name", container, *LIMITS, "-v", f"{vol}:/work", "-v", f"{repo}:/src:ro", "-w", "/work"]
        if network == "none":
            args += ["--network", "none"]
        start = time.time()
        timed_out = False
        try:
            r = subprocess.run([*args, IMAGE, "sh", "-c", cmd], capture_output=True, text=True,
                               timeout=STEP_LIMIT[name] * scale)
            code, text = r.returncode, r.stdout + r.stderr
        except subprocess.TimeoutExpired:
            code, text, timed_out = 124, "timeout", True
            # the timeout only ends the docker client; the container would run on and hold its memory
            subprocess.run(["docker", "kill", container], capture_output=True, timeout=30)
        failed, total = parse_tests(text) if name == "test" else ([], 0)
        res.steps.append(VerifyStep(
            name=name, status="passed" if code == 0 else "failed", duration_ms=int((time.time() - start) * 1000),
            log_tail="\n".join(text.splitlines()[-15:])[-1800:], failed_tests=failed, tests_run=total,
            timed_out=timed_out))
        return code == 0

    def skip(name: str) -> None:
        res.steps.append(VerifyStep(name=name, status="skipped", duration_ms=0, log_tail=""))

    def cat(path: str) -> str | None:
        r = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", f"{vol}:/work", IMAGE, "cat", path],
                           capture_output=True, text=True, timeout=60)
        return r.stdout if r.returncode == 0 else None

    subprocess.run(["docker", "volume", "create", vol], capture_output=True)
    try:
        ok = step("copy", "cp -a /src/. /work/ && rm -rf /work/.git /work/node_modules", "none")
        if ok and apply_cmd:
            ok = step("apply", apply_cmd, "bridge")
        if ok:
            # baseline keeps `npm ci`; after a change the lockfile was rewritten, so `npm install` (F8-13)
            ok = step("install", ("npm install " if apply_cmd else "npm ci ") + NPM, "bridge")
        if ok and setup_cmd:
            ok = step("setup", setup_cmd, "bridge")
        if ok:
            scripts = cat("/work/package.json") or ""
            has = lambda s: bool(re.search(rf'"{s}"\s*:', scripts))  # noqa: E731
            step("build", "npm run build", "none") if has("build") else skip("build")
            step("test", "npm test", "none") if has("test") else skip("test")
        res.lockfile = cat("/work/package-lock.json")
        res.package_json = cat("/work/package.json")
    finally:
        subprocess.run(["docker", "volume", "rm", "-f", vol], capture_output=True)
    return res
