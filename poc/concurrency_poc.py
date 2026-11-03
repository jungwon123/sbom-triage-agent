"""Operations PoC: sandbox throughput by number of concurrent containers.
Runs the same fixed job list at each level. Host rescan is excluded: it is not a container cost.
usage: python poc/concurrency_poc.py"""
import concurrent.futures as cf, importlib.util, json, os, pathlib, subprocess, sys, threading, time

spec = importlib.util.spec_from_file_location("verify_all", "poc/verify_all.py")
va = importlib.util.module_from_spec(spec); spec.loader.exec_module(va)

JOBS = [("realworld", "body-parser", "1.20.2", "1.20.3", True),
        ("nodegoat", "minimist", "1.2.5", "1.2.6", False),
        ("realworld", "form-data", "4.0.0", "4.0.6", False),
        ("nodegoat", "body-parser", "1.18.3", "1.20.3", True)] * 3
LEVELS = (8, 1, 4, 12, 2)
PASSES = 2
OUT = pathlib.Path("out/poc/concurrency.jsonl")


def run_job(index: int, job: tuple, level: int, passno: int) -> dict:
    name, pkg, old, new, direct = job
    repo, setup = va.REPOS[name]
    label = f"conc-p{passno}-l{level}-{index}"
    env = {**os.environ, "SETUP_CMD": setup, "INSTALL_CMD": "npm install"}
    start = time.time()
    subprocess.run([sys.executable, "poc/sandbox_poc.py", repo, label, va.apply_cmd(pkg, old, new, direct)],
                   env=env, capture_output=True)
    steps = json.load(open(va.SB / f"{label}.json"))
    return {"repo": name, "pkg": pkg, "seconds": round(time.time() - start, 1),
            "steps": {s["name"]: (s["status"], s["seconds"], s["code"]) for s in steps},
            "test_summary": next((s["summary"] for s in steps if s["name"] == "test"), "")}


def sample_memory(stop: threading.Event, peaks: list) -> None:
    while not stop.is_set():
        out = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}"], capture_output=True, text=True).stdout
        used = 0.0
        for line in out.splitlines():
            value = line.split("/")[0].strip()
            used += float(value[:-3]) * (1024 if value.endswith("GiB") else 1) if value.endswith(("GiB", "MiB")) else 0
        peaks.append(used)
        stop.wait(2)


def main() -> None:
    with OUT.open("a") as out:
        for passno in range(1, PASSES + 1):
            for level in LEVELS:
                stop, peaks = threading.Event(), []
                sampler = threading.Thread(target=sample_memory, args=(stop, peaks))
                sampler.start()
                start = time.time()
                with cf.ThreadPoolExecutor(level) as ex:
                    rows = list(ex.map(lambda p: run_job(p[0], p[1], level, passno), enumerate(JOBS)))
                wall = time.time() - start
                stop.set(); sampler.join()
                rec = {"pass": passno, "level": level, "wall_seconds": round(wall, 1),
                       "jobs_per_min": round(len(JOBS) / wall * 60, 1), "peak_mem_mib": round(max(peaks or [0])), "jobs": rows}
                out.write(json.dumps(rec) + "\n"); out.flush()
                print(passno, level, rec["wall_seconds"], rec["jobs_per_min"], rec["peak_mem_mib"], flush=True)


if __name__ == "__main__":
    main()
