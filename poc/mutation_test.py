"""Scenario 2: mutate a repo copy in memory so the correct usage state is known, then check the rule detector."""
import importlib.util, json, re

spec = importlib.util.spec_from_file_location("rule_poc", "poc/rule_poc.py")
rp = importlib.util.module_from_spec(spec); spec.loader.exec_module(rp)
import pathlib
repo = pathlib.Path("fixtures/demo-repo")
BASE = list(rp.sources(repo))
PKGS = ["axios", "body-parser", "express", "cors", "jsonwebtoken", "bcryptjs"]


def strip(files, pkg, runtime_only=True):
    pat = re.compile(rf"""^.*(from\s+|require\(\s*|import\(\s*|import\s+)['"]{re.escape(pkg)}(/[^'"]*)?['"].*$""", re.M)
    return [(r, t if runtime_only and rp.TEST_PATH.search(r) else pat.sub("", t)) for r, t in files]


def mutate(kind, pkg):
    clean = strip(BASE, pkg, runtime_only=False)
    if kind == "add_runtime":
        return clean + [("src/app/poc.ts", f"import lib from '{pkg}';\nlib();\n")], "runtime"
    if kind == "remove_all":
        return clean, "none"
    if kind == "move_to_test":
        return clean + [("src/tests/poc.test.ts", f"import lib from '{pkg}';\n")], "test"
    if kind == "comment_only":
        return clean + [("src/app/poc.ts", f"// import lib from '{pkg}';\n")], "none"
    if kind == "string_only":
        return clean + [("src/app/poc.ts", f"export const doc = \"const lib = require('{pkg}')\";\n")], "none"
    if kind == "dynamic_name":
        return clean + [("src/app/poc.ts", f"const name = '{pkg}';\nexport const lib = require(name);\n")], "runtime"
    raise ValueError(kind)


KINDS = ["add_runtime", "remove_all", "move_to_test", "comment_only", "string_only", "dynamic_name"]
rows = []
for kind in KINDS:
    for pkg in PKGS:
        files, truth = mutate(kind, pkg)
        runtime, test = rp.sites(pkg, files)
        got = "runtime" if runtime else "test" if test else "none"
        rows.append({"kind": kind, "pkg": pkg, "truth": truth, "got": got, "ok": got == truth})
by = {k: f"{sum(r['ok'] for r in rows if r['kind']==k)}/{len(PKGS)}" for k in KINDS}
ok = sum(r["ok"] for r in rows)
print(json.dumps({"total": len(rows), "correct": ok, "accuracy_pct": round(ok / len(rows) * 100, 1), "by_kind": by}, ensure_ascii=False, indent=1))
json.dump(rows, open("out/poc/mutation.json", "w"), ensure_ascii=False, indent=1)
