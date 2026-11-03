"""Scenario 3: stratified sample of findings as a blind labeling sheet.
Rule outputs stay out of the sheet; the key goes to out/ for scoring later."""
import csv, importlib.util, json, pathlib, random

spec = importlib.util.spec_from_file_location("rule_poc", "poc/rule_poc.py")
rp = importlib.util.module_from_spec(spec); spec.loader.exec_module(rp)
SEED = 20261031
PLAN = {"realworld": ("fixtures/demo-repo", {"NOW": 2, "NEXT": 4, "MONITOR": 4}),
        "nodegoat": ("fixtures/eval/NodeGoat", {"NOW": 2, "NEXT": 2, "MONITOR": 1}),
        "mongoose": ("fixtures/eval/node-express-mongoose", {"NOW": 2, "NEXT": 2, "MONITOR": 1})}
advisory = {}
for f in rp.CACHE.glob("*.json"):
    d = json.loads(f.read_text())
    if isinstance(d, dict) and d.get("id") and "affected" in d:
        for key in [d["id"], *d.get("aliases", [])]:
            advisory.setdefault(key, d)
rng = random.Random(SEED)
rows, key = [], {}
for name, (repo, plan) in PLAN.items():
    findings = json.load(open(f"out/poc/{name}.json"))
    files = list(rp.sources(pathlib.Path(repo)))
    for bucket, n in plan.items():
        pool = sorted((f for f in findings if f["bucket"] == bucket), key=lambda f: (f["pkg"], f["ver"], f["id"]))
        rng.shuffle(pool)
        chosen, seen = [], set()
        for f in pool:
            if f["pkg"] not in seen:
                seen.add(f["pkg"]); chosen.append(f)
            if len(chosen) == n:
                break
        for f in chosen:
            runtime, test = rp.sites(f["pkg"], files)
            adv = advisory.get(f["id"], {})
            rows.append({
                "repo": name, "package": f["pkg"], "version": f["ver"], "advisory": f["id"],
                "scope": "dev" if f["dev"] else "prod", "dependency": "direct" if f["direct"] else "transitive",
                "cvss": f["cvss"], "epss_percentile": f["pct"] if f["pct"] is not None else "없음", "kev": "예" if f["kev"] else "아니오",
                "fixed_in": f["fixed"] or "없음", "upgrade_size": f["bump"],
                "runtime_files": "; ".join(runtime[:4]) or "없음", "test_files": "; ".join(test[:4]) or "없음",
                "summary": (adv.get("summary") or "").replace("\n", " ")[:140],
                "link": f"https://osv.dev/vulnerability/{adv.get('id', f['id'])}",
                "label(NOW/NEXT/MONITOR)": "", "confidence(상/중/하)": "", "memo": "",
            })
            key[f"{name}|{f['pkg']}|{f['ver']}|{f['id']}"] = {"bucket": f["bucket"], "risk": f["risk"]}
rng.shuffle(rows)
for i, r in enumerate(rows, 1):
    r = {"item": f"G{i:02d}", **r}
    rows[i - 1] = r
with open("fixtures/golden-sheet.csv", "w", newline="", encoding="utf-8-sig") as out:
    w = csv.DictWriter(out, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
pathlib.Path("out/poc/golden-key.json").write_text(json.dumps(key, ensure_ascii=False, indent=1))
print(len(rows))
