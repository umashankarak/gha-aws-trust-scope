"""
Check every number in the Paper 10 manuscript against the data files.

    python3 src/verify_numbers.py

Reads data/coded_resolved.csv, data/label_holdout_sample.csv, data/labels_holdout.csv,
data/corrected_estimates.csv, data/analysis_extra.txt and the owned-infra evidence.
Prints OK or MISMATCH for each figure the paper states. Read-only.
"""
import csv, json, glob, re
from collections import Counter
from pathlib import Path

D = Path("data")
RES = ["S0", "S1", "S2", "S3", "S4"]
GR = ["P0", "P1", "P2", "P3"]
BREADTHS = ["P0", "P1", "P2", "P3", "PU2"]
bad = 0


def check(label, actual, expected, tol=0.0005):
    global bad
    if isinstance(expected, float):
        ok = actual is not None and abs(actual - expected) <= tol
        a = f"{actual:.4f}" if actual is not None else "None"
    else:
        ok = actual == expected
        a = str(actual)
    if not ok:
        bad += 1
    print(f"  [{'OK' if ok else 'MISMATCH'}] {label:<58} paper={expected}  data={a}")


def pct(a, b):
    return round(100 * a / b, 1) if b else None


rows = list(csv.DictReader((D / "coded_resolved.csv").open()))
print("\n== Funnel (Table 3, Fig 2) ==")
check("candidate files", len(rows), 6716)
excl = [r for r in rows if r.get("exclusions")]
reasons = Counter(x for r in excl for x in r["exclusions"].split(";") if x)
kept = [r for r in rows if r["kept"] == "True"]
weak = [r for r in rows if not r.get("exclusions") and r["kept"] != "True"]
check("hard-excluded, any reason", len(excl), 1977)
for k, v in [("instructional_readme", 989), ("tutorial_vocabulary", 711), ("fixture_path", 449),
             ("template_repository", 97), ("archived", 1)]:
    check(f"  exclusion reason {k}", reasons.get(k, 0), v)
if reasons.get("fork"):
    print(f"  note: fork exclusions = {reasons['fork']} (paper lists forks as a reason but gives no count)")
check("fewer than 3 of 4 signals", len(weak), 3933)
check("kept", len(kept), 806)

rung = Counter(r["rung"] for r in kept)
print("\n== Trust codes, kept files (Table 4) ==")
for k, v in [("S0", 5), ("S1", 14), ("S2", 271), ("S3", 145), ("S4", 88), ("U1", 23), ("U3", 259)]:
    check(f"{k} files", rung.get(k, 0), v)
check("parse error", rung.get("PARSE_ERROR", 0) + rung.get("TIMEOUT", 0), 1)
for k, v in [("S0", 0.6), ("S1", 1.7), ("S2", 33.6), ("S3", 18.0), ("S4", 10.9), ("U1", 2.9), ("U3", 32.1)]:
    check(f"{k} raw share %", pct(rung.get(k, 0), 806), v, tol=0.05)
res = [r for r in kept if r["rung"] in RES]
check("resolved trusts (S0-S4)", len(res), 523)
loose = sum(1 for r in res if r["rung"] in ("S0", "S1", "S2"))
check("loose resolved trusts", loose, 290)
check("loose share of resolved %", pct(loose, len(res)), 55.4, tol=0.05)
check("S0+S1 raw share of kept %", pct(rung["S0"] + rung["S1"], 806), 2.4, tol=0.05)

u3 = [r for r in kept if r["rung"] == "U3"]
ext = Counter("source" if Path(r["path"]).suffix.lower() in (".ts", ".js", ".py", ".go") else "config" for r in u3)
print(f"  note: U3 by file type: {dict(ext)} (paper: 168 config + 89 source + 1 test + 1 other issuer = 259)")

print("\n== Permission breadth (Table 5, Fig 3) ==")
pu2 = [r for r in res if r.get("perm_breadth_final") == "PU2"]
both = [r for r in res if r.get("perm_breadth_final") in GR]
check("PU2 among resolved", len(pu2), 182)
check("PU2 share of resolved %", pct(len(pu2), len(res)), 34.8, tol=0.05)
check("roles with both axes", len(both), 341)
src = Counter(r.get("perm_source", "") for r in both)
check("breadth resolved same-file", src.get("same-file", 0), 328)
check("breadth resolved cross-file", src.get("cross-file", 0), 13)
ct = Counter((r["rung"], r["perm_breadth_final"]) for r in both)
expected = {"S0": [0, 1, 0, 2], "S1": [0, 0, 4, 5], "S2": [10, 37, 27, 99], "S3": [7, 38, 13, 36], "S4": [1, 30, 3, 28]}
for rg, vals in expected.items():
    check(f"row {rg} (P0,P1,P2,P3)", [ct.get((rg, p), 0) for p in GR], vals)
col = Counter(r["perm_breadth_final"] for r in both)
check("column totals (P0,P1,P2,P3)", [col.get(p, 0) for p in GR], [18, 106, 47, 170])
core = sum(v for (rg, p), v in ct.items() if rg in ("S0", "S1", "S2") and p in ("P2", "P3"))
check("loose x broad roles", core, 137)
check("loose x broad %", pct(core, len(both)), 40.2, tol=0.05)
check("S2 x P3 roles", ct.get(("S2", "P3"), 0), 99)
check("S2 x P3 %", pct(ct.get(("S2", "P3"), 0), len(both)), 29.0, tol=0.05)
for rg, n, p in [("S2", 173, 57.2), ("S3", 94, 38.3), ("S4", 62, 45.2)]:
    tot = sum(ct.get((rg, q), 0) for q in GR)
    check(f"{rg} roles / P3 share %", (tot, pct(ct.get((rg, "P3"), 0), tot)), (n, p))
s01 = sum(1 for r in kept if r["rung"] in ("S0", "S1") and r.get("perm_breadth_final") in ("P2", "P3"))
check("S0/S1 files with P2/P3 (to notify)", s01, 11)

print("\n== Held-out validation (Tables 7-9) ==")
tool = {r["key"]: r for r in rows}
sample = {r["key"]: r for r in csv.DictReader((D / "label_holdout_sample.csv").open())}
human = {r["key"]: r for r in csv.DictReader((D / "labels_holdout.csv").open())}
drawn = Counter(s["stratum"] for s in sample.values())
items = []
for k, s in sample.items():
    h = human.get(k, {})
    if "calibration" in (h.get("note") or "").lower():
        continue
    t = tool.get(k, {})
    tb = t.get("perm_breadth_final") or t.get("perm_breadth") or ""
    items.append({"w": int(s["stratum_size"]) / drawn[s["stratum"]], "tr": t.get("rung", ""),
                  "hr": h.get("human_rung", ""), "tb": tb if tb in BREADTHS else "",
                  "hb": h.get("human_breadth", "") if h.get("human_breadth") in BREADTHS else ""})
check("held-out files", len(items), 50)
check("held-out per tool stratum", dict(sorted(drawn.items())),
      {"S0": 3, "S1": 3, "S2": 12, "S3": 10, "S4": 10, "U1": 6, "U3": 6})


def kappa(pairs):
    n = len(pairs)
    po = sum(a == b for a, b in pairs) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return (po - pe) / (1 - pe)


for name, tk, hk, n, agree, acc, wacc, kap in [("trust", "tr", "hr", 50, 38, 0.76, 0.80, 0.71),
                                              ("breadth", "tb", "hb", 44, 34, 0.77, 0.83, 0.69)]:
    it = [x for x in items if x[tk] and x[hk]]
    ag = sum(x[tk] == x[hk] for x in it)
    check(f"{name}: items compared", len(it), n)
    check(f"{name}: agreements", ag, agree)
    check(f"{name}: sample accuracy", round(ag / len(it), 2), acc, tol=0.005)
    w = sum(x["w"] for x in it if x[tk] == x[hk]) / sum(x["w"] for x in it)
    check(f"{name}: weighted accuracy", round(w, 2), wacc, tol=0.005)
    check(f"{name}: Cohen's kappa", round(kappa([(x[tk], x[hk]) for x in it]), 2), kap, tol=0.005)
cm = Counter((x["tr"], x["hr"]) for x in items)
check("S2 row of trust matrix (S2,S3,U1)", [cm[("S2", "S2")], cm[("S2", "S3")], cm[("S2", "U1")]], [7, 3, 2])
check("author-U1 files / with resolved tool code",
      (sum(1 for x in items if x["hr"] == "U1"), sum(1 for x in items if x["hr"] == "U1" and x["tr"] in RES)), (11, 6))
loose_tool = sum(1 for x in items if x["tr"] in ("S0", "S1", "S2") and x["hr"] in ("S3", "S4", "U1"))
check("disagreements: tool loose, author S3/S4/U1", loose_tool, 7)

print("\n== Corrected estimates (Tables 4 and 6) ==")
want = {"S0 share of kept files": 0.002, "S1 share of kept files": 0.012, "S2 share of kept files": 0.207,
        "S3 share of kept files": 0.230, "S4 share of kept files": 0.098, "U1 share of kept files": 0.129,
        "U3 share of kept files": 0.322}
for r in csv.DictReader((D / "corrected_estimates.csv").open()):
    m = r["measure"]
    if m in want:
        check(f"corrected {m}", float(r["corrected"]), want[m])
    elif m.startswith("Loose"):
        check("loose share corrected / CI", (r["corrected"], r["ci_low"], r["ci_high"]), ("0.402", "0.238", "0.546"))
    elif m.startswith("Core") or "loose x broad" in m.lower():
        check("loose x broad corrected / CI", (r["corrected"], r["ci_low"], r["ci_high"]), ("0.251", "0.140", "0.368"))
    elif m.startswith("S2 x P3"):
        check("S2 x P3 corrected / CI", (r["corrected"], r["ci_low"], r["ci_high"]), ("0.210", "0.116", "0.310"))
    else:
        print(f"  note: other row {m}: {r}")

print("\n== Sensitivity (Table 10) ==")
txt = (D / "analysis_extra.txt").read_text() if (D / "analysis_extra.txt").exists() else ""
if not txt:
    print("  note: data/analysis_extra.txt not found; sensitivity checks skipped")
for label, pat in [("rule 5 v1: core 46.3%", r"Rule 5 v1.*?core cell loose x broad: 158 of 341 \(46\.3%\)\s+S2 x P3: 100 \(29\.3%\)"),
                   ("StringEquals: unchanged 40.2 / 29.0", r"StringEquals wildcards treated.*?core cell loose x broad: 137 of 341 \(40\.2%\)\s+S2 x P3: 99 \(29\.0%\)"),
                   ("single-role: 230 roles, 40.9 / 27.8", r"Single-role files only\s+\(both axes resolved: 230 of 397\).*?core cell loose x broad: 94 of 230 \(40\.9%\)\s+S2 x P3: 64 \(27\.8%\)"),
                   ("rule 5 moves 64 roles (63 P1>P2, 1 P1>P3)", r"\('P1', 'P2'\): 63, \('P1', 'P3'\): 1"),
                   ("94 text-scan files", r"files without operator information \(text-scan coded\): 94")]:
    if not txt:
        break
    ok = re.search(pat, txt, re.S) is not None
    bad += not ok
    print(f"  [{'OK' if ok else 'MISMATCH'}] {label}")

print("\n== Demonstration evidence ==")
red = glob.glob("evidence/cloudtrail-redacted.json") + glob.glob("data/owned-infra/**/cloudtrail-redacted.json", recursive=True)
ev = glob.glob("data/owned-infra/**/cloudtrail-summary.json", recursive=True)
if red:
    events = json.load(open(red[0]))
    check("CloudTrail demo events", len(events), 8)
    print("  note: results:", dict(Counter(e.get("result", "") for e in events)))
elif ev:
    events = json.load(open(ev[0]))
    print(f"  note: {ev[0]} lists {len(events)} events; the paper says 8 across the three runs.")
    print("        (The first evidence script dropped refused events, so a lower count here can be expected;")
    print("         check against the by-subject listing you ran afterwards.)")
else:
    print("  note: cloudtrail-summary.json not found under data/owned-infra; check the count of 8 by hand")

print(f"\n{bad} mismatch(es)")
