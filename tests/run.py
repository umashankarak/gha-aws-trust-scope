import sys, json, re
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from classify import classify_file

root = Path(__file__).resolve().parents[1] / "fixtures"

# expected.yaml is the human-readable codebook and the source of truth.
# expected.json is generated from it so the suite runs with no dependencies.
try:
    import yaml
    expected = yaml.safe_load((root / "expected.yaml").read_text())
except ImportError:
    expected = json.loads((root / "expected.json").read_text())

# Path-exclusion fixtures (rung: EXCLUDE) are verified against the deployedness
# filter, not the classifier -- assert here that FIXTURE_PATH would drop them.
from deployedness import FIXTURE_PATH
exclude_rows = {k: v for k, v in expected.items() if v.get("rung") == "EXCLUDE"}
expected = {k: v for k, v in expected.items() if v.get("rung") != "EXCLUDE"}
excl_fails = 0
for rel in exclude_rows:
    if not FIXTURE_PATH.search(rel):
        excl_fails += 1
        print(f"FAIL {rel}  <- FIXTURE_PATH should exclude this consumer/test file but did not")

rows, fails = [], 0
for rel, exp in expected.items():
    got = classify_file(root / rel)
    checks = {
        "rung": (exp["rung"], got.rung),
        "aud":  (exp["aud_constrained"], got.aud_constrained),
        "fmt":  (exp["sub_format"], got.sub_format),
    }
    bad = [k for k, (e, g) in checks.items() if e != g]
    if bad: fails += 1
    rows.append((rel, exp["rung"], got.rung, bad, got.reason))

w = max(len(r[0]) for r in rows)
for rel, e, g, bad, reason in rows:
    mark = "ok  " if not bad else "FAIL"
    detail = f"  <- mismatch on {','.join(bad)}" if bad else ""
    print(f"{mark} {rel:<{w}}  exp={e:<3} got={g:<3}{detail}")
    if bad:
        print(f"       reason: {reason}")

print(f"\n{len(rows) - fails}/{len(rows)} fixtures agree with hand-coding")
if exclude_rows:
    print(f"{len(exclude_rows) - excl_fails}/{len(exclude_rows)} path-exclusion fixtures correctly excluded")
sys.exit(1 if (fails or excl_fails) else 0)
