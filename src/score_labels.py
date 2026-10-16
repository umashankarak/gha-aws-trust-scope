"""
Score human labels against the classifier (and against yourself, for retest).

    python3 src/score_labels.py --out data/ --labels ~/Downloads/labels_pass1.csv
    python3 src/score_labels.py --out data/ --labels labels_pass1.csv --retest labels_retest.csv

Reports, for trust rung and for permission breadth:
  - per-class precision (of items the tool called X, share you agreed were X)
  - per-class recall, estimated with inverse sampling weights
  - overall accuracy, weighted to the kept-set stratum sizes
  - Cohen's kappa between tool and human
and lists every disagreement so you can review it. With --retest it also
reports intra-rater kappa (your pass 1 vs your pass 2).
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

RUNGS = ["S0", "S1", "S2", "S3", "S4", "U1", "U3"]
BREADTHS = ["P0", "P1", "P2", "P3", "PU2"]


def kappa(pairs):
    pairs = [(a, b) for a, b in pairs if a and b]
    n = len(pairs)
    if n == 0:
        return float("nan"), 0
    po = sum(a == b for a, b in pairs) / n
    ca, cb = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    pe = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return ((po - pe) / (1 - pe) if pe < 1 else 1.0), n


def _table(title, items, classes, tool_key, human_key):
    """items: list of dicts with tool/human labels and weight w."""
    rows = [x for x in items if x[tool_key] and x[human_key]]
    print(f"\n=== {title} (n={len(rows)}) ===")
    if not rows:
        print("  no comparable items")
        return
    labels = [c for c in classes if any(x[tool_key] == c or x[human_key] == c for x in rows)]
    # confusion matrix: rows = tool, cols = human
    print("  tool \\ human  " + "".join(f"{c:>6}" for c in labels))
    for t in labels:
        line = "".join(f"{sum(1 for x in rows if x[tool_key]==t and x[human_key]==h):>6}" for h in labels)
        print(f"  {t:<14}{line}")

    print(f"\n  {'class':<6}{'precision':>11}{'recall(w)':>11}{'n_tool':>8}{'n_human':>9}")
    for c in labels:
        tool_c = [x for x in rows if x[tool_key] == c]
        prec = sum(x[human_key] == c for x in tool_c) / len(tool_c) if tool_c else float("nan")
        hum_c = [x for x in rows if x[human_key] == c]
        wsum = sum(x["w"] for x in hum_c)
        rec = sum(x["w"] for x in hum_c if x[tool_key] == c) / wsum if wsum else float("nan")
        print(f"  {c:<6}{prec:>11.2f}{rec:>11.2f}{len(tool_c):>8}{len(hum_c):>9}")

    w_acc = sum(x["w"] for x in rows if x[tool_key] == x[human_key]) / sum(x["w"] for x in rows)
    raw_acc = sum(x[tool_key] == x[human_key] for x in rows) / len(rows)
    k, _ = kappa([(x[tool_key], x[human_key]) for x in rows])
    print(f"\n  accuracy (sample)            : {raw_acc:.3f}")
    print(f"  accuracy (weighted to kept)  : {w_acc:.3f}")
    print(f"  Cohen's kappa tool vs human  : {k:.3f}")


def main(out_dir: Path, labels_path: Path, retest_path: Path | None,
         adjudicated_path: Path | None = None, sample_name: str = "label_sample.csv"):
    src = out_dir / "coded_resolved.csv"
    if not src.exists():
        src = out_dir / "coded.csv"
    tool = {r["key"]: r for r in csv.DictReader(src.open())}
    sample = {r["key"]: r for r in csv.DictReader((out_dir / sample_name).open())}
    human = {r["key"]: r for r in csv.DictReader(labels_path.open())}

    # inverse sampling weight per stratum
    drawn = Counter(s["stratum"] for s in sample.values())
    items = []
    for key, s in sample.items():
        h = human.get(key, {})
        t = tool.get(key, {})
        tb = t.get("perm_breadth_final") or t.get("perm_breadth") or ""
        items.append({
            "key": key, "repo": s["repo"], "path": s["path"],
            "w": int(s["stratum_size"]) / drawn[s["stratum"]],
            "tool_rung": t.get("rung", ""), "human_rung": h.get("human_rung", ""),
            "tool_breadth": tb if tb in BREADTHS else "",
            "human_breadth": h.get("human_breadth", "") if h.get("human_breadth") in BREADTHS else "",
            "note": h.get("note", ""),
        })

    # Calibration items were discussed before independent labeling: exclude them.
    calib = [x for x in items if "calibration" in x["note"].lower()]
    items = [x for x in items if "calibration" not in x["note"].lower()]
    labeled = sum(1 for x in items if x["human_rung"])
    print(f"labeled {labeled} of {len(items)} sampled items "
          f"({len(calib)} calibration item(s) excluded)")

    if adjudicated_path:
        # Replace human labels with the adjudicated final labels where filled in.
        adj = {r["key"]: r for r in csv.DictReader(adjudicated_path.open())}
        changed = 0
        for x in items:
            a = adj.get(x["key"])
            if not a:
                continue
            if a.get("final_rung"):
                x["human_rung"] = a["final_rung"]; changed += 1
            if a.get("final_breadth") in BREADTHS:
                x["human_breadth"] = a["final_breadth"]
        print(f"ADJUDICATED scoring: final labels applied to {changed} disagreement(s)")

    _table("TRUST RUNG", items, RUNGS, "tool_rung", "human_rung")
    _table("PERMISSION BREADTH (items where both graded P0-P3/PU2)",
           items, BREADTHS, "tool_breadth", "human_breadth")

    dis = [x for x in items if x["human_rung"] and
           (x["tool_rung"] != x["human_rung"] or
            (x["tool_breadth"] and x["human_breadth"] and x["tool_breadth"] != x["human_breadth"]))]
    print(f"\n=== DISAGREEMENTS ({len(dis)}) ===")
    for x in dis:
        print(f"  {x['repo'][:38]:38} {x['path'][:34]:34} "
              f"rung tool={x['tool_rung']:<3} you={x['human_rung']:<3} "
              f"breadth tool={x['tool_breadth'] or '-':<3} you={x['human_breadth'] or '-':<3}"
              + (f"  note: {x['note'][:40]}" if x['note'] else ""))
    if not adjudicated_path:
        # Adjudication sheet: one row per disagreement, decision columns left blank.
        cols = ["key", "repo", "path", "tool_rung", "human_rung", "tool_breadth",
                "human_breadth", "note", "verdict", "final_rung", "final_breadth", "rule"]
        dis_name = ("label_disagreements.csv" if sample_name == "label_sample.csv"
                    else "label_disagreements_holdout.csv")
        with (out_dir / dis_name).open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            for x in dis:
                w.writerow({**x, "verdict": "", "final_rung": "", "final_breadth": "", "rule": ""})
        print(f"\nwrote {out_dir / dis_name} "
              "(verdict/final_rung/final_breadth/rule left blank for adjudication)")

    if retest_path:
        second = {r["key"]: r for r in csv.DictReader(retest_path.open())}
        both = [k for k in second if k in human]
        kr, nr = kappa([(human[k]["human_rung"], second[k]["human_rung"]) for k in both])
        kb, nb = kappa([(human[k]["human_breadth"], second[k]["human_breadth"]) for k in both
                        if human[k]["human_breadth"] in BREADTHS and second[k]["human_breadth"] in BREADTHS])
        print(f"\n=== INTRA-RATER (you vs you) ===")
        print(f"  trust rung kappa : {kr:.3f}  (n={nr})")
        print(f"  breadth kappa    : {kb:.3f}  (n={nb})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--labels", required=True)
    ap.add_argument("--retest")
    ap.add_argument("--adjudicated", help="filled-in label_disagreements csv")
    ap.add_argument("--sample", default="label_sample.csv",
                    help="sample file in --out (label_holdout_sample.csv for the held-out pass)")
    a = ap.parse_args()
    main(Path(a.out), Path(a.labels), Path(a.retest) if a.retest else None,
         Path(a.adjudicated) if a.adjudicated else None, a.sample)
