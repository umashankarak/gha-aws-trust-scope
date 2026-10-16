"""
Correct the headline prevalence numbers for the classifier's measured error.

The held-out validation sample was drawn stratified by the TOOL's trust rung.
Within each tool stratum r, the human labels estimate P(true class | tool = r).
Weighting those conditional shares by the number of kept files in each tool
stratum gives an estimate of the true distribution over all kept files (the
reclassification estimator used with stratified validation subsamples).
Confidence intervals come from a stratified bootstrap (resampling labeled items
within each stratum).

    python3 src/correct_estimates.py --out data/

Reads   data/coded_resolved.csv, data/label_holdout_sample.csv, data/labels_holdout.csv
Writes  data/corrected_estimates.csv and prints a raw-vs-corrected table.

Caveats printed with the results: strata with very few labeled items (S0, S1)
make their contribution uncertain, and the held-out sample excludes the files
already labeled in pass 1.
"""

from __future__ import annotations

import argparse
import csv
import random
from collections import Counter, defaultdict
from pathlib import Path

RUNGS = ["S0", "S1", "S2", "S3", "S4", "U1", "U3"]
RESOLVED = {"S0", "S1", "S2", "S3", "S4"}
LOOSE = {"S0", "S1", "S2"}
GRADED = {"P0", "P1", "P2", "P3"}
BROAD = {"P2", "P3"}


BREADTHS = ["P0", "P1", "P2", "P3", "PU2"]


def _estimate(strata, sizes, cells):
    """
    strata: tool trust stratum -> list of (tool_breadth, human_trust, human_breadth)
    sizes:  tool trust stratum -> number of kept files
    cells:  (tool_trust, tool_breadth) -> number of kept files

    Trust shares use the stratified reclassification estimator. The joint
    trust x breadth measures combine a per-stratum trust correction
    P(human trust | tool trust) with a breadth correction
    P(human breadth | tool breadth), applied to the tool's full trust x breadth
    table, assuming trust and breadth errors are independent. This keeps the
    whole population's breadth mix instead of re-estimating it from 50 items.
    """
    N = sum(sizes.values())
    pt = {r: Counter(h for _, h, _ in v) for r, v in strata.items()}
    pt = {r: {h: c[h] / sum(c.values()) for h in RUNGS} for r, c in pt.items()}
    for r in sizes:  # a stratum with no labeled items is taken at face value
        pt.setdefault(r, {h: float(h == r) for h in RUNGS})
    bb = defaultdict(Counter)
    for v in strata.values():
        for tb, _, hb in v:
            if tb in BREADTHS and hb in BREADTHS:
                bb[tb][hb] += 1
    pb = {}
    for b in BREADTHS:
        tot = sum(bb[b].values())
        # A tool breadth class never seen in the sample is taken at face value.
        pb[b] = {h: (bb[b][h] / tot if tot else float(h == b)) for h in BREADTHS}

    out = {f"share_{c}": sum(sizes[r] * pt[r][c] for r in sizes) / N for c in RUNGS}
    resolved = sum(sizes[r] * sum(pt[r][h] for h in RESOLVED) for r in sizes)
    loose = sum(sizes[r] * sum(pt[r][h] for h in LOOSE) for r in sizes)
    out["loose_of_resolved"] = loose / resolved if resolved else float("nan")

    both = core = s2p3 = 0.0
    for (r, b), n in cells.items():
        if r not in pt or b not in pb:
            continue
        p_res = sum(pt[r][h] for h in RESOLVED)
        p_loose = sum(pt[r][h] for h in LOOSE)
        p_grad = sum(pb[b][h] for h in GRADED)
        p_broad = sum(pb[b][h] for h in BROAD)
        both += n * p_res * p_grad
        core += n * p_loose * p_broad
        s2p3 += n * pt[r]["S2"] * pb[b]["P3"]
    out["core_of_both"] = core / both if both else float("nan")
    out["s2p3_of_both"] = s2p3 / both if both else float("nan")
    return out


def _raw(kept):
    N = len(kept)
    c = Counter(r["rung"] for r in kept)
    out = {f"share_{x}": c[x] / N for x in RUNGS}
    res = [r for r in kept if r["rung"] in RESOLVED]
    out["loose_of_resolved"] = sum(r["rung"] in LOOSE for r in res) / len(res)
    both = [r for r in res if r["_b"] in GRADED]
    out["core_of_both"] = sum(r["rung"] in LOOSE and r["_b"] in BROAD for r in both) / len(both)
    out["s2p3_of_both"] = sum(r["rung"] == "S2" and r["_b"] == "P3" for r in both) / len(both)
    return out


def main(out_dir: Path, boot: int, seed: int):
    src = out_dir / "coded_resolved.csv"
    tool = {r["key"]: r for r in csv.DictReader(src.open())}
    kept = [r for r in tool.values() if r["kept"] == "True" and r["rung"] in RUNGS]
    sizes = Counter(r["rung"] for r in kept)

    sample = list(csv.DictReader((out_dir / "label_holdout_sample.csv").open()))
    human = {r["key"]: r for r in csv.DictReader((out_dir / "labels_holdout.csv").open())}

    for r in kept:
        r["_b"] = r.get("perm_breadth_final") or r.get("perm_breadth") or ""
    cells = Counter((r["rung"], r["_b"]) for r in kept)

    # Labeled items grouped by the TOOL stratum they were drawn from, carrying
    # the tool's breadth for that file so the breadth error can be estimated.
    strata: dict[str, list] = defaultdict(list)
    for s_ in sample:
        h = human.get(s_["key"])
        t = tool.get(s_["key"], {})
        if h and h.get("human_rung") in RUNGS:
            tb = t.get("perm_breadth_final") or t.get("perm_breadth") or ""
            strata[s_["stratum"]].append((tb, h["human_rung"], h.get("human_breadth", "")))
    missing = [r for r in sizes if r not in strata]

    raw = _raw(kept)
    point = _estimate(strata, sizes, cells)

    rng = random.Random(seed)
    draws = defaultdict(list)
    for _ in range(boot):
        res = {r: [rng.choice(v) for _ in v] for r, v in strata.items()}
        for k, v in _estimate(res, sizes, cells).items():
            draws[k].append(v)

    def ci(k):
        xs = sorted(x for x in draws[k] if x == x)
        if not xs:
            return float("nan"), float("nan")
        return xs[int(0.025 * (len(xs) - 1))], xs[int(0.975 * (len(xs) - 1))]

    rows = []
    labels = [(f"share_{c}", f"{c} share of kept files") for c in RUNGS] + [
        ("loose_of_resolved", "Loose (S0-S2) share of resolved AWS trusts"),
        ("core_of_both", "Core cell: loose x broad (P2-P3), of roles with both axes"),
        ("s2p3_of_both", "S2 x P3, of roles with both axes"),
    ]
    print(f"kept files: {len(kept)}   tool strata sizes: {dict(sizes)}")
    print(f"labeled held-out items per stratum: { {r: len(v) for r, v in strata.items()} }")
    if missing:
        print(f"WARNING: no labeled items for strata {missing}; taken at face value (uncorrected)")
    print(f"\n{'measure':<62}{'raw':>8}{'corrected':>11}{'95% CI':>18}")
    for k, name in labels:
        lo, hi = ci(k)
        rows.append({"measure": name, "raw": f"{raw[k]:.3f}", "corrected": f"{point[k]:.3f}",
                     "ci_low": f"{lo:.3f}", "ci_high": f"{hi:.3f}"})
        print(f"{name:<62}{raw[k]*100:>7.1f}%{point[k]*100:>10.1f}%   [{lo*100:5.1f}%, {hi*100:5.1f}%]")

    small = [r for r, v in strata.items() if len(v) < 5]
    print(f"\nNotes: {boot} stratified bootstrap draws, seed {seed}."
          + (f" Strata with fewer than 5 labeled items: {small}; their share is weakly estimated." if small else "")
          + " The held-out sample excludes pass-1 files.")

    with (out_dir / "corrected_estimates.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["measure", "raw", "corrected", "ci_low", "ci_high"])
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {out_dir / 'corrected_estimates.csv'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--boot", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=20261012)
    a = ap.parse_args()
    main(Path(a.out), a.boot, a.seed)
