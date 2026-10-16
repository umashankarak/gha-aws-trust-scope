"""
Stage 3 -- run the filter and the classifier over collected candidates,
emit the pilot report and the coded dataset.

Run:  python3 src/pipeline.py --out data/
"""

from __future__ import annotations

import argparse
import csv
import json
import signal
from collections import Counter
from pathlib import Path

from gh import GitHubClient
from classify import classify_file
from permissions import classify_permissions
from deployedness import evaluate, FIXTURE_PATH

RUNGS = ["S0", "S1", "S2", "S3", "S4", "U1", "U3"]
BREADTHS = ["P0", "P1", "P2", "P3", "PU2"]

PER_FILE_TIMEOUT = 10  # seconds; safety net so no single file can hang the run


class _Timeout(Exception):
    pass


def _timeout_handler(signum, frame):
    raise _Timeout()


def classify_with_timeout(blob: Path):
    """
    Classify one file, but never spend more than PER_FILE_TIMEOUT on it.

    The parser now guarantees forward progress, so this should never fire -- it
    is a belt-and-suspenders guard for a long unattended run. SIGALRM is
    main-thread only, which is where code() runs. No-op on platforms without it.
    """
    has_alarm = hasattr(signal, "SIGALRM")
    if has_alarm:
        signal.signal(signal.SIGALRM, _timeout_handler)
        signal.alarm(PER_FILE_TIMEOUT)
    try:
        return classify_file(blob), None
    except _Timeout:
        return None, f"timeout after {PER_FILE_TIMEOUT}s"
    except Exception as e:  # noqa: BLE001 -- record and move on
        return None, str(e)[:200]
    finally:
        if has_alarm:
            signal.alarm(0)


def _index_blobs(blobs: Path) -> dict[str, Path]:
    """
    Map candidate key -> blob path in a SINGLE directory scan.

    Blob names are '<key><ext>'; the key is the 16-char stem prefix. Doing this
    once and looking up by key turns the per-record blobs.glob() (a full
    directory scan every time -> O(n^2) over thousands of files) into O(n).
    """
    index = {}
    for p in blobs.iterdir():
        if p.is_file() and not p.name.startswith("."):
            index[p.stem] = p
    return index


def enrich(out_dir: Path, threshold: int = 3):
    """Fetch repo metadata for each candidate and apply the filter."""
    client = GitHubClient()
    cand_path = out_dir / "candidates.jsonl"
    enriched_path = out_dir / "enriched.jsonl"
    blobs = out_dir / "blobs"

    records = [json.loads(l) for l in cand_path.read_text().splitlines() if l.strip()]
    done = set()
    if enriched_path.exists():
        for line in enriched_path.read_text().splitlines():
            if line.strip():
                done.add(json.loads(line)["key"])

    blob_index = _index_blobs(blobs)

    # One repo may contribute several candidate files; cache per repo.
    repo_cache: dict[str, dict] = {}

    with enriched_path.open("a") as fh:
        for i, rec in enumerate(records, 1):
            if rec["key"] in done:
                continue
            repo = rec["repo"]
            if repo not in repo_cache:
                meta = client.repo(repo)
                if not meta:
                    repo_cache[repo] = {"__missing__": True}
                else:
                    tree = client.list_tree(repo, meta.get("default_branch", "HEAD"))
                    wf_paths = [p for p in tree if p.startswith(".github/workflows/")][:10]
                    wf_texts = {}
                    for p in wf_paths:
                        try:
                            wf_texts[p] = client.raw_file(repo, p) or ""
                        except Exception:
                            wf_texts[p] = ""
                    readme = None
                    for cand in ("README.md", "readme.md", "README.rst"):
                        if cand in tree:
                            try:
                                readme = client.raw_file(repo, cand)
                            except Exception:
                                pass
                            break
                    try:
                        contributors = client.contributors_count(repo)
                    except Exception:
                        contributors = 0
                    repo_cache[repo] = {
                        "meta": meta, "tree": tree, "wf_texts": wf_texts,
                        "readme": readme, "contributors": contributors,
                    }

            cached = repo_cache[repo]
            if cached.get("__missing__"):
                continue

            blob = blob_index.get(rec["key"])
            policy_text = blob.read_text(errors="replace") if blob else ""

            verdict = evaluate(
                cached["meta"], cached["tree"], cached["wf_texts"],
                policy_text, cached["contributors"], cached["readme"],
                threshold=threshold,
            )
            fh.write(json.dumps({**rec, "filter": verdict,
                                 "stars": cached["meta"].get("stargazers_count", 0)}) + "\n")
            fh.flush()
            if i % 25 == 0:
                print(f"  enriched {i}/{len(records)}")

    print(f"enriched -> {enriched_path}")
    return enriched_path


def code(out_dir: Path):
    """Classify every kept candidate; write coded.csv and the pilot report."""
    enriched = [json.loads(l) for l in (out_dir / "enriched.jsonl").read_text().splitlines() if l.strip()]
    blobs = out_dir / "blobs"
    blob_index = _index_blobs(blobs)

    rows = []
    for i, rec in enumerate(enriched, 1):
        blob = blob_index.get(rec["key"])
        if not blob:
            continue
        if i % 1000 == 0:
            print(f"  coded {i}/{len(enriched)}", flush=True)
        c, err = classify_with_timeout(blob)
        if err is not None:
            rung = "TIMEOUT" if err.startswith("timeout") else "PARSE_ERROR"
            row = {**_flat(rec), "rung": rung, "aud_constrained": "",
                   "sub_format": "", "reason": err, "sub_patterns": "",
                   "perm_breadth": "", "perm_evidence": err}
        else:
            # Axis 2: permission breadth behind the role, from the same file.
            try:
                breadth, evidence = classify_permissions(
                    blob.read_text(encoding="utf-8-sig", errors="replace"),
                    Path(rec.get("path", "") or blob.name).suffix or blob.suffix)
            except Exception as e:  # noqa: BLE001
                breadth, evidence = "", str(e)[:120]
            row = {**_flat(rec), "rung": c.rung, "aud_constrained": c.aud_constrained,
                   "sub_format": c.sub_format, "reason": c.reason,
                   "sub_patterns": " | ".join(c.sub_patterns),
                   "perm_breadth": breadth, "perm_evidence": evidence}
        # Path-based fixture exclusion, applied here so it needs no re-enrichment.
        if FIXTURE_PATH.search(rec.get("path", "") or ""):
            row["kept"] = False
            row["kept_strict"] = False
            row["exclusions"] = ";".join(filter(None, [row["exclusions"], "fixture_path"]))
        rows.append(row)

    out_csv = out_dir / "coded.csv"
    if rows:
        with out_csv.open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)

    _report(rows, out_dir)
    return out_csv


def _flat(rec: dict) -> dict:
    f = rec.get("filter", {})
    return {
        "key": rec["key"], "repo": rec["repo"], "path": rec["path"],
        "frame": rec["frame"], "shard": rec["shard"], "stars": rec.get("stars", 0),
        "kept": f.get("kept"), "kept_strict": f.get("kept_strict"),
        "signals_passed": f.get("signals_passed"),
        "exclusions": ";".join(f.get("exclusion_reasons", [])),
    }


def _report(rows: list[dict], out_dir: Path):
    kept = [r for r in rows if r["kept"]]
    strict = [r for r in rows if r["kept_strict"]]
    excluded = [r for r in rows if r["exclusions"]]

    def dist(subset):
        c = Counter(r["rung"] for r in subset)
        return {k: c.get(k, 0) for k in RUNGS + ["PARSE_ERROR"] if c.get(k)}

    u1 = sum(1 for r in kept if r["rung"] == "U1")
    u1_share = (u1 / len(kept) * 100) if kept else 0.0

    lines = [
        "PILOT REPORT",
        "=" * 60,
        f"candidates classified      : {len(rows)}",
        f"hard-excluded              : {len(excluded)}",
        f"kept (>=3 of 4 signals)    : {len(kept)}",
        f"kept (4 of 4 signals)      : {len(strict)}",
        "",
        f"U1 share of kept           : {u1_share:.1f}%   (gate: below 20%)",
        "",
        "Rung distribution, kept set (>=3 of 4):",
    ]
    for k, v in dist(kept).items():
        pct = v / len(kept) * 100 if kept else 0
        lines.append(f"   {k:<12} {v:>5}  {pct:5.1f}%")
    lines += ["", "Rung distribution, hard-excluded set (the tutorial population):"]
    for k, v in dist(excluded).items():
        pct = v / len(excluded) * 100 if excluded else 0
        lines.append(f"   {k:<12} {v:>5}  {pct:5.1f}%")

    # --- Axis 2: permission breadth, and the core cross-tab ---
    resolved_trust = [r for r in kept if r["rung"] in ("S0", "S1", "S2", "S3", "S4")]
    if resolved_trust:
        lines += ["", "Permission breadth, kept + trust-resolved set:"]
        pc = Counter(r.get("perm_breadth") or "(none)" for r in resolved_trust)
        for b in BREADTHS + ["(none)"]:
            if pc.get(b):
                lines.append(f"   {b:<6} {pc[b]:>5}  {pc[b]/len(resolved_trust)*100:5.1f}%")

        # Cross-tab: trust rung (rows) x breadth (cols), over roles where BOTH
        # axes resolved (breadth != PU2). This is the paper's core table.
        both = [r for r in resolved_trust if r.get("perm_breadth") in ("P0", "P1", "P2", "P3")]
        lines += ["",
                  f"Cross-tab trust x breadth (both resolved: {len(both)} of "
                  f"{len(resolved_trust)}; PU2 permissions excluded):",
                  "         P0    P1    P2    P3", ]
        for rg in ("S0", "S1", "S2", "S3", "S4"):
            cells = Counter(r["perm_breadth"] for r in both if r["rung"] == rg)
            row_n = sum(cells.values())
            if row_n:
                lines.append(f"   {rg}  " + "".join(f"{cells.get(p,0):>6}" for p in ("P0","P1","P2","P3"))
                             + f"   (n={row_n})")
        loose_broad = sum(1 for r in both if r["rung"] in ("S0","S1","S2") and r["perm_breadth"] in ("P2","P3"))
        lines.append("")
        lines.append(f"   CORE CELL  loose trust (S0-S2) x broad power (P2-P3): "
                     f"{loose_broad} of {len(both)} resolved "
                     f"({loose_broad/len(both)*100:.1f}%)" if both else "   (no fully-resolved roles)")

    lines += ["", "GO/NO-GO", "-" * 60]
    ok_n = len(kept) >= 300
    ok_u1 = u1_share < 20
    lines.append(f"  [{'PASS' if ok_n else 'FAIL'}] kept >= 300         : {len(kept)}")
    lines.append(f"  [{'PASS' if ok_u1 else 'FAIL'}] U1 share < 20%      : {u1_share:.1f}%")
    lines.append("")
    lines.append("  PROCEED to Phase 3." if (ok_n and ok_u1) else
                 "  DO NOT loosen the filter to hit the number. Widen the frames\n"
                 "  (GitLab/Bitbucket issuers) or pivot to the capability-URL study.")

    text = "\n".join(lines)
    (out_dir / "pilot_report.txt").write_text(text)
    print("\n" + text)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--threshold", type=int, default=3)
    ap.add_argument("--code-only", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    if not args.code_only:
        enrich(out, args.threshold)
    code(out)
