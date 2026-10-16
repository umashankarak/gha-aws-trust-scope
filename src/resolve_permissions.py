"""
Axis 2, coverage step -- resolve permissions that live in OTHER files of the repo.

The in-file pass (permissions.py) leaves ~half of roles as PU2 because their
attached policies are defined elsewhere. This step, for each kept trust-resolved
PU2 role, fetches the repo's IaC files and links permissions to the role BY
REFERENCE (role name), never by repo-wide union -- so a narrow GitHub role is
not tagged with an unrelated admin role's power.

Run (on your machine, needs GITHUB_TOKEN):
    python3 src/resolve_permissions.py --out data/

Reads data/coded.csv, writes data/coded_resolved.csv and prints the updated
breadth distribution and trust x breadth cross-tab.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

from gh import GitHubClient
from permissions import github_roles, resolve_role_breadth, _broadest, _ROLE_BLOCK, _blocks

IAC_EXT = (".tf", ".json", ".yaml", ".yml", ".ts")
MAX_FILES_PER_REPO = 100

# Prioritize real IaC and skip source/noise, so the 100-file budget reaches the
# .tf where the role lives instead of being spent on app source.
_SKIP_DIR = re.compile(
    r'(^|/)(node_modules|vendor|dist|build|\.git|\.terraform|__pycache__|coverage'
    r'|\.next|target|test|tests|__tests__|spec|fixtures|examples|docs)(/|$)', re.IGNORECASE)
_IAC_HINT = re.compile(
    r'(iam|oidc|role|trust|assume|policy|policies|cloudformation|cfn|terraform'
    r'|infra|bootstrap|deploy|/\.aws/|github-actions)', re.IGNORECASE)
_CDK_HINT = re.compile(r'(cdk|sst|pulumi|stack|infra|iam|oidc)', re.IGNORECASE)


def _select_iac(tree: list[str]) -> list[str]:
    """.tf first (always), then IaC-hinted CFN json/yaml, then CDK-hinted .ts."""
    tf, cfn, cdk = [], [], []
    for p in tree:
        if _SKIP_DIR.search(p):
            continue
        low = p.lower()
        if low.endswith(".tf"):
            tf.append(p)
        elif low.endswith((".yaml", ".yml", ".json")) and _IAC_HINT.search(p):
            cfn.append(p)
        elif low.endswith(".ts") and _CDK_HINT.search(p):
            cdk.append(p)
    return (tf + cfn + cdk)[:MAX_FILES_PER_REPO]


def roles_for_trust_file(trust_text: str, trust_path: str, repo_text: str):
    """
    The role(s) a trust file belongs to, by EXPLICIT link only (codebook rule 6):
      1. a GitHub-trust aws_iam_role defined in the trust file itself, or
      2. an aws_iam_role elsewhere whose assume_role_policy loads this file by
         name (file("...trust.json"), templatefile(...)).
    No repo-wide fallback: a repo's other GitHub roles are not this file's role.
    """
    own = github_roles(trust_text)
    if own:
        return own
    base = trust_path.rsplit("/", 1)[-1]
    if not base or not repo_text:
        return []
    linked = []
    for m, body in _blocks(repo_text, _ROLE_BLOCK):
        arp = re.search(r'assume_role_policy\s*=\s*([^\n]+)', body)
        if arp and base in arp.group(1):
            na = re.search(r'\bname\s*=\s*"([^"]+)"', body)
            linked.append((m.group(1), na.group(1) if na else None))
    return linked


def resolve(out_dir: Path):
    client = GitHubClient()
    rows = list(csv.DictReader((out_dir / "coded.csv").open()))
    cache = out_dir / "repo_cache"
    cache.mkdir(exist_ok=True)

    # Only kept, trust-resolved, currently-PU2 roles need cross-file resolution.
    todo = [r for r in rows if r["kept"] == "True"
            and r["rung"] in ("S0", "S1", "S2", "S3", "S4")
            and r.get("perm_breadth") == "PU2"]
    by_repo: dict[str, list] = {}
    for r in todo:
        by_repo.setdefault(r["repo"], []).append(r)
    print(f"{len(todo)} PU2 roles across {len(by_repo)} repos to resolve")

    resolved = {}  # key -> (breadth, source, evidence)
    for i, (repo, rrows) in enumerate(by_repo.items(), 1):
        repo_text = _repo_iac_text(client, repo, cache)
        for r in rrows:
            blob = _blob_text(out_dir, r["key"])
            roles = roles_for_trust_file(blob, r["path"], repo_text)
            search_text = repo_text or blob
            best, ev = None, []
            for rn, na in roles:
                b, e = resolve_role_breadth(search_text, rn, na)
                if b and (best is None or _broadest([best, b]) == b):
                    best, ev = b, e
            if best:
                resolved[r["key"]] = (best, "cross-file", "; ".join(ev[:6]))
        if i % 25 == 0:
            print(f"  resolved repos {i}/{len(by_repo)}")

    # Merge: same-file grade stays; PU2 upgraded where cross-file found something.
    for r in rows:
        if r["key"] in resolved:
            b, src, ev = resolved[r["key"]]
            r["perm_breadth_final"] = b
            r["perm_source"] = src
            r["perm_evidence_final"] = ev
        else:
            r["perm_breadth_final"] = r.get("perm_breadth", "")
            r["perm_source"] = "same-file" if r.get("perm_breadth") in ("P0","P1","P2","P3") else "unresolved"
            r["perm_evidence_final"] = r.get("perm_evidence", "")

    out_csv = out_dir / "coded_resolved.csv"
    with out_csv.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)
    _report_resolved(rows)
    print(f"\nwrote {out_csv}")


def _repo_iac_text(client, repo, cache) -> str:
    cached = cache / (repo.replace("/", "__") + ".txt")
    if cached.exists():
        return cached.read_text(errors="replace")
    try:
        tree = client.list_tree(repo)
    except Exception:
        tree = []
    files = _select_iac(tree)
    parts = []
    for p in files:
        try:
            t = client.raw_file(repo, p)
            if t:
                parts.append(t)
        except Exception:
            pass
    text = "\n".join(parts)
    cached.write_text(text)
    return text


def _blob_text(out_dir, key) -> str:
    for p in (out_dir / "blobs").glob(f"{key}.*"):
        return p.read_text(encoding="utf-8-sig", errors="replace")
    return ""


def _report_resolved(rows):
    kept = [r for r in rows if r["kept"] == "True" and r["rung"] in ("S0","S1","S2","S3","S4")]
    pc = Counter(r["perm_breadth_final"] or "(none)" for r in kept)
    print("\nPermission breadth after cross-file resolution:")
    for b in ["P0","P1","P2","P3","PU2","(none)"]:
        if pc.get(b):
            print(f"   {b:<5} {pc[b]:>5}  {pc[b]/len(kept)*100:5.1f}%")
    both = [r for r in kept if r["perm_breadth_final"] in ("P0","P1","P2","P3")]
    print(f"\nCross-tab trust x breadth (both resolved: {len(both)} of {len(kept)}):")
    print("         P0    P1    P2    P3")
    for rg in ("S0","S1","S2","S3","S4"):
        cells = Counter(r["perm_breadth_final"] for r in both if r["rung"] == rg)
        n = sum(cells.values())
        if n:
            print(f"   {rg}  " + "".join(f"{cells.get(p,0):>6}" for p in ("P0","P1","P2","P3")) + f"   (n={n})")
    core = sum(1 for r in both if r["rung"] in ("S0","S1","S2") and r["perm_breadth_final"] in ("P2","P3"))
    if both:
        print(f"\n   CORE CELL loose (S0-S2) x broad (P2-P3): {core} of {len(both)} ({core/len(both)*100:.1f}%)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    resolve(Path(ap.parse_args().out))
