"""
Build a dossier for every tool/human disagreement so each one can be traced to
a cause (classifier bug, codebook ambiguity, or labeling slip) before anyone
adjudicates.

    python3 src/diagnose_disagreements.py --out data/

Reads data/label_disagreements.csv (written by score_labels.py), the coded CSV,
and the file blobs. Writes data/disagreement_dossier.txt: for each item, the
classifier's stated reason and evidence, plus the lines of the file that bear
on the trust condition and the permissions.

The dossier contains only public file excerpts and the classifier's output.
It does not contain your labels' notes beyond the first 80 characters.
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path

TRUST_LINE = re.compile(
    r'(:sub\b|"sub"|\bsub\s*[:=]|repo:|environment|job_workflow_ref|:ref:|pull_request|'
    r'StringLike|StringEquals|ForAnyValue|token\.actions|AssumeRoleWithWebIdentity|'
    r'variable\s*=|values\s*=|Condition|subjects?\b|allowed_?(repos|branches|subjects))',
    re.IGNORECASE)
PERM_LINE = re.compile(
    r'(\bactions?\s*[:=]|"Action"|Action:|policy_arn|ManagedPolicyArns|managed_policy|'
    r'arn:aws:iam::aws:policy|Resource|addToPolicy|grant[A-Z]\w*\(|PolicyStatement|'
    r'aws_iam_role_policy|inline_policy|Policies:)')


def _lines(text: str, pattern, cap: int):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if pattern.search(line):
            out.append(f"    {i:>5}: {line.rstrip()[:150]}")
            if len(out) >= cap:
                out.append("    ... (more lines omitted)")
                break
    return out


def main(out_dir: Path):
    dis = list(csv.DictReader((out_dir / "label_disagreements.csv").open()))
    src = out_dir / "coded_resolved.csv"
    if not src.exists():
        src = out_dir / "coded.csv"
    tool = {r["key"]: r for r in csv.DictReader(src.open())}
    blobs = {p.stem: p for p in (out_dir / "blobs").iterdir()
             if p.is_file() and not p.name.startswith(".")}

    rung_dis = [d for d in dis if d["tool_rung"] != d["human_rung"]]
    breadth_only = [d for d in dis if d["tool_rung"] == d["human_rung"]]
    # Group rung disagreements by tool rung so patterns are easy to see.
    rung_dis.sort(key=lambda d: (d["tool_rung"], d["human_rung"], d["repo"]))
    breadth_only.sort(key=lambda d: (d["tool_breadth"], d["human_breadth"], d["repo"]))

    out = []
    for title, group, focus in (("RUNG DISAGREEMENTS", rung_dis, "trust"),
                                ("BREADTH-ONLY DISAGREEMENTS", breadth_only, "perm")):
        out.append("=" * 100)
        out.append(f"{title} ({len(group)})")
        out.append("=" * 100)
        for n, d in enumerate(group, 1):
            t = tool.get(d["key"], {})
            blob = blobs.get(d["key"])
            text = blob.read_text(encoding="utf-8-sig", errors="replace") if blob else ""
            out.append("")
            out.append(f"[{focus[0].upper()}{n:03d}] {d['repo']}  {d['path']}")
            out.append(f"  rung    tool={d['tool_rung']:<3} human={d['human_rung']:<3}   "
                       f"breadth tool={d['tool_breadth'] or '-':<3} human={d['human_breadth'] or '-'}")
            out.append(f"  tool reason   : {t.get('reason', '')[:200]}")
            out.append(f"  tool subs     : {t.get('sub_patterns', '')[:200]}")
            out.append(f"  tool perm     : {(t.get('perm_evidence_final') or t.get('perm_evidence', ''))[:200]}"
                       f"  [source={t.get('perm_source', 'file')}]")
            if d.get("note"):
                out.append(f"  human note    : {d['note'][:80]}")
            out.append(f"  file length   : {len(text.splitlines())} lines")
            if focus == "trust":
                out.append("  trust-related lines:")
                out += _lines(text, TRUST_LINE, 25) or ["    (none matched)"]
            out.append("  permission-related lines:")
            out += _lines(text, PERM_LINE, 15 if focus == "trust" else 25) or ["    (none matched)"]

    target = out_dir / "disagreement_dossier.txt"
    target.write_text("\n".join(out) + "\n")
    print(f"{len(rung_dis)} rung + {len(breadth_only)} breadth-only disagreements -> {target}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    main(Path(ap.parse_args().out))
