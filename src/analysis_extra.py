"""
Robustness analyses for the paper. Reads the frozen v2.2 outputs; does not
change any classification.

    python3 src/analysis_extra.py --out data/

  A. Funnel: how 6,716 candidates become the 341 roles with both axes, and why
     files drop out at each step.
  B. StringEquals check: in IAM, '*' is a wildcard only under the *Like
     operators. Under StringEquals a sub value such as "repo:o/r:*" matches only
     the literal string, which GitHub never issues, so that pattern admits no
     workflow. Counts such patterns and regrades files with them removed.
  C. Rule 5 sensitivity: breadth under the v1 rule ("a policy that writes in
     more than one service is P2") vs the v2 rule (resource scope decides).
  D. Single-role subset: the cross-tab restricted to files with exactly one
     GitHub-trusted statement, to show multi-role files do not drive the result.

Writes data/analysis_extra.txt (everything printed).
"""

from __future__ import annotations

import argparse
import csv
import io
import json
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path

import permissions as perm
from classify import (GH_ISSUER, RUNG_ORDER, _classify_sub, _extract_json_policies_from_hcl,
                      _extract_native_policy_documents, _iter_conditions, _loosest,
                      _placeholder, _sub_values, _walk_for_policies)
from resolve_permissions import roles_for_trust_file

RESOLVED = ["S0", "S1", "S2", "S3", "S4"]
LOOSE = {"S0", "S1", "S2"}
GRADED = ["P0", "P1", "P2", "P3"]
BROAD = {"P2", "P3"}


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _pct(a, b):
    return f"{a / b * 100:5.1f}%" if b else "   n/a"


def _crosstab(rows, breadth_key, title):
    both = [r for r in rows if r["_rung"] in RESOLVED and r[breadth_key] in GRADED]
    print(f"\n{title}  (both axes resolved: {len(both)} of {len(rows)})")
    print("          P0    P1    P2    P3")
    for rg in RESOLVED:
        c = Counter(r[breadth_key] for r in both if r["_rung"] == rg)
        n = sum(c.values())
        if n:
            print(f"   {rg}  " + "".join(f"{c.get(p, 0):>6}" for p in GRADED) + f"   (n={n})")
    core = sum(1 for r in both if r["_rung"] in LOOSE and r[breadth_key] in BROAD)
    s2p3 = sum(1 for r in both if r["_rung"] == "S2" and r[breadth_key] == "P3")
    print(f"   core cell loose x broad: {core} of {len(both)} ({_pct(core, len(both)).strip()})"
          f"   S2 x P3: {s2p3} ({_pct(s2p3, len(both)).strip()})")
    return core, len(both)


def _policies(path: Path, text: str):
    """Policy documents exactly as classify_file extracts them, plus CFN defaults."""
    suffix = path.suffix.lower()
    params = {}
    if suffix == ".json":
        try:
            doc = json.loads(text)
        except ValueError:
            return [], params
    elif suffix in (".yaml", ".yml"):
        doc = perm._load_cfn(text)
        if doc is None:
            return [], params
    else:
        return _extract_json_policies_from_hcl(text) + _extract_native_policy_documents(text), params
    out = []
    _walk_for_policies(doc, out)
    p = doc.get("Parameters") if isinstance(doc, dict) else None
    if isinstance(p, dict):
        params = {k: v.get("Default") for k, v in p.items()
                  if isinstance(v, dict) and v.get("Default") not in (None, "")}
    return out, params


def _github_statements(path: Path, text: str):
    """[(operator, claim, raw_value)] per GitHub web-identity statement."""
    pols, params = _policies(path, text)
    stmts = []
    for pol in pols:
        ss = pol.get("Statement", [])
        for s in (ss if isinstance(ss, list) else [ss]):
            if not isinstance(s, dict):
                continue
            acts = s.get("Action", [])
            acts = acts if isinstance(acts, list) else [acts]
            if not any("AssumeRoleWithWebIdentity" in str(a) for a in acts):
                continue
            cond = s.get("Condition", {})
            keyed = [(op, str(k), v) for op, m in (cond.items() if isinstance(cond, dict) else [])
                     if isinstance(m, dict) for k, v in m.items()]
            if not (GH_ISSUER in json.dumps(s.get("Principal", {}), default=str)
                    or any(GH_ISSUER in k for _, k, _ in keyed)):
                continue
            stmts.append(keyed)
    return stmts, {"text": text, "params": params}


# --------------------------------------------------------------------------
# A. funnel
# --------------------------------------------------------------------------

def funnel(rows):
    print("=" * 78)
    print("A. FUNNEL")
    print("=" * 78)
    n = len(rows)
    excl = [r for r in rows if r.get("exclusions")]
    reasons = Counter(x for r in excl for x in r["exclusions"].split(";") if x)
    kept = [r for r in rows if r["kept"] == "True"]
    weak = [r for r in rows if not r.get("exclusions") and r["kept"] != "True"]
    print(f"candidates classified                  {n:>6}")
    print(f"  hard-excluded (any reason)           {len(excl):>6}")
    for k, v in reasons.most_common():
        print(f"      {k:<32} {v:>6}")
    print(f"  fewer than 3 of 4 deployment signals {len(weak):>6}")
    print(f"kept as deployed                       {len(kept):>6}")
    rung = Counter(r["rung"] for r in kept)
    u3 = [r for r in kept if r["rung"] == "U3"]
    why = Counter()
    for r in u3:
        reason = r.get("reason", "")
        ext = Path(r["path"]).suffix.lower()
        if "assertion" in reason:
            why["test/assertion code"] += 1
        elif "issuer is not" in reason:
            why["web-identity trust for another issuer"] += 1
        elif ext in (".ts", ".js", ".py", ".go"):
            why["application code mentioning the issuer (no AWS trust)"] += 1
        else:
            why["IaC without an AWS GitHub trust (provider-only, Azure/GCP, module inputs, variables)"] += 1
    print(f"  not an AWS GitHub trust (U3)         {len(u3):>6}")
    for k, v in why.most_common():
        print(f"      {k:<62} {v:>4}")
    print(f"  trust shape not in file (U1)         {rung.get('U1', 0):>6}")
    print(f"  parse error                          {rung.get('PARSE_ERROR', 0) + rung.get('TIMEOUT', 0):>6}")
    res = [r for r in kept if r["rung"] in RESOLVED]
    print(f"AWS GitHub trusts with a graded rung    {len(res):>6}")
    pu2 = [r for r in res if r.get("perm_breadth_final") == "PU2"]
    print(f"  permissions not visible (PU2)        {len(pu2):>6}")
    both = [r for r in res if r.get("perm_breadth_final") in GRADED]
    src = Counter(r.get("perm_source", "") for r in both)
    print(f"roles with both axes resolved           {len(both):>6}   (breadth source: {dict(src)})")


# --------------------------------------------------------------------------
# B. StringEquals literal wildcard
# --------------------------------------------------------------------------

def string_equals(rows, blobs):
    print("\n" + "=" * 78)
    print("B. STRINGEQUALS CHECK ('*' is literal under *Equals operators)")
    print("=" * 78)
    files_hit, pats_hit, unparsed, changed = 0, 0, 0, Counter()
    for r in rows:
        r["_rung_se"] = r["rung"]
        if r["rung"] not in RESOLVED:
            continue
        p = blobs.get(r["key"])
        if not p:
            unparsed += 1
            continue
        text = p.read_text(encoding="utf-8-sig", errors="replace")
        stmts, ctx = _github_statements(p, text)
        if not stmts:
            unparsed += 1  # salvage-coded: no operator information
            continue
        stmt_rungs, hit_here = [], False
        for keyed in stmts:
            pats = []
            jwr_seen = False
            for op, key, val in keyed:
                claim = key.rsplit(":", 1)[-1]
                if claim == "job_workflow_ref":
                    jwr_seen = True
                if claim != "sub":
                    continue
                vals = _sub_values(val, ctx)
                literal = "Equals" in op and "Not" not in op
                for v in vals:
                    if literal and "*" in _placeholder(v):
                        pats_hit += 1
                        hit_here = True
                        continue  # admits no real token: drop it
                    pats.append(v)
            grades = [g for g, _, _ in map(_classify_sub, pats) if g in RUNG_ORDER]
            if grades:
                stmt_rungs.append(_loosest(grades))
            elif not pats and not any(k.rsplit(":", 1)[-1] == "sub" for _, k, _ in keyed) and not jwr_seen:
                stmt_rungs.append("S0")  # genuinely no sub condition
            # a statement whose only sub patterns were literal wildcards admits nobody
        if hit_here:
            files_hit += 1
            new = _loosest(stmt_rungs) if stmt_rungs else "NONE"
            r["_rung_se"] = new if new != "NONE" else "ADMITS_NONE"
            if r["_rung_se"] != r["rung"]:
                changed[(r["rung"], r["_rung_se"])] += 1
    print(f"wildcard sub patterns under a *Equals operator: {pats_hit} in {files_hit} files")
    print(f"files without operator information (text-scan coded): {unparsed}")
    if changed:
        print("rung changes if those patterns are treated as matching nothing:")
        for (a, b), n in changed.most_common():
            print(f"   {a} -> {b}: {n}")
    else:
        print("no rung changes")


# --------------------------------------------------------------------------
# C. Rule 5 sensitivity
# --------------------------------------------------------------------------

def _old_grade(actions, resources, not_action=False):
    g = _new_grade(actions, resources, not_action)
    if g in (None, "P3", "P2"):
        return g
    acts = [a for a in actions if isinstance(a, str) and ":" in a]
    services = {a.split(":", 1)[0].lower() for a in acts}
    writes = [a for a in acts if perm._is_write(a)]
    if writes and len(services) > 1:
        return "P2"
    return g


_new_grade = perm.grade_actions


def _union_grade_stmts(stmts, tag, grades, evidence):
    """v1 graded a policy's statements as one union of actions and resources."""
    acts = [a for s in stmts for a in s[0]]
    res = [x for s in stmts for x in s[1]]
    g = perm._broadest([_old_grade(acts, res, any(s[2] for s in stmts))])
    if g:
        grades.append(g)
        evidence.append(f"{tag}={g}")


def rule5(rows, blobs, cache):
    print("\n" + "=" * 78)
    print("C. RULE 5 SENSITIVITY (v1: multi-service writes = P2; v2: resource scope decides)")
    print("=" * 78)
    orig_ga, orig_gs = perm.grade_actions, perm._grade_stmts
    perm.grade_actions = _old_grade
    perm._grade_stmts = _union_grade_stmts
    try:
        for r in rows:
            r["_b_v1"] = r.get("perm_breadth_final", "")
            if r["rung"] not in RESOLVED or r.get("perm_breadth_final") not in GRADED:
                continue
            p = blobs.get(r["key"])
            text = p.read_text(encoding="utf-8-sig", errors="replace") if p else ""
            if r.get("perm_source") == "cross-file":
                ct = cache / (r["repo"].replace("/", "__") + ".txt")
                repo_text = ct.read_text(errors="replace") if ct.exists() else ""
                best = None
                for rn, na in roles_for_trust_file(text, r["path"], repo_text):
                    b, _ = perm.resolve_role_breadth(repo_text, rn, na)
                    best = perm._broadest([x for x in (best, b) if x])
                r["_b_v1"] = best or r["perm_breadth_final"]
            else:
                b, _ = perm.classify_permissions(text, Path(r["path"]).suffix)
                r["_b_v1"] = b if b in GRADED else r["perm_breadth_final"]
    finally:
        perm.grade_actions, perm._grade_stmts = orig_ga, orig_gs
    moved = Counter((r["perm_breadth_final"], r["_b_v1"]) for r in rows
                    if r["rung"] in RESOLVED and r.get("perm_breadth_final") in GRADED
                    and r["_b_v1"] != r["perm_breadth_final"])
    print("breadth changes from v2 to v1:", dict(moved) if moved else "none")


# --------------------------------------------------------------------------
# D. Single-role subset
# --------------------------------------------------------------------------

def single_role(rows, blobs):
    print("\n" + "=" * 78)
    print("D. SINGLE-ROLE SUBSET")
    print("=" * 78)
    counts = Counter()
    for r in rows:
        r["_nroles"] = None
        if r["rung"] not in RESOLVED:
            continue
        p = blobs.get(r["key"])
        if not p:
            continue
        stmts, _ = _github_statements(p, p.read_text(encoding="utf-8-sig", errors="replace"))
        r["_nroles"] = len(stmts) if stmts else None
        counts["unknown (text-scan coded)" if not stmts else ("1" if len(stmts) == 1 else "2+")] += 1
    print("GitHub-trust statements per resolved file:", dict(counts))
    return [r for r in rows if r["_nroles"] == 1]


# --------------------------------------------------------------------------

def main(out_dir: Path):
    rows = list(csv.DictReader((out_dir / "coded_resolved.csv").open()))
    blobs = {p.stem: p for p in (out_dir / "blobs").iterdir()
             if p.is_file() and not p.name.startswith(".")}
    cache = out_dir / "repo_cache"
    kept = [r for r in rows if r["kept"] == "True"]
    for r in kept:
        r["_rung"] = r["rung"]

    funnel(rows)
    string_equals(kept, blobs)
    rule5(kept, blobs, cache)
    singles = single_role(kept, blobs)

    print("\n" + "=" * 78)
    print("CROSS-TABS")
    print("=" * 78)
    _crosstab(kept, "perm_breadth_final", "Main (v2.2 as frozen)")
    _crosstab(kept, "_b_v1", "Rule 5 v1 (multi-service writes = P2)")
    for r in kept:
        r["_rung"] = r["_rung_se"] if r.get("_rung_se") in RESOLVED else (
            "X" if r.get("_rung_se") == "ADMITS_NONE" else r["rung"])
    _crosstab(kept, "perm_breadth_final", "StringEquals wildcards treated as matching nothing")
    for r in kept:
        r["_rung"] = r["rung"]
    _crosstab(singles, "perm_breadth_final", "Single-role files only")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    out = Path(ap.parse_args().out)
    buf = io.StringIO()
    with redirect_stdout(buf):
        main(out)
    text = buf.getvalue()
    print(text)
    (out / "analysis_extra.txt").write_text(text)
    print(f"wrote {out / 'analysis_extra.txt'}")
