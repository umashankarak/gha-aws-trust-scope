"""
Build a BLIND labeling page for classifier validation.

Draws a stratified random sample from the kept set (stratified by the
classifier's trust rung so rare rungs get enough items), and writes a
self-contained HTML page that shows each file WITHOUT the classifier's answer.
You label trust rung and permission breadth; the page autosaves in your
browser and exports labels.csv. Then run score_labels.py.

Run (on your machine):
    python3 src/make_label_sheet.py --out data/
    open data/label.html

The sample and seed are written to data/label_sample.csv so the draw is
reproducible and reportable.
"""

from __future__ import annotations

import argparse
import csv
import html
import json
import random
import re
from pathlib import Path

from diagnose_disagreements import TRUST_LINE, PERM_LINE


def _key_lines(text: str, cap: int = 60) -> str:
    """The lines that decide the labels, with line numbers, so most items can be
    labeled without scrolling the whole file."""
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if TRUST_LINE.search(line) or PERM_LINE.search(line) or re.search(r'aws:policy/|Statement', line):
            out.append(f"{i:>5}: {line.rstrip()[:180]}")
            if len(out) >= cap:
                out.append("  ... more in the full file below")
                break
    return "\n".join(out) or "(no trust or permission lines matched: open the full file)"

# Items per classifier stratum. Small strata are taken whole.
DEFAULT_PLAN = {"S0": 25, "S1": 12, "S2": 30, "S3": 30, "S4": 25, "U1": 15, "U3": 30}
# Held-out validation sample, drawn AFTER the pass-1 fixes from items never
# labeled before. This is the sample whose accuracy the paper reports.
HOLDOUT_PLAN = {"S0": 8, "S1": 8, "S2": 12, "S3": 10, "S4": 10, "U1": 6, "U3": 6}
MAX_FILE_CHARS = 30000
MAX_REPO_CHARS = 40000


def _read(p: Path, limit: int) -> str:
    try:
        t = p.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return ""
    return t if len(t) <= limit else t[:limit] + f"\n\n... [truncated at {limit} chars]"


def build(out_dir: Path, seed: int, retest: int, holdout: int = 0, retest_of: str = "pass1"):
    src = out_dir / "coded_resolved.csv"
    if not src.exists():
        src = out_dir / "coded.csv"
    rows = [r for r in csv.DictReader(src.open()) if r["kept"] == "True"]
    blobs = {p.stem: p for p in (out_dir / "blobs").iterdir()
             if p.is_file() and not p.name.startswith(".")}
    cache = out_dir / "repo_cache"

    rng = random.Random(seed)
    sample = []

    if retest:
        # Intra-rater retest: re-draw from items already labeled in an earlier pass.
        prior = out_dir / ("label_sample.csv" if retest_of == "pass1" else "label_holdout_sample.csv")
        if not prior.exists():
            raise SystemExit(f"No {prior.name} yet: label that pass before --retest.")
        first = list(csv.DictReader(prior.open()))
        sample = rng.sample(first, min(retest, len(first)))
        tag = "retest" if retest_of == "pass1" else "holdout_retest"
    elif holdout:
        seen = set()
        for prior in ("label_sample.csv",):
            pp = out_dir / prior
            if pp.exists():
                seen |= {r["key"] for r in csv.DictReader(pp.open())}
        fresh = [r for r in rows if r["key"] not in seen]
        by_rung: dict[str, list] = {}
        for r in fresh:
            by_rung.setdefault(r["rung"], []).append(r)
        total = sum(HOLDOUT_PLAN.values())
        for rung, n in HOLDOUT_PLAN.items():
            n = max(1, round(n * holdout / total))
            pool = by_rung.get(rung, [])
            take = pool if len(pool) <= n else rng.sample(pool, n)
            for r in take:
                sample.append({"key": r["key"], "repo": r["repo"], "path": r["path"],
                               "stratum": rung, "stratum_size": len(pool)})
        rng.shuffle(sample)
        tag = "holdout"
        with (out_dir / "label_holdout_sample.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["key", "repo", "path", "stratum", "stratum_size"])
            w.writeheader()
            w.writerows(sample)
        (out_dir / "label_seed_holdout.txt").write_text(
            f"seed={seed}\nplan={json.dumps(HOLDOUT_PLAN)}\nrequested={holdout}\n"
            f"excluded_pass1_keys={len(seen)}\n")
    else:
        by_rung: dict[str, list] = {}
        for r in rows:
            by_rung.setdefault(r["rung"], []).append(r)
        for rung, n in DEFAULT_PLAN.items():
            pool = by_rung.get(rung, [])
            take = pool if len(pool) <= n else rng.sample(pool, n)
            for r in take:
                sample.append({"key": r["key"], "repo": r["repo"], "path": r["path"],
                               "stratum": rung, "stratum_size": len(pool)})
        rng.shuffle(sample)  # interleave strata so order does not leak the answer
        tag = "pass1"
        with (out_dir / "label_sample.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["key", "repo", "path", "stratum", "stratum_size"])
            w.writeheader()
            w.writerows(sample)
        (out_dir / "label_seed.txt").write_text(f"seed={seed}\nplan={json.dumps(DEFAULT_PLAN)}\n")

    items = []
    for i, s in enumerate(sample):
        blob = blobs.get(s["key"])
        repo_txt = ""
        cached = cache / (s["repo"].replace("/", "__") + ".txt")
        if cached.exists():
            repo_txt = _read(cached, MAX_REPO_CHARS)
        ftxt = _read(blob, MAX_FILE_CHARS) if blob else "(blob missing)"
        items.append({
            "n": i + 1, "key": s["key"], "repo": s["repo"], "path": s["path"],
            "file": ftxt, "key_lines": _key_lines(ftxt),
            "repo_other": repo_txt,
        })

    page = _PAGE.replace("__DATA__", json.dumps(items).replace("</", "<\\/"))
    page = page.replace("__TAG__", tag).replace("__COUNT__", str(len(items)))
    target = out_dir / {"pass1": "label.html", "retest": "label_retest.html",
                        "holdout": "label_holdout.html",
                        "holdout_retest": "label_holdout_retest.html"}[tag]
    target.write_text(page)
    print(f"{len(items)} items -> {target}")
    print("Open it in a browser. Labels autosave; click 'Export CSV' when done.")


_PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Blind labeling (__TAG__)</title>
<style>
:root{--bg:#fbfaf7;--fg:#1d1d1b;--muted:#6b6a64;--line:#e3e0d8;--card:#fff;--accent:#b4441f;--sel:#f4e2d8;--code:#f3f1ec}
@media (prefers-color-scheme:dark){:root{--bg:#171715;--fg:#ecebe6;--muted:#a19f97;--line:#33322e;--card:#1f1f1c;--accent:#e98a5f;--sel:#3a2a22;--code:#22221f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,system-ui,sans-serif}
header{position:sticky;top:0;z-index:2;background:var(--bg);border-bottom:1px solid var(--line);padding:10px 16px;display:flex;gap:12px;align-items:center;flex-wrap:wrap}
header b{font-size:16px}.bar{flex:1;min-width:120px;height:6px;background:var(--line);border-radius:3px}.bar i{display:block;height:100%;background:var(--accent);border-radius:3px}
main{display:grid;grid-template-columns:minmax(0,1fr) 340px;gap:16px;padding:16px;max-width:1400px;margin:0 auto}
@media (max-width:900px){main{grid-template-columns:minmax(0,1fr)}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
pre{background:var(--code);border-radius:8px;padding:12px;overflow:auto;max-height:62vh;font:12.5px/1.45 ui-monospace,Menlo,monospace;white-space:pre}
.meta{color:var(--muted);font-size:13px;word-break:break-all}
h3{margin:14px 0 6px;font-size:14px}.opts{display:flex;flex-wrap:wrap;gap:6px}
.opts button{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:7px;padding:6px 10px;font:600 13px system-ui;cursor:pointer}
.opts button.on{background:var(--accent);color:#fff;border-color:var(--accent)}
textarea{width:100%;min-height:60px;background:var(--code);color:var(--fg);border:1px solid var(--line);border-radius:7px;padding:8px;font:13px system-ui}
.nav{display:flex;gap:8px;margin-top:12px}.nav button,header button{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:7px;padding:7px 12px;cursor:pointer;font:600 13px system-ui}
.nav button.primary{background:var(--accent);color:#fff;border-color:var(--accent)}
details{margin-top:10px}summary{cursor:pointer;color:var(--muted);font-size:13px}
.cb{font-size:13px}.cb dt{font-weight:700;margin-top:6px}.cb dd{margin:0 0 2px 0;color:var(--muted)}
.done{color:var(--accent);font-weight:700}
</style></head><body>
<header><b>Blind labeling — __TAG__</b><span id="pos"></span><div class="bar"><i id="prog"></i></div>
<span id="cnt" class="meta"></span><button onclick="exportCsv()">Export CSV</button></header>
<main>
<section class="card">
  <div class="meta" id="where"></div>
  <h3>Key lines (trust conditions and permissions)</h3>
  <pre id="keylines"></pre>
  <details id="fileWrap"><summary>Full file</summary><pre id="file"></pre></details>
  <details id="otherWrap"><summary>Other IaC files from this repo (for judging permissions)</summary><pre id="other"></pre></details>
</section>
<aside class="card">
  <h3>Trust rung (who can assume)</h3><div class="opts" id="rung"></div>
  <h3>Permission breadth (what the GitHub role can do)</h3><div class="opts" id="breadth"></div>
  <h3>Note (optional)</h3><textarea id="note" placeholder="Anything ambiguous?"></textarea>
  <div class="nav"><button onclick="go(-1)">← Prev</button><button class="primary" onclick="go(1)">Next →</button><button onclick="jumpNext()">Next unlabeled</button></div>
  <p class="meta">Keys: 1–7 trust rung, q w e r t y breadth, ← → move</p>
  <details open><summary>Codebook v2</summary><dl class="cb">
    <dt>Trust: which GitHub workflows can assume the role</dt>
    <dd>Several roles or subjects in the file: grade the loosest.
      ${var.x}, ${Param} and &lt;PLACEHOLDER&gt; in the owner/repo count as named.
      Resolve locals, variable/parameter defaults and Fn::Sub in this file.
      @12345 or @* after a name is an ID, not a wildcard.</dd>
    <dt>S0</dt><dd>Anyone on GitHub: no sub condition, owner is *, or owner prefix wildcard (repo:acme*/x)</dd>
    <dt>S1</dt><dd>Any repo in one org: repo:acme/* or repo:acme/web-*</dd>
    <dt>S2</dt><dd>One repo, any branch or tag: repo:acme/web:* — also any * in the ref or environment (refs/heads/*, refs/tags/v*, environment:*, environment:prod-*)</dd>
    <dt>S3</dt><dd>One repo + a literal ref or pull_request (:ref:refs/heads/main)</dd>
    <dt>S4</dt><dd>One repo + a literal environment (:environment:prod), or job_workflow_ref pinned at a literal ref</dd>
    <dt>U1</dt><dd>GitHub trust, but the sub's shape is not in this file (bare variable/parameter with no default, or built by code)</dd>
    <dt>U3</dt><dd>Not an AWS IAM trust for GitHub Actions: Azure/GCP federation, token-verification code, tests, module calls that only pass subjects, provider-only files</dd>
    <dt>Breadth: what the GitHub role can do</dt>
    <dd>Only the GitHub role's permissions. Ignore other roles in the file (ECS task, EKS node, Lambda roles) and policies with a Principal (bucket/key policies).</dd>
    <dt>P0</dt><dd>Read-only</dd>
    <dt>P1</dt><dd>Writes only on named resources, in any number of services (one bucket + one CloudFront distribution = P1). ecr:GetAuthorizationToken on * does not count.</dd>
    <dt>P2</dt><dd>svc:* actions; writes on * or on every resource of a type (function:*); *FullAccess; ReadOnlyAccess; service PowerUser; EKS ClusterAdmin</dd>
    <dt>P3</dt><dd>*, AdministratorAccess, PowerUserAccess, IAMFullAccess, any iam: write including PassRole, sts:AssumeRole on * or on CDK bootstrap roles (role/cdk-*)</dd>
    <dt>PU2</dt><dd>Nothing attached to the GitHub role is visible. Use "Other files" only if a file there explicitly attaches a policy to this role (by name/reference, or loads this trust file).</dd>
    <dt>N/A</dt><dd>U3 items</dd>
  </dl></details>
</aside>
</main>
<script>
const ITEMS = __DATA__;
const KEY = "oidc-label-__TAG__";
const RUNGS = ["S0","S1","S2","S3","S4","U1","U3"], BREADTHS = ["P0","P1","P2","P3","PU2","N/A"];
let store = {}; try { store = JSON.parse(localStorage.getItem(KEY) || "{}"); } catch(e) {}
let i = 0;
function save(){ try { localStorage.setItem(KEY, JSON.stringify(store)); } catch(e) {} }
function cur(){ return store[ITEMS[i].key] || (store[ITEMS[i].key] = {}); }
function buttons(id, opts, field){
  const el = document.getElementById(id); el.innerHTML = "";
  opts.forEach(o => { const b = document.createElement("button"); b.textContent = o;
    if (cur()[field] === o) b.className = "on";
    b.onclick = () => { cur()[field] = o; save(); render(); }; el.appendChild(b); });
}
function render(){
  const it = ITEMS[i];
  document.getElementById("where").textContent = `#${it.n}  ${it.repo}  ::  ${it.path}`;
  document.getElementById("file").textContent = it.file;
  document.getElementById("keylines").textContent = it.key_lines || "";
  const ow = document.getElementById("otherWrap");
  ow.style.display = it.repo_other ? "" : "none";
  document.getElementById("other").textContent = it.repo_other || "";
  buttons("rung", RUNGS, "rung"); buttons("breadth", BREADTHS, "breadth");
  const note = document.getElementById("note"); note.value = cur().note || "";
  note.oninput = () => { cur().note = note.value; save(); };
  const done = ITEMS.filter(x => store[x.key] && store[x.key].rung && store[x.key].breadth).length;
  document.getElementById("pos").textContent = `${i+1} / ${ITEMS.length}`;
  document.getElementById("cnt").innerHTML = done === ITEMS.length ? '<span class="done">All labeled — export</span>' : `${done} labeled`;
  document.getElementById("prog").style.width = (100*done/ITEMS.length) + "%";
}
function go(d){ i = Math.max(0, Math.min(ITEMS.length-1, i+d)); render(); window.scrollTo(0,0); }
function jumpNext(){ for (let k=1;k<=ITEMS.length;k++){ const j=(i+k)%ITEMS.length; const s=store[ITEMS[j].key];
  if(!s||!s.rung||!s.breadth){ i=j; render(); window.scrollTo(0,0); return; } } }
function exportCsv(){
  const q = v => '"' + String(v ?? "").replace(/"/g,'""') + '"';
  const lines = ["key,repo,path,human_rung,human_breadth,note"];
  ITEMS.forEach(it => { const s = store[it.key] || {};
    lines.push([it.key,it.repo,it.path,s.rung,s.breadth,s.note].map(q).join(",")); });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([lines.join("\n")], {type:"text/csv"}));
  a.download = "labels___TAG__.csv"; a.click();
}
document.addEventListener("keydown", e => { if (e.target.tagName === "TEXTAREA") return;
  if (e.key === "ArrowRight") go(1); if (e.key === "ArrowLeft") go(-1);
  const r = "1234567".indexOf(e.key), b = "qwerty".indexOf(e.key.toLowerCase());
  if (r >= 0) { cur().rung = RUNGS[r]; save(); render(); }
  if (b >= 0) { cur().breadth = BREADTHS[b]; save(); render(); } });
render();
</script></body></html>"""


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data")
    ap.add_argument("--seed", type=int, default=20261009)
    ap.add_argument("--retest", type=int, default=0,
                    help="build an intra-rater retest page of N items from an earlier pass")
    ap.add_argument("--retest-of", choices=["pass1", "holdout"], default="pass1")
    ap.add_argument("--holdout", type=int, default=0,
                    help="build the held-out validation page of ~N never-labeled items")
    a = ap.parse_args()
    build(Path(a.out), a.seed, a.retest, a.holdout, a.retest_of)
