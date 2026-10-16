"""
Stage 1 -- collect candidate trust-policy files from public GitHub.

Run:  python3 src/collect.py --out data/

GitHub caps any single code-search query at 1,000 returned results, so a frame
that matches more than that is SHARDED along an axis that partitions the corpus
(file extension, then size bands). Sharding is recorded per result so the
sampling frame is reconstructable -- required for the artifact.
"""

from __future__ import annotations

import argparse
import json
import hashlib
from pathlib import Path

from gh import GitHubClient

ISSUER = "token.actions.githubusercontent.com"

# Each frame is (name, base_query, [shard_clauses]).
# Shards partition results so the 1,000-per-query ceiling can be exceeded.
SIZE_BANDS = ["size:<2000", "size:2000..8000", "size:8000..30000", "size:>30000"]

FRAMES = [
    ("terraform", f'"{ISSUER}" extension:tf', SIZE_BANDS),
    ("cloudformation_yaml", f'"{ISSUER}" AssumeRoleWithWebIdentity extension:yml', SIZE_BANDS),
    ("cloudformation_yaml2", f'"{ISSUER}" AssumeRoleWithWebIdentity extension:yaml', SIZE_BANDS),
    ("cloudformation_json", f'"{ISSUER}" AssumeRoleWithWebIdentity extension:json', SIZE_BANDS),
    ("cdk_typescript", f'"{ISSUER}" extension:ts', SIZE_BANDS),
    # Captured for the ecosystem claim; likely too sparse to analyse alone.
    ("gitlab_aws", '"gitlab.com" AssumeRoleWithWebIdentity extension:tf', SIZE_BANDS),
]


def collect(out_dir: Path, frames=None, limit_per_shard: int = 1000):
    client = GitHubClient()
    out_dir.mkdir(parents=True, exist_ok=True)
    candidates_path = out_dir / "candidates.jsonl"

    seen = set()
    if candidates_path.exists():
        for line in candidates_path.read_text().splitlines():
            if line.strip():
                seen.add(json.loads(line)["key"])
        print(f"resuming: {len(seen)} candidates already collected")

    frames = frames or FRAMES
    written = 0
    with candidates_path.open("a") as fh:
        for name, base, shards in frames:
            for shard in shards:
                query = f"{base} {shard}"
                print(f"[{name}] {query}")
                try:
                    for item, total in client.search_code(query, limit_per_shard):
                        repo = item["repository"]["full_name"]
                        path = item["path"]
                        key = hashlib.sha256(f"{repo}:{path}".encode()).hexdigest()[:16]
                        if key in seen:
                            continue
                        seen.add(key)
                        record = {
                            "key": key,
                            "repo": repo,
                            "path": path,
                            "frame": name,
                            "shard": shard,
                            "shard_total_count": total,
                            "html_url": item.get("html_url"),
                        }
                        fh.write(json.dumps(record) + "\n")
                        fh.flush()
                        written += 1
                except Exception as e:
                    print(f"  ! {name}/{shard} failed: {e}")

    print(f"\ncollected {written} new candidates ({len(seen)} total) -> {candidates_path}")
    return candidates_path


def fetch_files(out_dir: Path):
    """Download each candidate's file content into data/blobs/<key>.<ext>."""
    client = GitHubClient()
    blobs = out_dir / "blobs"
    blobs.mkdir(parents=True, exist_ok=True)
    records = [json.loads(l) for l in (out_dir / "candidates.jsonl").read_text().splitlines() if l.strip()]

    fetched = skipped = failed = 0
    for i, rec in enumerate(records, 1):
        ext = Path(rec["path"]).suffix or ".txt"
        dest = blobs / f"{rec['key']}{ext}"
        if dest.exists():
            skipped += 1
            continue
        try:
            content = client.raw_file(rec["repo"], rec["path"])
            if content is None:
                failed += 1
                continue
            dest.write_text(content)
            fetched += 1
        except Exception as e:
            print(f"  ! {rec['repo']}/{rec['path']}: {e}")
            failed += 1
        if i % 50 == 0:
            print(f"  {i}/{len(records)} (fetched={fetched} cached={skipped} failed={failed})")

    print(f"\nfetched {fetched}, cached {skipped}, failed {failed} -> {blobs}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Collect OIDC trust-policy candidates from public GitHub.")
    ap.add_argument("--out", default="data", help="output directory (default: data)")
    ap.add_argument("--search-only", action="store_true", help="run search frames, do not download files")
    ap.add_argument("--fetch-only", action="store_true", help="download files for existing candidates.jsonl")
    args = ap.parse_args()

    out = Path(args.out)
    if not args.fetch_only:
        collect(out)
    if not args.search_only:
        fetch_files(out)
