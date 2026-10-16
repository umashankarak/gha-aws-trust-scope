"""
Minimal GitHub REST client for corpus collection.

Auth: reads GITHUB_TOKEN from the environment. The token needs NO scopes --
a fine-grained PAT with read-only public-repo access, or a classic token with
nothing checked, is enough. We authenticate for the rate-limit bucket
(5,000 req/hr vs 60) and because /search/code rejects anonymous requests.
"""

from __future__ import annotations

import os
import sys
import time
import json
import urllib.request
import urllib.parse
import urllib.error

API = "https://api.github.com"


class RateLimited(Exception):
    pass


class GitHubClient:
    def __init__(self, token: str | None = None, verbose: bool = True):
        self.token = token or os.environ.get("GITHUB_TOKEN", "").strip()
        if not self.token:
            raise SystemExit(
                "No token found.\n\n"
                "  export GITHUB_TOKEN=ghp_xxxxxxxxxxxx\n\n"
                "Create one at https://github.com/settings/tokens\n"
                "Fine-grained: Public Repositories (read-only). Classic: tick NO scopes.\n"
                "The study reads only public data; the token is for rate limits."
            )
        self.verbose = verbose
        self._last_search = 0.0

    def _request(self, url: str, accept: str = "application/vnd.github+json") -> tuple[dict | list, dict]:
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Bearer {self.token}")
        req.add_header("Accept", accept)
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        req.add_header("User-Agent", "oidc-scope-study")

        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    headers = dict(resp.headers)
                    body = resp.read()
                    if accept.endswith("raw"):
                        return body.decode("utf-8", errors="replace"), headers
                    return json.loads(body), headers
            except urllib.error.HTTPError as e:
                remaining = e.headers.get("x-ratelimit-remaining")
                if e.code in (403, 429) and remaining == "0":
                    reset = int(e.headers.get("x-ratelimit-reset", time.time() + 60))
                    wait = max(reset - time.time(), 1) + 2
                    self._log(f"  rate limit hit, sleeping {int(wait)}s")
                    time.sleep(wait)
                    continue
                if e.code in (502, 503):
                    time.sleep(2 ** attempt)
                    continue
                if e.code == 401:
                    raise SystemExit("GitHub rejected the token (401). Check GITHUB_TOKEN.")
                if e.code == 404:
                    return None, dict(e.headers)
                raise
            except urllib.error.URLError:
                time.sleep(2 ** attempt)
        raise RateLimited(f"gave up after retries: {url}")

    def _log(self, msg: str):
        if self.verbose:
            print(msg, file=sys.stderr, flush=True)

    def search_code(self, query: str, max_results: int = 1000):
        """
        Paginate /search/code.

        Two hard limits from GitHub, both of which shape the sampling frame:
          - 10 requests/minute for code search (we self-throttle to 7s apart)
          - 1,000 results per query, regardless of total_count
        Exceeding 1,000 requires SHARDING the query (see collect.py), not paging.
        """
        per_page = 100
        seen_total = None
        for page in range(1, (max_results // per_page) + 1):
            gap = time.time() - self._last_search
            if gap < 7:
                time.sleep(7 - gap)
            url = f"{API}/search/code?q={urllib.parse.quote(query)}&per_page={per_page}&page={page}"
            data, _ = self._request(url)
            self._last_search = time.time()
            if not data:
                break
            if seen_total is None:
                seen_total = data.get("total_count", 0)
                self._log(f"  total_count={seen_total} for {query[:70]}")
            items = data.get("items", [])
            if not items:
                break
            for item in items:
                yield item, seen_total
            if len(items) < per_page:
                break

    def repo(self, full_name: str) -> dict | None:
        data, _ = self._request(f"{API}/repos/{full_name}")
        return data

    def raw_file(self, full_name: str, path: str, ref: str = "HEAD") -> str | None:
        url = f"{API}/repos/{full_name}/contents/{urllib.parse.quote(path)}?ref={ref}"
        data, _ = self._request(url, accept="application/vnd.github.raw")
        return data

    def contributors_count(self, full_name: str) -> int:
        data, headers = self._request(f"{API}/repos/{full_name}/contributors?per_page=1&anon=false")
        link = headers.get("Link", "")
        if 'rel="last"' in link:
            for part in link.split(","):
                if 'rel="last"' in part:
                    try:
                        return int(part.split("page=")[-1].split(">")[0].split("&")[0])
                    except (ValueError, IndexError):
                        pass
        return len(data) if isinstance(data, list) else 0

    def list_tree(self, full_name: str, ref: str = "HEAD") -> list[str]:
        data, _ = self._request(f"{API}/repos/{full_name}/git/trees/{ref}?recursive=1")
        if not data or "tree" not in data:
            return []
        return [n["path"] for n in data["tree"] if n.get("type") == "blob"]

    def rate_limit(self) -> dict:
        data, _ = self._request(f"{API}/rate_limit")
        return data
