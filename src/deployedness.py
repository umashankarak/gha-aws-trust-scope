"""
Stage 2 -- the deployedness filter.

Keeps repositories showing operational signals; drops tutorials, demos and
scaffolding. Deliberately does NOT filter on stars: stars reward teaching
value, so a popularity filter keeps tutorials and discards quiet production
repos -- the exact opposite of what the study needs.

Four signals, pass >= 3 by default. The threshold is a parameter, not a truth:
report prevalence at both 3-of-4 and 4-of-4.
"""

from __future__ import annotations

import re
import json
from datetime import datetime, timezone
from pathlib import Path

TUTORIAL_WORDS = re.compile(
    r"\b(tutorial|demo|example|examples|sample|samples|workshop|getting[-_ ]?started"
    r"|poc|proof[-_ ]of[-_ ]concept|hello[-_ ]world|learn|learning|bootcamp|training"
    r"|course|kata|katas|playground|scratch|sandbox|test[-_ ]?repo|boilerplate"
    r"|starter|template|blueprint|cookbook|guide|tutorials)\b",
    re.IGNORECASE,
)

PLACEHOLDER_ACCOUNT = re.compile(
    r"(123456789012|111122223333|000000000000|<[^>]*account[^>]*>|YOUR[-_ ]?ACCOUNT"
    r"|ACCOUNT[-_ ]?ID|AWS_ACCOUNT_ID|\bxxxx+\b|012345678901)",
    re.IGNORECASE,
)

ENV_PLURALITY = re.compile(
    r"(^|/)(dev|development|staging|stage|prod|production|qa|test|preprod|uat)"
    r"(/|\.tfvars|\.tf$|$)",
    re.IGNORECASE,
)

# Paths that are not a trust-policy DEFINITION and must not be coded:
#  - synthetic test fixtures / vendored code (not real deployments)
#  - test/spec source files (assertions about policies, not policies)
#  - .github/workflows/*.yml -- the CONSUMER side (the job that assumes the
#    role), which often mentions the issuer and even quotes a sub in comments.
# Conservative on dirs: bare test/ and examples/ are left in (too broad) and
# noted as a threats-to-validity limit; test FILES (*.test.*, *.spec.*) are out.
FIXTURE_PATH = re.compile(
    r"(^|/)(testdata|fixtures?|corpus|__snapshots__|__fixtures__|__tests__|vendor"
    r"|node_modules|\.terraform|\.external_modules|golden|snapshots)(/|$)"
    r"|(^|/)\.github/workflows/"
    r"|\.(test|spec)\.[a-z]+$",
    re.IGNORECASE,
)

INSTRUCTIONAL_README = re.compile(
    r"(^|\n)\s*(#+\s*)?(prerequisites|step\s*1|getting started|what you.ll (need|build)"
    r"|in this (tutorial|guide|workshop))",
    re.IGNORECASE,
)


def signal_workflow_consumes_role(tree: list[str], workflow_texts: dict[str, str]) -> bool:
    """A workflow that actually requests a token and configures cloud creds."""
    has_workflow = any(p.startswith(".github/workflows/") for p in tree)
    if not has_workflow:
        return False
    for text in workflow_texts.values():
        if not text:
            continue
        wants_token = "id-token" in text and "write" in text
        configures = any(
            marker in text
            for marker in (
                "aws-actions/configure-aws-credentials",
                "google-github-actions/auth",
                "azure/login",
            )
        )
        if wants_token and configures:
            return True
    return False


def signal_real_account(policy_text: str) -> bool:
    """Concrete account identifiers rather than documentation placeholders."""
    if not policy_text:
        return False
    return not bool(PLACEHOLDER_ACCOUNT.search(policy_text))


def signal_operational_history(repo_meta: dict, contributors: int) -> bool:
    """Two or more contributors AND activity spanning more than 90 days."""
    if contributors < 2:
        return False
    try:
        created = datetime.fromisoformat(repo_meta["created_at"].replace("Z", "+00:00"))
        pushed = datetime.fromisoformat(repo_meta["pushed_at"].replace("Z", "+00:00"))
    except (KeyError, ValueError, AttributeError):
        return False
    return (pushed - created).days > 90


def signal_environment_plurality(tree: list[str]) -> bool:
    """More than one deployment target visible in the tree."""
    hits = {m.group(2).lower() for p in tree for m in [ENV_PLURALITY.search(p)] if m}
    if len(hits) >= 2:
        return True
    tfvars = [p for p in tree if p.endswith(".tfvars")]
    return len(tfvars) >= 2


def hard_exclusions(repo_meta: dict, readme: str | None) -> list[str]:
    """Reasons to drop the repo outright, before the four signals."""
    reasons = []
    name = repo_meta.get("full_name", "")
    desc = repo_meta.get("description") or ""
    topics = " ".join(repo_meta.get("topics", []) or [])

    if TUTORIAL_WORDS.search(name.split("/")[-1]) or TUTORIAL_WORDS.search(desc) or TUTORIAL_WORDS.search(topics):
        reasons.append("tutorial_vocabulary")
    if repo_meta.get("fork"):
        reasons.append("fork")
    if repo_meta.get("is_template"):
        reasons.append("template_repository")
    if repo_meta.get("archived"):
        reasons.append("archived")
    if readme and INSTRUCTIONAL_README.search(readme[:4000]):
        reasons.append("instructional_readme")
    return reasons


def evaluate(repo_meta: dict, tree: list[str], workflow_texts: dict[str, str],
             policy_text: str, contributors: int, readme: str | None,
             threshold: int = 3) -> dict:
    excl = hard_exclusions(repo_meta, readme)
    signals = {
        "workflow_consumes_role": signal_workflow_consumes_role(tree, workflow_texts),
        "real_account": signal_real_account(policy_text),
        "operational_history": signal_operational_history(repo_meta, contributors),
        "environment_plurality": signal_environment_plurality(tree),
    }
    passed = sum(signals.values())
    return {
        "excluded": bool(excl),
        "exclusion_reasons": excl,
        "signals": signals,
        "signals_passed": passed,
        "kept": (not excl) and passed >= threshold,
        "kept_strict": (not excl) and passed == 4,
    }
