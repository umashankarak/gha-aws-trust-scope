#!/usr/bin/env bash
# Creates two test roles in YOUR account, trusted only by YOUR repo, with NO permissions.
#   ./setup.sh <github-owner> <repo-name>
# Writes .github/workflows/oidc-demo.yml (with the role ARNs filled in) into the current directory.
set -euo pipefail
OWNER="$1"; REPO="$2"
ISS="token.actions.githubusercontent.com"
ACCT=$(aws sts get-caller-identity --query Account --output text)
PROVIDER="arn:aws:iam::$ACCT:oidc-provider/$ISS"
HERE="$(cd "$(dirname "$0")" && pwd)"

if aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$PROVIDER" >/dev/null 2>&1; then
  echo "Reusing the existing GitHub OIDC provider."
  echo "existing" > "$HERE/.provider-state"
else
  echo "Creating the GitHub OIDC provider."
  # AWS no longer relies on this thumbprint for GitHub; older CLI versions still require one.
  aws iam create-open-id-connect-provider --url "https://$ISS" \
    --client-id-list sts.amazonaws.com \
    --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1 >/dev/null
  echo "created" > "$HERE/.provider-state"
fi

trust() {  # $1 = operator for sub, $2 = sub value
  # Built with Python so the aud and sub conditions merge under one operator key
  # when both are StringEquals (duplicate JSON keys would silently drop one).
  python3 - "$PROVIDER" "$ISS" "$1" "$2" <<'EOF'
import json, sys
provider, iss, op, sub = sys.argv[1:5]
cond = {"StringEquals": {f"{iss}:aud": "sts.amazonaws.com"}}
cond.setdefault(op, {})[f"{iss}:sub"] = sub
print(json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Principal": {"Federated": provider},
    "Action": "sts:AssumeRoleWithWebIdentity", "Condition": cond}]}))
EOF
}

# Role A: the pattern the paper measures as S2 (repo pinned, any branch).
aws iam create-role --role-name oidc-demo-any-branch --max-session-duration 3600 \
  --description "Paper 10 demo: S2 trust, no permissions" \
  --assume-role-policy-document "$(trust StringLike "repo:$OWNER/$REPO:*")" >/dev/null
# Role B: S3 (repo and main branch pinned).
aws iam create-role --role-name oidc-demo-main-only --max-session-duration 3600 \
  --description "Paper 10 demo: S3 trust, no permissions" \
  --assume-role-policy-document "$(trust StringEquals "repo:$OWNER/$REPO:ref:refs/heads/main")" >/dev/null
# Neither role gets any permission policy: assuming it is the whole test.

ARN_A="arn:aws:iam::$ACCT:role/oidc-demo-any-branch"
ARN_B="arn:aws:iam::$ACCT:role/oidc-demo-main-only"
mkdir -p .github/workflows
sed -e "s#__ROLE_ANY_BRANCH__#$ARN_A#" -e "s#__ROLE_MAIN_ONLY__#$ARN_B#" \
  "$HERE/template/oidc-demo.yml" > .github/workflows/oidc-demo.yml

echo
echo "Created:"
echo "  $ARN_A   (trusts repo:$OWNER/$REPO:*)"
echo "  $ARN_B   (trusts repo:$OWNER/$REPO:ref:refs/heads/main only)"
echo "Wrote .github/workflows/oidc-demo.yml"
echo "Next: commit and push to main (see README step 4)."
