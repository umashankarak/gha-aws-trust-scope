#!/usr/bin/env bash
# Pre-test: checks that your machine is ready. Creates nothing, changes nothing.
#   ./pretest.sh <github-owner> <repo-name>
set -u
OWNER="${1:-}"; REPO="${2:-}"
ok=0; bad=0
pass(){ echo "  [ OK ] $1"; ok=$((ok+1)); }
fail(){ echo "  [FAIL] $1"; bad=$((bad+1)); }

echo "Pre-test for the OIDC branch demo"
[ -n "$OWNER" ] && [ -n "$REPO" ] && pass "repo given: $OWNER/$REPO" || fail "usage: ./pretest.sh <github-owner> <repo-name>"

command -v aws >/dev/null && pass "aws CLI: $(aws --version 2>&1 | cut -d' ' -f1)" || fail "aws CLI not found"
command -v python3 >/dev/null && pass "python3 found" || fail "python3 not found"
command -v git >/dev/null && pass "git found" || fail "git not found"

ID=$(aws sts get-caller-identity --query Arn --output text 2>/dev/null)
if [ -n "$ID" ]; then pass "AWS login works as: $ID"; else fail "aws sts get-caller-identity failed (check 'aws configure')"; fi
ACCT=$(aws sts get-caller-identity --query Account --output text 2>/dev/null)

aws iam list-roles --max-items 1 >/dev/null 2>&1 && pass "can read IAM (needed to create the two test roles)" \
  || fail "cannot read IAM; you need IAM permissions (iam:CreateRole etc.) in this account"

for r in oidc-demo-any-branch oidc-demo-main-only; do
  if aws iam get-role --role-name "$r" >/dev/null 2>&1; then fail "role $r already exists (run ./teardown.sh first)"; else pass "role name $r is free"; fi
done

if [ -n "$ACCT" ] && aws iam get-open-id-connect-provider \
     --open-id-connect-provider-arn "arn:aws:iam::$ACCT:oidc-provider/token.actions.githubusercontent.com" >/dev/null 2>&1; then
  pass "GitHub OIDC provider already exists in this account (setup will reuse it and teardown will keep it)"
else
  pass "no GitHub OIDC provider yet (setup will create it and teardown will remove it)"
fi

if aws cloudtrail lookup-events --region us-east-1 --max-results 1 >/dev/null 2>&1; then
  pass "CloudTrail event history readable in us-east-1 (used for evidence)"
else
  fail "cannot read CloudTrail event history (cloudtrail:LookupEvents); evidence step will not work"
fi

echo
echo "$ok checks passed, $bad failed."
[ "$bad" -eq 0 ] && echo "Ready. Next: ./setup.sh $OWNER $REPO" || echo "Fix the FAIL lines, then run this again."
