#!/usr/bin/env bash
# Re-point the two demo roles at the subject format GitHub actually issues for
# this repository. Copy the prefix (everything before ":ref:") from the
# "token sub" column of a run summary.
#   ./use-immutable-subject.sh 'repo:OWNER@OWNERID/REPO@REPOID'
set -euo pipefail
SUBP="$1"
case "$SUBP" in repo:*@*/*@*) ;; *) echo "expected repo:OWNER@ID/REPO@ID, got: $SUBP" >&2; exit 1;; esac
ACCT=$(aws sts get-caller-identity --query Account --output text)

policy() {  # $1 operator for sub, $2 sub value
  python3 - "$ACCT" "$1" "$2" <<'EOF'
import json, sys
acct, op, sub = sys.argv[1:4]
iss = "token.actions.githubusercontent.com"
cond = {"StringEquals": {f"{iss}:aud": "sts.amazonaws.com"}}
cond.setdefault(op, {})[f"{iss}:sub"] = sub
print(json.dumps({"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": f"arn:aws:iam::{acct}:oidc-provider/{iss}"},
    "Action": "sts:AssumeRoleWithWebIdentity", "Condition": cond}]}))
EOF
}

aws iam update-assume-role-policy --role-name oidc-demo-any-branch \
  --policy-document "$(policy StringLike "$SUBP:*")"
aws iam update-assume-role-policy --role-name oidc-demo-main-only \
  --policy-document "$(policy StringEquals "$SUBP:ref:refs/heads/main")"
echo "Role A now trusts: $SUBP:*"
echo "Role B now trusts: $SUBP:ref:refs/heads/main"
