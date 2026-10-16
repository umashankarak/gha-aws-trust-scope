#!/usr/bin/env bash
# Deletes the two demo roles. Deletes the GitHub OIDC provider only if setup.sh created it.
#   ./teardown.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
for r in oidc-demo-any-branch oidc-demo-main-only; do
  aws iam delete-role --role-name "$r" 2>/dev/null && echo "deleted role $r" || echo "role $r not found"
done
if [ "$(cat "$HERE/.provider-state" 2>/dev/null)" = "created" ]; then
  ACCT=$(aws sts get-caller-identity --query Account --output text)
  aws iam delete-open-id-connect-provider \
    --open-id-connect-provider-arn "arn:aws:iam::$ACCT:oidc-provider/token.actions.githubusercontent.com" \
    && echo "deleted the GitHub OIDC provider (setup.sh had created it)"
  rm -f "$HERE/.provider-state"
else
  echo "kept the GitHub OIDC provider (it existed before setup.sh)"
fi
