#!/usr/bin/env bash
# Pulls the AssumeRoleWithWebIdentity events for the demo from CloudTrail event history
# (free, last 90 days). Run from the test repository folder about 15 minutes after the runs.
#   /path/to/demo-kit/evidence.sh
# Refused events do not record the target role, so attempts are matched by the token subject,
# which contains the repository name.
set -euo pipefail
REPO=$(basename -s .git "$(git remote get-url origin)")
mkdir -p evidence
START=$(python3 -c 'import datetime as d; print((d.datetime.now(d.timezone.utc)-d.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"))')
aws cloudtrail lookup-events --region us-east-1 --start-time "$START" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity \
  --output json > evidence/cloudtrail-raw.json

REPO="$REPO" python3 - <<'EOF'
import json, os
repo = os.environ["REPO"]
raw = json.load(open("evidence/cloudtrail-raw.json"))
rows = []
for e in raw.get("Events", []):
    ev = json.loads(e["CloudTrailEvent"])
    role = (ev.get("requestParameters") or {}).get("roleArn", "")
    ui = ev.get("userIdentity") or {}
    subject = ui.get("userName") or ui.get("principalId", "")
    if "oidc-demo-" not in role and f"/{repo}" not in subject:
        continue
    rows.append({
        "time": ev.get("eventTime"),
        "role": role.rsplit("/", 1)[-1] if role else "(not recorded)",
        "subject": subject,
        "result": "DENIED (" + ev["errorCode"] + ")" if ev.get("errorCode") else "ALLOWED",
        "eventID": ev.get("eventID"),
    })
rows.sort(key=lambda r: r["time"])
json.dump(rows, open("evidence/cloudtrail-summary.json", "w"), indent=2)
print(f"{'time':<22}{'role':<24}{'result':<28}subject")
for r in rows:
    print(f"{r['time']:<22}{r['role']:<24}{r['result']:<28}{r['subject']}")
print(f"\n{len(rows)} demo events. Saved evidence/cloudtrail-raw.json and evidence/cloudtrail-summary.json")
if not rows:
    print("No events yet: CloudTrail can take up to 15 minutes. Run this again later.")
EOF
