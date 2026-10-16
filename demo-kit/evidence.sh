#!/usr/bin/env bash
# Pulls the AssumeRoleWithWebIdentity events for the two demo roles from
# CloudTrail event history (free, last 90 days). Wait ~15 minutes after the runs.
#   ./evidence.sh
set -euo pipefail
mkdir -p evidence
START=$(python3 -c 'import datetime as d; print((d.datetime.now(d.timezone.utc)-d.timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ"))')
aws cloudtrail lookup-events --region us-east-1 --start-time "$START" \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRoleWithWebIdentity \
  --output json > evidence/cloudtrail-raw.json

python3 - <<'EOF'
import json
raw = json.load(open("evidence/cloudtrail-raw.json"))
rows = []
for e in raw.get("Events", []):
    ev = json.loads(e["CloudTrailEvent"])
    role = (ev.get("requestParameters") or {}).get("roleArn", "")
    if "oidc-demo-" not in role:
        continue
    ui = ev.get("userIdentity") or {}
    rows.append({
        "time": ev.get("eventTime"),
        "role": role.rsplit("/", 1)[-1],
        "subject": ui.get("userName") or ui.get("principalId", ""),
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
