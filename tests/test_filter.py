import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from deployedness import evaluate

REAL_POLICY = 'Federated = "arn:aws:iam::210987654321:oidc-provider/token.actions.githubusercontent.com"'
DEMO_POLICY = 'Federated = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"'
GOOD_WF = {".github/workflows/deploy.yml": "permissions:\n  id-token: write\nsteps:\n  - uses: aws-actions/configure-aws-credentials@v4"}

cases = [
    ("production repo", dict(
        repo_meta={"full_name":"acme/payments-api","description":"Payments service","created_at":"2023-01-05T00:00:00Z","pushed_at":"2026-09-01T00:00:00Z","fork":False,"is_template":False,"archived":False,"topics":[]},
        tree=[".github/workflows/deploy.yml","infra/prod/main.tf","infra/staging/main.tf"],
        workflow_texts=GOOD_WF, policy_text=REAL_POLICY, contributors=7, readme="# payments-api\nInternal service."),
     dict(kept=True, excluded=False)),

    ("tutorial by name", dict(
        repo_meta={"full_name":"someone/aws-oidc-tutorial","description":"Learn OIDC","created_at":"2025-01-01T00:00:00Z","pushed_at":"2026-01-01T00:00:00Z","fork":False,"is_template":False,"archived":False,"topics":[]},
        tree=[".github/workflows/deploy.yml","main.tf"], workflow_texts=GOOD_WF,
        policy_text=REAL_POLICY, contributors=3, readme="# Tutorial"),
     dict(kept=False, excluded=True)),

    ("placeholder account, 1 author", dict(
        repo_meta={"full_name":"someone/infra","description":"my infra","created_at":"2026-08-01T00:00:00Z","pushed_at":"2026-08-03T00:00:00Z","fork":False,"is_template":False,"archived":False,"topics":[]},
        tree=["main.tf"], workflow_texts={}, policy_text=DEMO_POLICY, contributors=1, readme=None),
     dict(kept=False, excluded=False)),

    ("fork", dict(
        repo_meta={"full_name":"someone/payments-api","description":"svc","created_at":"2023-01-01T00:00:00Z","pushed_at":"2026-01-01T00:00:00Z","fork":True,"is_template":False,"archived":False,"topics":[]},
        tree=[".github/workflows/deploy.yml","prod/a.tf","dev/b.tf"], workflow_texts=GOOD_WF,
        policy_text=REAL_POLICY, contributors=9, readme=None),
     dict(kept=False, excluded=True)),

    ("popular tutorial (stars would have kept it)", dict(
        repo_meta={"full_name":"famous/getting-started-oidc","description":"A worked example","created_at":"2022-01-01T00:00:00Z","pushed_at":"2026-06-01T00:00:00Z","fork":False,"is_template":False,"archived":False,"topics":["example"]},
        tree=[".github/workflows/deploy.yml","prod/a.tf","dev/b.tf"], workflow_texts=GOOD_WF,
        policy_text=REAL_POLICY, contributors=40, readme="# Prerequisites\nStep 1: create a role"),
     dict(kept=False, excluded=True)),
]

fails = 0
for name, kw, exp in cases:
    got = evaluate(**kw)
    bad = [k for k, v in exp.items() if got[k] != v]
    if bad: fails += 1
    print(f"{'ok  ' if not bad else 'FAIL'} {name:<44} kept={got['kept']} excl={got['exclusion_reasons'] or '-'} signals={got['signals_passed']}/4")

print(f"\n{len(cases)-fails}/{len(cases)} filter cases pass")
sys.exit(1 if fails else 0)
