"""
Axis 2 (permission breadth) tests. Run: python3 tests/test_permissions.py
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from permissions import classify_permissions, grade_actions, grade_managed

# grade_managed unit checks
MANAGED = [
    ("AdministratorAccess", "P3"),
    ("PowerUserAccess", "P3"),
    ("IAMFullAccess", "P3"),
    ("AmazonS3FullAccess", "P2"),
    ("AmazonEC2FullAccess", "P2"),
    ("ReadOnlyAccess", "P2"),
    ("AmazonS3ReadOnlyAccess", "P0"),
    # Service-scoped PowerUser is broad within ONE service, not account-wide.
    ("AmazonEC2ContainerRegistryPowerUser", "P2"),
    ("AWSCodeCommitPowerUser", "P2"),
]

# grade_actions unit checks: (actions, resources, expected)
ACTIONS = [
    (["*"], ["*"], "P3"),
    (["iam:PassRole"], ["*"], "P3"),
    (["iam:CreatePolicyVersion"], ["*"], "P3"),
    (["s3:*"], ["arn:aws:s3:::b/*"], "P2"),
    (["s3:GetObject", "ec2:StartInstances"], ["*"], "P2"),  # multi-service
    (["s3:PutObject"], ["*"], "P2"),                        # write on '*'
    (["s3:PutObject"], ["arn:aws:s3:::b/*"], "P1"),         # single-service write
    (["s3:GetObject"], ["arn:aws:s3:::b/*"], "P0"),         # single-service read
    (["sts:AssumeRoleWithWebIdentity"], ["*"], None),       # trust action -> ignored
]

# File-level checks: (name, expected_breadth, text)
ISS = "token.actions.githubusercontent.com"
FILES = [
    # Real observeinc shape: S2 trust + AdministratorAccess attachment -> P3.
    ("observeinc_admin", "P3", f'''
data "aws_iam_policy_document" "t" {{
  statement {{ actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {{ type="Federated" identifiers=["arn:aws:iam::1:oidc-provider/{ISS}"] }}
    condition {{ test="StringLike" variable="{ISS}:sub" values=["repo:o/r:*"] }} }}
}}
resource "aws_iam_role_policy_attachment" "a" {{
  role = aws_iam_role.ci.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}}'''),

    # Inline least-privilege: one service read -> P0.
    ("inline_readonly", "P0", f'''
resource "aws_iam_role_policy" "p" {{
  role = aws_iam_role.ci.id
  policy = jsonencode({{ Statement = [{{ Effect="Allow"
    Action=["s3:GetObject"], Resource="arn:aws:s3:::b/*" }}] }})
}}
# trust elsewhere: {ISS}'''),

    # Inline wildcard service -> P2.
    ("inline_s3_star", "P2", '''
resource "aws_iam_role_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect="Allow", Action="s3:*", Resource="*" }] })
}'''),

    # Trust policy only, no permissions in file -> PU2.
    ("trust_only", "PU2", f'''
resource "aws_iam_role" "r" {{
  assume_role_policy = jsonencode({{ Statement=[{{ Action="sts:AssumeRoleWithWebIdentity"
    Principal={{Federated="arn:aws:iam::1:oidc-provider/{ISS}"}}
    Condition={{StringEquals={{"{ISS}:aud"="sts.amazonaws.com"}}}} }}] }})
}}'''),

    # CloudFormation managed policy list -> P2 (service full access).
    ("cfn_managed", "P2", '''
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonS3FullAccess
'''),

    # Custom-policy ARN only, document not in file -> PU2.
    ("custom_arn_only", "PU2", '''
resource "aws_iam_role_policy_attachment" "a" {
  policy_arn = "arn:aws:iam::123456789012:policy/my-custom-policy"
}'''),
]

fails = 0
for name, want in MANAGED:
    got = grade_managed(name)
    if got != want:
        fails += 1; print(f"FAIL managed {name}: want {want} got {got}")
for acts, res, want in ACTIONS:
    got = grade_actions(acts, res)
    if got != want:
        fails += 1; print(f"FAIL actions {acts}: want {want} got {got}")
for name, want, text in FILES:
    got, ev = classify_permissions(text)
    ok = got == want
    if not ok: fails += 1
    print(f"{'ok  ' if ok else 'FAIL'} {name:22} want={want:4} got={got:4}  {ev[:50]}")

n = len(MANAGED) + len(ACTIONS) + len(FILES)
print(f"\n{n - fails}/{n} permission checks pass")
sys.exit(1 if fails else 0)
