"""
Adversarial regression tests -- edge cases found while auditing the classifier.
Each encodes a defect that was found and fixed, or a behavior that must hold.
Run: python3 tests/test_adversarial.py
"""
import sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from classify import classify_file

def _code(txt, suffix):
    d = tempfile.mkdtemp()
    p = Path(d) / ("x" + suffix)
    p.write_text(txt)
    return classify_file(p).rung

ISS = "token.actions.githubusercontent.com"
ARN = f"arn:aws:iam::1:oidc-provider/{ISS}"

CASES = [
    # (name, expected_rung, suffix, text)

    # Comment pollution on the SALVAGE path: a looser example in a // or /* */
    # comment must NOT beat the real rule. (Was a defect: comment won -> S1.)
    ("ts_line_comment_pollution", "S4", ".ts", f'''
// do NOT use repo:acme/*
const c = [
  {{ test: "StringEquals", variable: `${{iss}}:aud`, values: ["sts.amazonaws.com"] }},
  {{ test: "StringEquals", variable: `${{iss}}:sub`, values: [`repo:acme/app:environment:prod`] }},
];
new aws.iam.Role("r", {{ assumeRolePolicy: doc({{ statements:[{{ actions:["sts:AssumeRoleWithWebIdentity"],
  principals:[{{type:"Federated", identifiers:["{ARN}"]}}], conditions: c }}] }}).json }});'''),

    ("ts_block_comment_pollution", "S4", ".ts", f'''
/* legacy: repo:acme/* removed */
const c = [
  {{ test: "StringEquals", variable: `${{iss}}:sub`, values: [`repo:acme/app:environment:prod`] }},
];
new aws.iam.Role("r", {{ assumeRolePolicy: doc({{ statements:[{{ actions:["sts:AssumeRoleWithWebIdentity"],
  principals:[{{type:"Federated", identifiers:["{ARN}"]}}], conditions: c }}] }}).json }});'''),

    # A file that mentions the issuer ONLY in a comment is not a trust policy -> U3.
    ("issuer_only_in_comment", "U3", ".ts", f'''
// role trust must allow sts:AssumeRoleWithWebIdentity for {ISS}
export const region = "us-east-1";'''),

    # Structural path isolates the jsonencode body: an outside comment is invisible.
    ("structural_ignores_outside_comment", "S3", ".tf", f'''
# old: "{ISS}:sub" = "repo:acme/*"
resource "aws_iam_role" "r" {{
  assume_role_policy = jsonencode({{ Statement = [{{
    Action = "sts:AssumeRoleWithWebIdentity"
    Principal = {{ Federated = "{ARN}" }}
    Condition = {{ StringEquals = {{ "{ISS}:sub" = "repo:acme/app:ref:refs/heads/main" }} }}
  }}] }})
}}'''),

    # Multiple subs in one condition list -> coded by the loosest (union).
    ("multi_sub_loosest", "S2", ".tf", f'''
data "aws_iam_policy_document" "d" {{
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {{ type = "Federated" identifiers = ["{ARN}"] }}
    condition {{ test = "StringLike" variable = "{ISS}:sub"
      values = ["repo:acme/app:ref:refs/heads/main", "repo:acme/app:*"] }}
  }}
}}'''),

    # Non-GitHub web-identity (EKS) must stay U3.
    ("eks_not_github", "U3", ".tf", '''
resource "aws_iam_role" "irsa" {
  assume_role_policy = jsonencode({ Statement = [{
    Action = "sts:AssumeRoleWithWebIdentity"
    Principal = { Federated = "arn:aws:iam::1:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/X" }
    Condition = { StringEquals = { "oidc.eks.us-east-1.amazonaws.com/id/X:sub" = "system:serviceaccount:default:sa" } }
  }] })
}'''),

    # Genuinely open: web-identity, github principal, aud only, no sub -> S0.
    ("real_s0_aud_only", "S0", ".tf", f'''
resource "aws_iam_role" "r" {{
  assume_role_policy = jsonencode({{ Statement = [{{
    Action = "sts:AssumeRoleWithWebIdentity"
    Principal = {{ Federated = "{ARN}" }}
    Condition = {{ StringEquals = {{ "{ISS}:aud" = "sts.amazonaws.com" }} }}
  }}] }})
}}'''),
]

def _code_bytes(raw, suffix):
    d = tempfile.mkdtemp()
    p = Path(d) / ("x" + suffix)
    p.write_bytes(raw)
    return classify_file(p).rung

# Byte-level cases: encoding and CloudFormation intrinsics that once crashed.
BYTE_CASES = [
    # UTF-8 BOM prefix must not break JSON parsing (valid policy, was dropped).
    ("bom_prefixed_json", "S3", ".json", ('\ufeff' + (
        '{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity",'
        f'"Principal":{{"Federated":"{ARN}"}},'
        f'"Condition":{{"StringEquals":{{"{ISS}:sub":"repo:acme/app:ref:refs/heads/main",'
        f'"{ISS}:aud":"sts.amazonaws.com"}}}}}}]}}')).encode("utf-8")),

    # CloudFormation !GetAtt in Federated rendered as a value (once a TypeError).
    ("cfn_getatt_principal", "S2", ".yaml", (
        "Resources:\n  R:\n    Type: AWS::IAM::Role\n    Properties:\n"
        "      AssumeRolePolicyDocument:\n        Statement:\n"
        "          - Effect: Allow\n            Action: sts:AssumeRoleWithWebIdentity\n"
        "            Principal:\n              Federated: !GetAtt P.Arn\n"
        "            Condition:\n              StringLike:\n"
        f"                {ISS}:sub: repo:acme/app:*\n"
        "              StringEquals:\n"
        f"                {ISS}:aud: sts.amazonaws.com\n").encode("utf-8")),

    # Federated as a LIST containing an intrinsic dict must not crash join.
    ("cfn_list_intrinsic", "S4", ".yaml", (
        "Resources:\n  R:\n    Type: AWS::IAM::Role\n    Properties:\n"
        "      AssumeRolePolicyDocument:\n        Statement:\n"
        "          - Effect: Allow\n            Action: sts:AssumeRoleWithWebIdentity\n"
        "            Principal:\n              Federated:\n"
        f"                - !Sub arn:aws:iam::${{AWS::AccountId}}:oidc-provider/{ISS}\n"
        "            Condition:\n              StringEquals:\n"
        f"                {ISS}:sub: repo:acme/app:environment:prod\n").encode("utf-8")),
]

fails = 0
for name, want, suffix, txt in CASES:
    got = _code(txt, suffix)
    ok = got == want
    if not ok:
        fails += 1
    print(f"{'ok  ' if ok else 'FAIL'} {name:34} want={want:3} got={got}")

for name, want, suffix, raw in BYTE_CASES:
    got = _code_bytes(raw, suffix)
    ok = got == want
    if not ok:
        fails += 1
    print(f"{'ok  ' if ok else 'FAIL'} {name:34} want={want:3} got={got}")

total = len(CASES) + len(BYTE_CASES)
print(f"\n{total - fails}/{total} adversarial cases pass")
sys.exit(1 if fails else 0)
