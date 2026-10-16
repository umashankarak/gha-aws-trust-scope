import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from resolve_permissions import github_roles, resolve_role_breadth

ISS = "token.actions.githubusercontent.com"

# Repo where the GitHub role's permissions live in a SEPARATE file, and an
# UNRELATED admin role also exists. The github role must resolve to P1 (its own
# narrow policy), NOT P3 (the sibling's admin) -- the anti-pollution check.
trust_file = f'''
data "aws_iam_policy_document" "gh" {{
  statement {{ actions=["sts:AssumeRoleWithWebIdentity"]
    principals {{ type="Federated" identifiers=["arn:aws:iam::1:oidc-provider/{ISS}"] }}
    condition {{ test="StringLike" variable="{ISS}:sub" values=["repo:o/r:*"] }} }}
}}
resource "aws_iam_role" "ci" {{
  name = "gha-ci"
  assume_role_policy = data.aws_iam_policy_document.gh.json
}}
'''
perms_file = '''
resource "aws_iam_role_policy_attachment" "ci_attach" {
  role       = aws_iam_role.ci.name
  policy_arn = aws_iam_policy.ci_narrow.arn
}
resource "aws_iam_policy" "ci_narrow" {
  policy = jsonencode({ Statement = [{ Effect="Allow", Action="s3:PutObject", Resource="arn:aws:s3:::b/*" }] })
}
# an UNRELATED admin role in the same repo -- must NOT leak into ci's grade
resource "aws_iam_role" "ops_admin" { name = "ops" }
resource "aws_iam_role_policy_attachment" "ops_attach" {
  role       = aws_iam_role.ops_admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
'''

# 1. github role identified in the trust file
roles = github_roles(trust_file)
print("github_roles:", roles, "(want [('ci','gha-ci')])")
assert roles == [("ci", "gha-ci")], "role identification failed"

# 2. resolve across concatenated repo text -> must be P1 (s3:PutObject), not P3
repo_text = trust_file + perms_file
b, ev = resolve_role_breadth(repo_text, "ci", "gha-ci")
print("ci breadth:", b, ev, "(want P1, NOT P3)")
assert b == "P1", f"anti-pollution FAILED: got {b} (admin leaked from sibling)"

# 3. managed ARN attached directly to the github role -> P3
direct = trust_file + '''
resource "aws_iam_role_policy_attachment" "a" {
  role = aws_iam_role.ci.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
'''
b2, ev2 = resolve_role_breadth(direct, "ci", "gha-ci")
print("ci direct-admin:", b2, ev2, "(want P3)")
assert b2 == "P3"

# 4. role referenced by literal name string (not resource ref)
byname = trust_file + '''
resource "aws_iam_role_policy_attachment" "a" {
  role = "gha-ci"
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}
'''
b3, ev3 = resolve_role_breadth(byname, "ci", "gha-ci")
print("ci by-name:", b3, ev3, "(want P2)")
assert b3 == "P2"

print("\nall resolver linking tests pass")
