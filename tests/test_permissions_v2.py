"""
Axis 2 regression cases from the pass-1 review (codebook v2: rule 5 scope-based
P1/P2, role scoping, CloudFormation YAML parsing, explicit cross-file links).
Run: python3 tests/test_permissions_v2.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from permissions import classify_permissions  # noqa: E402
from resolve_permissions import roles_for_trust_file  # noqa: E402
from permissions import resolve_role_breadth  # noqa: E402

ISS = "token.actions.githubusercontent.com"

TF_TRUST = f'''
data "aws_iam_policy_document" "gh" {{
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {{ type = "Federated" identifiers = ["arn:aws:iam::1:oidc-provider/{ISS}"] }}
    condition {{ test = "StringLike" variable = "{ISS}:sub" values = ["repo:o/r:*"] }}
  }}
}}
resource "aws_iam_role" "deploy" {{
  name               = "gha-deploy"
  assume_role_policy = data.aws_iam_policy_document.gh.json
}}
'''

CASES = [
    # Rule 5: S3 writes on a named bucket + invalidation on a named distribution = P1.
    ("static_site_deploy_multi_service", ".tf", "P1", TF_TRUST + '''
data "aws_iam_policy_document" "deploy" {
  statement {
    actions   = ["s3:PutObject", "s3:DeleteObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::site", "arn:aws:s3:::site/*"]
  }
  statement {
    actions   = ["cloudfront:CreateInvalidation"]
    resources = ["arn:aws:cloudfront::1:distribution/E123"]
  }
}
resource "aws_iam_role_policy" "deploy" {
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}'''),
    # ecr:GetAuthorizationToken only exists on "*": not a broad write.
    ("ecr_push_named_repo", ".tf", "P1", TF_TRUST + '''
resource "aws_iam_role_policy" "ecr" {
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecr:GetAuthorizationToken"], Resource = "*" },
      { Effect = "Allow", Action = ["ecr:PutImage", "ecr:UploadLayerPart"],
        Resource = aws_ecr_repository.app.arn }
    ]
  })
}'''),
    # Writes on every resource of a type = P2.
    ("lambda_update_all_functions", ".tf", "P2", TF_TRUST + '''
resource "aws_iam_role_policy" "l" {
  role = aws_iam_role.deploy.id
  policy = jsonencode({ Statement = [{ Effect = "Allow",
    Action = ["lambda:UpdateFunctionCode"], Resource = "arn:aws:lambda:*:1:function:*" }] })
}'''),
    # Role scoping: another role's s3:* and node policies must not count.
    ("other_roles_ignored", ".tf", "P0", TF_TRUST + '''
resource "aws_iam_role_policy" "gh_read" {
  role = aws_iam_role.deploy.id
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = ["eks:DescribeCluster"],
    Resource = aws_eks_cluster.main.arn }] })
}
resource "aws_iam_role" "task" {
  name = "ecs-task"
  assume_role_policy = jsonencode({ Statement = [{ Action = "sts:AssumeRole",
    Principal = { Service = "ecs-tasks.amazonaws.com" } }] })
}
resource "aws_iam_role_policy" "task" {
  role = aws_iam_role.task.id
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }] })
}
resource "aws_iam_role_policy_attachment" "node" {
  role       = aws_iam_role.task.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}'''),
    # EKS access entry: cluster-admin access policy on the GitHub role = P2.
    ("eks_cluster_admin_access", ".tf", "P2", TF_TRUST + '''
resource "aws_eks_access_policy_association" "gh" {
  cluster_name  = aws_eks_cluster.main.name
  principal_arn = aws_iam_role.deploy.arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
}'''),
    # GitHub trust role with no attached permissions in file -> PU2, even
    # though another role in the file has admin.
    ("gh_role_unattached_other_admin", ".tf", "PU2", TF_TRUST + '''
resource "aws_iam_role" "ops" { name = "ops" assume_role_policy = "{}" }
resource "aws_iam_role_policy_attachment" "ops" {
  role = aws_iam_role.ops.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}'''),

    # CloudFormation YAML with unquoted actions and block lists (pass-1 read these as PU2).
    ("cfn_yaml_unquoted_actions", ".yaml", "P2", f'''
Resources:
  DeployRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Federated: !Ref Provider
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringLike:
                {ISS}:sub: !Sub repo:${{GitHubRepository}}:*
      Policies:
        - PolicyName: deploy
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: ecr:GetAuthorizationToken
                Resource: "*"
              - Effect: Allow
                Action:
                  - apprunner:CreateService
                  - apprunner:UpdateService
                Resource: "*"
'''),
    # CloudFormation: only the GitHub role counts; a sibling role's admin is ignored.
    ("cfn_role_scoped", ".yaml", "P2", f'''
Resources:
  TaskRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {{ Service: ecs-tasks.amazonaws.com }}
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AdministratorAccess
  GitHubRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Federated: !Sub arn:aws:iam::${{AWS::AccountId}}:oidc-provider/{ISS}
            Action: sts:AssumeRoleWithWebIdentity
            Condition:
              StringLike:
                {ISS}:sub: repo:o/*
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryFullAccess
        - arn:aws:iam::aws:policy/AmazonS3FullAccess
'''),
    # CloudFormation: narrow named-resource policy on the GitHub role = P1.
    ("cfn_narrow_named", ".yml", "P1", f'''
Resources:
  Role:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {{ Federated: !Ref Provider }}
            Action: sts:AssumeRoleWithWebIdentity
            Condition: {{ StringEquals: {{ "{ISS}:sub": "repo:o/r:environment:prod" }} }}
      Policies:
        - PolicyName: site
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: [s3:GetObject, s3:PutObject, s3:DeleteObject]
                Resource: !Sub arn:${{AWS::Partition}}:s3:::${{SiteBucket}}/*
              - Effect: Allow
                Action: cloudfront:CreateInvalidation
                Resource: !Sub arn:${{AWS::Partition}}:cloudfront::${{AWS::AccountId}}:distribution/${{DistributionId}}
'''),
    # CDK: specific-resource statement + grantPullPush -> P1.
    ("cdk_specific", ".ts", "P1", f'''
const role = new iam.Role(this, 'r', {{
  assumedBy: new iam.OpenIdConnectPrincipal(provider).withConditions({{
    StringLike: {{ '{ISS}:sub': `repo:${{org}}/${{repo}}:*` }} }}),
}});
role.addToPolicy(new iam.PolicyStatement({{
  actions: ['s3:PutObject'],
  resources: [`${{bucket.bucketArn}}/*`],
}}));
repo.grantPullPush(role);'''),
    # Local references inside jsonencode and data-doc [0] indexes (real pass-1 shapes).
    ("jsonencode_local_and_index", ".tf", "P1", TF_TRUST + '''
locals {
  deploy_policy = {
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["s3:PutObject"], Resource = ["${var.bucket_arn}/*"] }]
  }
}
resource "aws_iam_role_policy" "p" {
  role   = aws_iam_role.deploy.name
  policy = jsonencode(local.deploy_policy)
}'''),
    ("concat_statements_and_bucket_policy", ".tf", "P1", '''
resource "aws_iam_policy" "deploy" {
  policy = jsonencode({
    Statement = concat([
      { Action = ["s3:PutObject"], Effect = "Allow", Resource = [format("%s/*", aws_s3_bucket.w.arn)] },
      { Action = ["cloudfront:CreateInvalidation"], Effect = "Allow", Resource = [aws_cloudfront_distribution.d.arn] },
    ])
  })
}
data "aws_iam_policy_document" "bucket_policy" {
  statement {
    actions   = ["s3:*"]
    resources = ["*"]
    principals { type = "AWS" identifiers = ["*"] }
  }
}'''),
    # Rule 7: assuming the CDK bootstrap roles is admin-equivalent.
    ("cdk_bootstrap_assume", ".ts", "P3", """
role.addToPolicy(new iam.PolicyStatement({
  actions: ['sts:AssumeRole'],
  resources: [`arn:aws:iam::${this.account}:role/cdk-*`],
}));"""),
    # ssm:SendCommand on every instance (CFN substitutions contain ':').
    ("sendcommand_all_instances", ".yaml", "P2", f'''
Resources:
  R:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal: {{ Federated: !Ref P }}
            Action: sts:AssumeRoleWithWebIdentity
            Condition: {{ StringLike: {{ "{ISS}:sub": "repo:o/*:*" }} }}
      Policies:
        - PolicyName: ssm
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: [ssm:SendCommand]
                Resource:
                  - !Sub arn:aws:ec2:${{AWS::Region}}:${{AWS::AccountId}}:instance/*
'''),
    ("count_indexed_policy_attachment", ".tf", "P2", TF_TRUST + '''
resource "aws_iam_policy" "gh" {
  count  = 1
  policy = jsonencode({ Statement = [{ Effect = "Allow",
    Action = ["cloudfront:UpdateDistribution"], Resource = "*" }] })
}
resource "aws_iam_role_policy_attachment" "gh" {
  count      = 1
  role       = aws_iam_role.deploy.name
  policy_arn = aws_iam_policy.gh[0].arn
}'''),
]


def main():
    fails = 0
    for name, suffix, want, text in CASES:
        got, ev = classify_permissions(text, suffix)
        ok = got == want
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {name:34} want={want:4} got={got:4}  {ev[:70]}")

    # Rule 6: cross-file linking only by explicit reference.
    trust_json = '{"Statement":[{"Action":"sts:AssumeRoleWithWebIdentity"}]}'
    unrelated_repo = TF_TRUST + '''
resource "aws_iam_role_policy_attachment" "a" {
  role = aws_iam_role.deploy.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}'''
    r1 = roles_for_trust_file(trust_json, "infra/iam/site-trust.json", unrelated_repo)
    ok1 = r1 == []
    fails += not ok1
    print(f"{'ok  ' if ok1 else 'FAIL'} {'standalone trust json not linked':34} got roles={r1}")

    linked_repo = '''
resource "aws_iam_role" "site" {
  name = "site-deploy"
  assume_role_policy = file("${path.module}/site-trust.json")
}
resource "aws_iam_role_policy_attachment" "a" {
  role = aws_iam_role.site.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}''' + unrelated_repo
    r2 = roles_for_trust_file(trust_json, "infra/iam/site-trust.json", linked_repo)
    b2, _ = resolve_role_breadth(linked_repo, *r2[0]) if r2 else (None, [])
    ok2 = r2 == [("site", "site-deploy")] and b2 == "P2"
    fails += not ok2
    print(f"{'ok  ' if ok2 else 'FAIL'} {'trust json linked via file()':34} got roles={r2} breadth={b2}")

    n = len(CASES) + 2
    print(f"\n{n - fails}/{n} permission v2 checks pass")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
