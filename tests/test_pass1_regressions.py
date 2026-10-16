"""
Regression cases from the pass-1 labeling review (2026-10-11). Each case is a
trimmed reconstruction of a real file shape that the classifier got wrong, with
the rung the written codebook (rules 1-4) assigns. Run: python3 tests/test_pass1_regressions.py
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from classify import classify_file  # noqa: E402

ISS = "token.actions.githubusercontent.com"

CASES = [
    # --- Bug: non-literal sub read as "no sub" (S0). Rule 1 resolves from file. ---
    ("local_list_comprehension", ".tf", "S2", f'''
locals {{
  full_paths = [
    for repo in local.allowed_github_repositories : "repo:${{local.github_org_name}}/${{repo}}:*"
  ]
}}
data "aws_iam_policy_document" "assume" {{
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {{ type = "Federated" identifiers = ["arn:aws:iam::1:oidc-provider/{ISS}"] }}
    condition {{
      test     = "StringLike"
      variable = "{ISS}:sub"
      values   = local.full_paths
    }}
  }}
}}'''),
    ("local_in_list", ".tf", "S2", f'''
locals {{
  sub_pattern = "repo:${{local.github_owner}}/${{local.github_repo}}:*"
}}
data "aws_iam_policy_document" "a" {{
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {{
      test     = "StringLike"
      variable = "{ISS}:sub"
      values   = [local.sub_pattern]
    }}
  }}
}}'''),
    ("local_env_subject", ".tf", "S4", f'''
locals {{
  frontend_deploy_subject = "repo:${{var.github_owner}}/${{var.github_repo}}:environment:production"
}}
data "aws_iam_policy_document" "a" {{
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {{
      test     = "StringEquals"
      variable = "{ISS}:sub"
      values   = [local.frontend_deploy_subject]
    }}
  }}
}}'''),
    ("ternary_in_parens_jsonencode", ".tf", "S3", f'''
resource "aws_iam_role" "ci" {{
  assume_role_policy = jsonencode({{
    Statement = [{{
      Action = "sts:AssumeRoleWithWebIdentity"
      Principal = {{ Federated = "arn:aws:iam::1:oidc-provider/{ISS}" }}
      Condition = {{
        StringEquals = {{
          "{ISS}:sub" = (var.environment != null ?
            "repo:${{var.org}}/${{var.repo}}:environment:${{var.environment}}" :
          "repo:${{var.org}}/${{var.repo}}:ref:refs/heads/${{var.branch}}")
        }}
      }}
    }}]
  }})
}}'''),
    ("format_call", ".tf", "S2", f'''
resource "aws_iam_role" "r" {{
  assume_role_policy = jsonencode({{
    Statement = [{{
      Action = "sts:AssumeRoleWithWebIdentity",
      Principal = {{ Federated = format("arn:aws:iam::%s:oidc-provider/{ISS}", data.x.id) }}
      Condition = {{
        "StringLike" : {{
          "{ISS}:sub" : format("repo:%s:*", var.repo_name)
        }}
      }}
    }}]
  }})
}}'''),
    ("each_value_subject", ".tf", "S3", f'''
locals {{
  roles = {{
    prod = {{
      subject = "repo:${{var.github_org}}/${{var.repo}}:ref:refs/heads/main"
    }}
  }}
}}
resource "aws_iam_role" "r" {{
  for_each = local.roles
  assume_role_policy = jsonencode({{
    Statement = [{{
      Principal = {{ Federated = "arn:aws:iam::1:oidc-provider/{ISS}" }}
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {{
        StringLike   = {{ "{ISS}:sub" = each.value.subject }}
      }}
    }}]
  }})
}}'''),
    ("prefix_local_env", ".tf", "S4", f'''
locals {{
  subject_prefix = "repo:${{var.github_org}}@${{var.github_org_id}}/${{var.github_repo}}@${{var.github_repo_id}}"
}}
data "aws_iam_policy_document" "a" {{
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {{
      test     = "StringEquals"
      variable = "{ISS}:sub"
      values = [
        "${{local.subject_prefix}}:environment:plan",
        "${{local.subject_prefix}}:environment:production",
      ]
    }}
  }}
}}'''),
    ("operator_chosen_by_expression", ".tf", "S2", f'''
locals {{
  infra_subjects = {{ for mode in ["plan", "apply"] : mode => [
    for shape in local.repo_shapes : mode == "apply"
    ? "repo:${{shape}}:environment:${{local.deploy_environment}}"
    : "repo:${{shape}}:*"
  ] }}
}}
data "aws_iam_policy_document" "trust" {{
  for_each = toset(["plan", "apply"])
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {{
      test     = "StringEquals"
      variable = "{ISS}:aud"
      values   = ["sts.amazonaws.com"]
    }}
    condition {{
      test     = each.key == "apply" ? "StringEquals" : "StringLike"
      variable = "{ISS}:sub"
      values   = local.infra_subjects[each.key]
    }}
  }}
}}'''),
    ("bare_var_no_default", ".tf", "U1", f'''
variable "allowed_subjects" {{ type = list(string) }}
data "aws_iam_policy_document" "a" {{
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {{ test = "StringLike" variable = "{ISS}:sub" values = var.allowed_subjects }}
  }}
}}'''),
    ("cfn_json_fn_sub", ".json", "S4", '''
{"Resources": {"R": {"Type": "AWS::IAM::Role", "Properties": {
  "AssumeRolePolicyDocument": {"Statement": [{
    "Effect": "Allow",
    "Principal": {"Federated": {"Ref": "Provider"}},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {"StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": [
        {"Fn::Sub": "repo:${GitHubRepositoryIdentity}:environment:production"}
      ]}}}]}}}}}'''),
    ("cfn_yaml_if_lists", ".yaml", "S3", f'''
Conditions:
  IsShared: !Equals [!Ref Environment, shared]
Resources:
  Role:
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
                "{ISS}:sub": !If
                  - IsShared
                  - - !Sub "repo:${{GitHubOrg}}/${{GitHubRepo}}:environment:shared"
                    - !Sub "repo:${{GitHubOrg}}/${{GitHubRepo}}:ref:refs/heads/main"
                  - - !Sub "repo:${{GitHubOrg}}/${{GitHubRepo}}:environment:dev"
                    - !Sub "repo:${{GitHubOrg}}/${{GitHubRepo}}:pull_request"
'''),
    ("cfn_bare_param_no_default", ".yaml", "U1", f'''
Parameters:
  GitHubRepository:
    Type: String
Resources:
  Role:
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
                {ISS}:sub: !Sub ${{GitHubRepository}}
'''),
    ("cfn_bare_param_with_default", ".yaml", "S1", f'''
Parameters:
  GitHubRepository:
    Type: String
    Default: "repo:acme/*"
Resources:
  Role:
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
                {ISS}:sub: !Sub ${{GitHubRepository}}
'''),

    # --- Rule 2: '*' in the ref or environment -> S2 ---
    ("ref_wildcard_any_branch", ".json", "S2", f'''
{{"Statement": [{{"Effect": "Allow",
  "Principal": {{"Federated": "arn:aws:iam::1:oidc-provider/{ISS}"}},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {{"StringLike": {{"{ISS}:sub": [
    "repo:o/r:ref:refs/heads/*", "repo:o/r:pull_request"]}}}}}}]}}'''),
    ("env_prefix_wildcard", ".tf", "S2", f'''
data "aws_iam_policy_document" "a" {{
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {{
      test     = "StringLike"
      variable = "{ISS}:sub"
      values   = ["repo:o/r:environment:${{local.app}}-${{var.environment}}*"]
    }}
  }}
}}'''),
    ("literal_ref_and_env", ".json", "S3", f'''
{{"Statement": [{{"Effect": "Allow",
  "Principal": {{"Federated": "arn:aws:iam::1:oidc-provider/{ISS}"}},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {{"StringLike": {{"{ISS}:sub": [
    "repo:o/r:ref:refs/heads/main", "repo:o/r:environment:production"]}}}}}}]}}'''),

    # --- Rule 3: immutable-id wildcard does not widen; owner prefix wildcard is S0 ---
    ("id_wildcard_not_widening", ".json", "S3", f'''
{{"Statement": [{{"Effect": "Allow",
  "Principal": {{"Federated": "arn:aws:iam::1:oidc-provider/{ISS}"}},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {{"StringLike": {{"{ISS}:sub": [
    "repo:acme/infra@*:ref:refs/heads/main", "repo:acme/infra@*:environment:prod"]}}}}}}]}}'''),
    ("owner_prefix_wildcard", ".tf", "S0", f'''
data "aws_iam_policy_document" "a" {{
  statement {{
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {{
      test     = "StringLike"
      variable = "{ISS}:sub"
      values   = ["repo:${{local.github_owner}}*/${{local.github_repo_name}}*:*"]
    }}
  }}
}}'''),
    ("org_wildcard_with_env_is_still_S1", ".json", "S1", f'''
{{"Statement": [{{"Effect": "Allow",
  "Principal": {{"Federated": "arn:aws:iam::1:oidc-provider/{ISS}"}},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {{"StringLike": {{"{ISS}:sub": "repo:acme/*:environment:prod"}}}}}}]}}'''),

    # --- job_workflow_ref ---
    ("jwr_literal_pins_S4", ".json", "S4", f'''
{{"Statement": [{{"Effect": "Allow",
  "Principal": {{"Federated": "arn:aws:iam::1:oidc-provider/{ISS}"}},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {{"StringLike": {{
    "{ISS}:sub": "repo:o/r:*",
    "{ISS}:job_workflow_ref": "o/r/.github/workflows/deploy.yml@refs/heads/main"}}}}}}]}}'''),
    ("jwr_wildcard_ref_ignored", ".json", "S2", f'''
{{"Statement": [{{"Effect": "Allow",
  "Principal": {{"Federated": "arn:aws:iam::1:oidc-provider/{ISS}"}},
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {{"StringLike": {{
    "{ISS}:sub": "repo:o/r:ref:refs/heads/*",
    "{ISS}:job_workflow_ref": "o/r/.github/workflows/x.yml@refs/heads/*"}}}}}}]}}'''),

    # --- CDK principals without the literal action string ---
    ("cdk_openid_principal", ".ts", "S2", f'''
const provider = new iam.OpenIdConnectProvider(this, 'p', {{ url: 'https://{ISS}' }});
new iam.Role(this, 'r', {{
  assumedBy: new iam.OpenIdConnectPrincipal(provider).withConditions({{
    StringLike: {{
      '{ISS}:sub': `repo:${{organization}}/${{repository}}:*`,
    }},
  }}),
}});'''),

    # --- Salvage: sub built by code is U1, not S0 ---
    ("cdk_sub_from_function", ".ts", "U1", f'''
const repoRestriction = githubOidcSubjects({{ org, repo }});
new iam.Role(this, 'r', {{
  assumedBy: new iam.FederatedPrincipal(providerArn, {{
    StringLike: {{ "{ISS}:sub": repoRestriction }},
    StringEquals: {{ "{ISS}:aud": "sts.amazonaws.com" }},
  }}, "sts:AssumeRoleWithWebIdentity"),
}});'''),

    # --- Not policy definitions ---
    ("aws_service_reference_json", ".json", "U3", '''
{"Actions": [{"Name": "AssumeRoleWithWebIdentity",
  "ActionConditionKeys": ["token.actions.githubusercontent.com:aud", "accounts.google.com:sub"]}],
 "ConditionKeys": [{"Name": "token.actions.githubusercontent.com:sub"}]}'''),
    ("assertion_test_ts", ".ts", "U3", f'''
const githubSubject = `repo:${{substitution("Repo")}}:environment:${{substitution("Env")}}`;
assert(trust, "must exist");
assert.deepEqual(trust.Condition, {{
  StringEquals: {{ "{ISS}:aud": "sts.amazonaws.com",
                  "{ISS}:sub": {{ "Fn::Sub": githubSubject }} }} }});
assert.equal(trust.Action, "sts:AssumeRoleWithWebIdentity");'''),
]


def main():
    fails = 0
    with tempfile.TemporaryDirectory() as td:
        for name, suffix, want, text in CASES:
            f = Path(td) / f"{name}{suffix}"
            f.write_text(text)
            c = classify_file(f)
            ok = c.rung == want
            fails += not ok
            print(f"{'ok  ' if ok else 'FAIL'} {name:34} want={want:3} got={c.rung:3}  {c.reason[:60]}")
    print(f"\n{len(CASES) - fails}/{len(CASES)} pass-1 regression cases pass")
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
