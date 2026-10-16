data "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"
}
locals {
  oidc_claim_prefix = trimprefix(data.aws_iam_openid_connect_provider.github_actions.url, "https://")
  organization = "observeinc"
  repository   = "terraform-aws-collection"
}
data "aws_iam_policy_document" "github_actions_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github_actions.arn]
    }
    condition {
      test     = "StringLike"
      variable = "${local.oidc_claim_prefix}:sub"
      values   = ["repo:${local.organization}/${local.repository}:*"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.oidc_claim_prefix}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}
