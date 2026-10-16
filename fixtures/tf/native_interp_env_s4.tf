locals {
  github_oidc_host = "token.actions.githubusercontent.com"
}
data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github_actions.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "${local.github_oidc_host}:sub"
      values   = ["repo:${var.github_repository}:environment:${var.github_environment}"]
    }
  }
}
