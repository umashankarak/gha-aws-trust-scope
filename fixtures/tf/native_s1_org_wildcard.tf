resource "aws_iam_role" "gha" {
  assume_role_policy = data.aws_iam_policy_document.oidc.json
}
data "aws_iam_policy_document" "oidc" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    effect  = "Allow"
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::210987654321:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:acme-corp/*"]
    }
  }
}
