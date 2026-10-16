variable "github_org"  { type = string }
variable "repo_name"   { type = string }

resource "aws_iam_role" "deploy" {
  assume_role_policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:${var.github_org}/${var.repo_name}:ref:refs/heads/main"
        }
      }
    }]
  })
}
