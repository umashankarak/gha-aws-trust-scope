resource "aws_iam_role" "deploy" {
  assume_role_policy = jsonencode({
    Statement = [{
      Effect = "Allow"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:acme-corp/payments-api:ref:refs/heads/main",
            "repo:acme-corp/payments-api:environment:production",
            "repo:acme-corp/payments-api:*"
          ]
        }
      }
    }]
  })
}
