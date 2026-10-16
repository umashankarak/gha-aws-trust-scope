resource "aws_iam_openid_connect_provider" "github_oidc" {
  client_id_list  = ["sts.amazonaws.com"]
  url             = "https://token.actions.githubusercontent.com"
}
resource "aws_iam_role" "github_oidc_role" {
  name               = "GithubActions-WebIdentity-Role"
  assume_role_policy = data.aws_iam_policy_document.oidc_role.json
}
