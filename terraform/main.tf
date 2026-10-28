data "aws_caller_identity" "current" {}

locals {
  oidc_host = "token.actions.githubusercontent.com"

  # The token's `sub` claim for a workflow running on the deploy branch.
  deploy_sub = "repo:${var.github_repo}:ref:refs/heads/${var.deploy_branch}"

  oidc_provider_arn = (
    var.create_oidc_provider
    ? aws_iam_openid_connect_provider.github[0].arn
    : data.aws_iam_openid_connect_provider.github[0].arn
  )
}

# Registers GitHub as an identity provider AWS will accept tokens from.
# No thumbprint_list: AWS validates GitHub's certificate against its own
# trusted CA library, so there is nothing to keep up to date.
resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1

  url = "https://${local.oidc_host}"
}
