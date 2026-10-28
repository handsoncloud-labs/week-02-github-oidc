# The trust policy is the whole security model. Both conditions use
# StringEquals: no wildcards. Leave the `sub` condition out and any repository
# on GitHub that can reach this role's ARN would pass, because the audience
# ("sts.amazonaws.com") is the same for everyone.
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = [local.deploy_sub]
    }
  }
}

resource "aws_iam_role" "deploy" {
  name                 = "${var.name_prefix}-deploy"
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = var.session_seconds
}

# What the job may do once it is in: write objects under site/ in one bucket.
data "aws_iam_policy_document" "deploy" {
  statement {
    sid       = "PutSiteObjects"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.site.arn}/site/*"]
  }
}

resource "aws_iam_role_policy" "deploy" {
  name   = "put-site-objects"
  role   = aws_iam_role.deploy.id
  policy = data.aws_iam_policy_document.deploy.json
}
