output "role_arn" {
  description = "Goes into the AWS_ROLE_ARN repository variable (not a secret)."
  value       = aws_iam_role.deploy.arn
}

output "role_name" {
  value = aws_iam_role.deploy.name
}

output "bucket" {
  description = "Goes into the ARTIFACT_BUCKET repository variable."
  value       = aws_s3_bucket.site.bucket
}

output "aws_region" {
  value = var.aws_region
}

output "github_repo" {
  value = var.github_repo
}

output "deploy_branch" {
  value = var.deploy_branch
}

output "deploy_sub" {
  description = "The exact token subject the trust policy requires."
  value       = local.deploy_sub
}
