variable "aws_region" {
  description = "Region for the deploy bucket. IAM itself is global."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every named resource."
  type        = string
  default     = "hoc-oidc"
}

variable "github_repo" {
  description = "The repository allowed to assume the role, as owner/name."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repo))
    error_message = "github_repo must look like owner/name, with no wildcards."
  }
}

variable "deploy_branch" {
  description = "The only branch whose workflows may assume the deploy role."
  type        = string
  default     = "main"

  validation {
    condition     = !can(regex("[*?]", var.deploy_branch))
    error_message = "deploy_branch must be an exact branch name, not a pattern."
  }
}

variable "create_oidc_provider" {
  description = "An account can hold only one GitHub OIDC provider. Set false if it already exists and Terraform should look it up instead."
  type        = bool
  default     = true
}

variable "session_seconds" {
  description = "Maximum lifetime of the role's credentials. IAM's minimum is 3600; the workflow asks for less."
  type        = number
  default     = 3600
}
