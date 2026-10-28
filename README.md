# GitHub Actions to AWS with OIDC (no stored keys)

A workflow deploys a file to S3 using **temporary credentials from OIDC**. No access key is stored anywhere. A trust policy limits the role to one repository and one branch.

```
workflow job ──(1) request token──▶ GitHub OIDC issuer
             ◀─(2) signed token (repo, branch, workflow)
             ──(3) token──▶ AWS STS ──▶ IAM OIDC provider (signature) + role trust policy
             ◀─(4) short-lived credentials
             ──(5) s3:PutObject site/*──▶ bucket
```

- `terraform/`: OIDC provider, deploy role (trust policy + one-statement permissions), S3 bucket
- `.github/workflows/deploy.yml`: the workflow (`id-token: write`, no secrets)
- `scripts/oidc_claims.py`: prints the claims in the job's token, never the token
- `oidc.py`: the client used in the video (`setup`, `trust`, `run`, `keys`, `cleanup`)

## The trust policy

```hcl
condition { test = "StringEquals"  variable = "token.actions.githubusercontent.com:aud"  values = ["sts.amazonaws.com"] }
condition { test = "StringEquals"  variable = "token.actions.githubusercontent.com:sub"  values = ["repo:OWNER/REPO:ref:refs/heads/main"] }
```

The audience is the same for every GitHub user, so **the `sub` condition is what makes the role yours**. Use `StringEquals` with an exact value. A `StringLike` with `*` widens access to more repos, branches or forks than you meant.

## Run it

Requires Terraform ≥ 1.9, the `gh` CLI (`gh auth login`), Python 3.11+, and AWS credentials that can create IAM roles and S3 buckets.

```bash
# 1. This folder must be the root of a GitHub repo, so the workflow runs.
cd labs/week-02-github-oidc
git init -b main && git add . && git commit -m "OIDC lab"
gh repo create handsoncloud-labs/week-02-github-oidc --public --source . --push

# 2. Tell Terraform which repo may assume the role.
cp terraform/terraform.tfvars.example terraform/terraform.tfvars   # edit github_repo
#    Already have a GitHub OIDC provider in this account? Set create_oidc_provider = false.
terraform -chdir=terraform init && terraform -chdir=terraform apply

# 3. Hand the role ARN to the repo as variables (identifiers, not secrets).
python oidc.py setup

# 4. See it work, then see it refused.
python oidc.py trust
python oidc.py run                # deploy branch: succeeds
python oidc.py run demo-denied    # any other branch: STS refuses
python oidc.py keys               # no AWS keys in the repo

# Tear down
python oidc.py cleanup && terraform -chdir=terraform destroy
```

## Cost

IAM roles and the OIDC provider are free. The bucket holds one small file. GitHub Actions minutes for a public repo are free.
