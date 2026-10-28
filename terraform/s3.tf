# The deploy target. Holds one small file; S3 cost at this size is negligible.
resource "aws_s3_bucket" "site" {
  bucket        = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-site"
  force_destroy = true # lab only: lets `terraform destroy` remove the uploaded file
}

resource "aws_s3_bucket_public_access_block" "site" {
  bucket                  = aws_s3_bucket.site.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "site" {
  bucket = aws_s3_bucket.site.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
