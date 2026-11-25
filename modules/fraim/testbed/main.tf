resource "aws_s3_bucket_acl" "rapports" {
  bucket = "rapports-exemple-test"
  acl    = "public-read-write"
}
