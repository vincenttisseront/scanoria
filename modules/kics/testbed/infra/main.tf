# Banc d'essai Scanoria : IaC volontairement fautive, jamais appliquée.
resource "aws_security_group" "ssh_world" {
  name = "ssh-world"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "public" {
  bucket = "scanoria-testbed-exemple"
}

resource "aws_s3_bucket_acl" "public" {
  bucket = aws_s3_bucket.public.id
  acl    = "public-read"
}
