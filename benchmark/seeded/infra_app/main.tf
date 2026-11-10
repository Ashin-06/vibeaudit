# Seeded benchmark app: each `expect:` line is a known problem the named rule must report.
resource "aws_s3_bucket_acl" "uploads" { # expect: CFG014
  bucket = "uploads"
  acl    = "public-read"
}

resource "aws_security_group" "db" {
  ingress { # expect: CFG015
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" { # expect: CFG016
  engine         = "postgres"
  instance_class = "db.t3.micro"
}
