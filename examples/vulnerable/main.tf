# Vulnerable example: EC2 with admin IAM role in public subnet
# This demonstrates privilege escalation + lateral movement risk

provider "aws" {
  region = "us-east-1"
}

# Overpermissive IAM role - allows PassRole to any resource
resource "aws_iam_role" "ec2_role" {
  name = "ec2-admin-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# Admin policy attached directly - wildcard on everything
resource "aws_iam_role_policy" "ec2_admin_policy" {
  name = "ec2-admin-policy"
  role = aws_iam_role.ec2_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-admin-profile"
  role = aws_iam_role.ec2_role.name
}

# Security group open to the world on SSH and HTTP
resource "aws_security_group" "open_sg" {
  name        = "open-security-group"
  description = "Dangerously open security group"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# EC2 in public subnet with admin role and open security group
resource "aws_instance" "web" {
  ami                         = "ami-0c55b159cbfafe1f0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.ec2_profile.name
  vpc_security_group_ids      = [aws_security_group.open_sg.id]

  # No encryption on root volume
  root_block_device {
    encrypted = false
  }

  tags = {
    Name = "vulnerable-web-server"
  }
}

# S3 bucket with no encryption and public access
resource "aws_s3_bucket" "data" {
  bucket = "my-vulnerable-data-bucket"
}

resource "aws_s3_bucket_acl" "data_acl" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
