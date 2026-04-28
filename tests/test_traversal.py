import tempfile
from pathlib import Path
import networkx as nx
from terraview.analyzers.traversal import run_graph_checks
from terraview.graph.builder import build_graph
from terraview.findings.models import Severity


def _build(tf: str) -> nx.DiGraph:
    with tempfile.TemporaryDirectory() as tmpdir:
        (Path(tmpdir) / "main.tf").write_text(tf)
        return build_graph(tmpdir)


CHAIN_001_TF = '''
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_role" "admin" {
  assume_role_policy = "{}"
}
resource "aws_iam_role_policy" "admin" {
  role   = aws_iam_role.admin.id
  policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })
}
resource "aws_iam_instance_profile" "profile" {
  role = aws_iam_role.admin.name
}
resource "aws_instance" "web" {
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.ssh.id]
  iam_instance_profile        = aws_iam_instance_profile.profile.name
}
'''

CHAIN_001_NO_OPEN_SSH_TF = '''
resource "aws_security_group" "ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}
resource "aws_iam_role" "admin" {
  assume_role_policy = "{}"
}
resource "aws_iam_role_policy" "admin" {
  role   = aws_iam_role.admin.id
  policy = jsonencode({ Statement = [{ Action = "*", Effect = "Allow", Resource = "*" }] })
}
resource "aws_iam_instance_profile" "profile" {
  role = aws_iam_role.admin.name
}
resource "aws_instance" "web" {
  associate_public_ip_address = true
  vpc_security_group_ids      = [aws_security_group.ssh.id]
  iam_instance_profile        = aws_iam_instance_profile.profile.name
}
'''


def test_chain_001_detected():
    g = _build(CHAIN_001_TF)
    findings = run_graph_checks(g)
    assert any(f.id == "CHAIN-001" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_chain_001_not_fired_without_open_ssh():
    g = _build(CHAIN_001_NO_OPEN_SSH_TF)
    findings = run_graph_checks(g)
    assert not any(f.id == "CHAIN-001" for f in findings)


def test_chain_001_blast_radius_includes_sg():
    g = _build(CHAIN_001_TF)
    findings = run_graph_checks(g)
    chain = next(f for f in findings if f.id == "CHAIN-001")
    assert any("security_group" in r for r in chain.blast_radius)


def test_chain_002_detected():
    tf = CHAIN_001_TF + '''
resource "aws_s3_bucket" "data" { bucket = "bucket" }
resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read"
}
'''
    g = _build(tf)
    findings = run_graph_checks(g)
    assert any(f.id == "CHAIN-002" for f in findings)


def test_no_findings_on_clean_config():
    tf = '''
resource "aws_instance" "web" {
  associate_public_ip_address = false
}
'''
    g = _build(tf)
    findings = run_graph_checks(g)
    assert findings == []
