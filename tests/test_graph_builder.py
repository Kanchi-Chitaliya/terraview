import tempfile
from pathlib import Path
from terraview.graph.builder import build_graph
from terraview.analyzers.traversal import run_graph_checks


def test_build_graph_creates_edges_for_references():
    with tempfile.TemporaryDirectory() as tmpdir:
        tf_path = Path(tmpdir)
        (tf_path / "main.tf").write_text(
            '''
            resource "aws_security_group" "ssh" {
              ingress {
                from_port   = 22
                to_port     = 22
                cidr_blocks = ["0.0.0.0/0"]
              }
            }

            resource "aws_iam_role" "admin" {
              assume_role_policy = jsonencode({
                Statement = [{
                  Effect = "Allow"
                  Principal = { Service = "ec2.amazonaws.com" }
                  Action = "sts:AssumeRole"
                }]
              })
            }

            resource "aws_iam_role_policy" "admin" {
              role   = aws_iam_role.admin.name
              policy = jsonencode({
                Statement = [{
                  Action   = ["*"]
                  Effect   = "Allow"
                  Resource = ["*"]
                }]
              })
            }

            resource "aws_iam_instance_profile" "web_profile" {
              role = aws_iam_role.admin.name
            }

            resource "aws_instance" "web" {
              associate_public_ip_address = true
              vpc_security_group_ids      = [aws_security_group.ssh.id]
              iam_instance_profile        = aws_iam_instance_profile.web_profile.name
            }
            '''
        )
        graph = build_graph(str(tf_path))

        assert graph.number_of_nodes() == 5
        assert graph.number_of_edges() >= 3
        assert "aws_instance.web" in graph.nodes
        assert "aws_security_group.ssh" in graph.nodes
        assert ("aws_instance.web", "aws_security_group.ssh") in graph.edges
        assert ("aws_iam_instance_profile.web_profile", "aws_iam_role.admin") in graph.edges
        assert ("aws_iam_role_policy.admin", "aws_iam_role.admin") in graph.edges

        findings = run_graph_checks(graph)
        assert len(findings) == 1
        assert findings[0].id == "CHAIN-001"
        assert findings[0].severity.value == "CRITICAL"
        assert "open SSH" in findings[0].description
