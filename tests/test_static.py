import networkx as nx
from terraview.analyzers.static import run_static_checks
from terraview.findings.models import Severity


def _graph(*nodes):
    g = nx.DiGraph()
    for node_id, attrs in nodes:
        g.add_node(node_id, **attrs)
    return g


def _node(node_id: str, rtype: str, rname: str, config: dict):
    return node_id, {
        "resource_type": rtype,
        "resource_name": rname,
        "file_path": "main.tf",
        "config": config,
    }


def test_open_ssh_detected():
    g = _graph(_node(
        "aws_security_group.open", "aws_security_group", "open",
        {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]},
    ))
    findings = run_static_checks(g)
    ids = [f.id for f in findings]
    assert "SG-001" in ids


def test_restricted_ssh_not_flagged():
    g = _graph(_node(
        "aws_security_group.internal", "aws_security_group", "internal",
        {"ingress": [{"from_port": 22, "to_port": 22, "cidr_blocks": ["10.0.0.0/8"]}]},
    ))
    findings = run_static_checks(g)
    assert not any(f.id == "SG-001" for f in findings)


def test_wildcard_iam_policy_detected():
    g = _graph(_node(
        "aws_iam_role_policy.admin", "aws_iam_role_policy", "admin",
        {"policy": '{"Statement":[{"Action":"*","Resource":"*"}]}'},
    ))
    findings = run_static_checks(g)
    assert any(f.id == "IAM-001" for f in findings)
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_public_s3_detected():
    g = _graph(_node(
        "aws_s3_bucket_acl.data", "aws_s3_bucket_acl", "data",
        {"acl": "public-read"},
    ))
    findings = run_static_checks(g)
    assert any(f.id == "S3-001" for f in findings)


def test_unencrypted_ebs_detected():
    g = _graph(_node(
        "aws_instance.web", "aws_instance", "web",
        {"root_block_device": [{"encrypted": False}]},
    ))
    findings = run_static_checks(g)
    assert any(f.id == "EBS-001" for f in findings)


def test_encrypted_ebs_not_flagged():
    g = _graph(_node(
        "aws_instance.web", "aws_instance", "web",
        {"root_block_device": [{"encrypted": True}]},
    ))
    findings = run_static_checks(g)
    assert not any(f.id == "EBS-001" for f in findings)


def test_public_ec2_detected():
    g = _graph(_node(
        "aws_instance.web", "aws_instance", "web",
        {"associate_public_ip_address": True},
    ))
    findings = run_static_checks(g)
    assert any(f.id == "EC2-001" for f in findings)


def test_no_false_positives_on_clean_config():
    g = _graph(_node(
        "aws_instance.web", "aws_instance", "web",
        {"associate_public_ip_address": False, "root_block_device": [{"encrypted": True}]},
    ))
    findings = run_static_checks(g)
    assert findings == []
