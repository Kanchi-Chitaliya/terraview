import networkx as nx
from terraview.findings.models import Finding, Severity


def run_static_checks(graph: nx.DiGraph) -> list[Finding]:
    """Run all static rule checks against the resource graph."""
    findings = []
    checks = [
        _check_open_ssh,
        _check_admin_iam_policy,
        _check_public_s3,
        _check_unencrypted_ebs,
        _check_public_ec2,
    ]
    for node_id, attrs in graph.nodes(data=True):
        for check in checks:
            result = check(node_id, attrs)
            if result:
                findings.append(result)
    return findings


def _check_open_ssh(node_id: str, attrs: dict) -> Finding | None:
    if attrs["resource_type"] != "aws_security_group":
        return None
    config = attrs["config"]
    for ingress in _get_list(config, "ingress"):
        if (
            _get_val(ingress, "from_port") == 22
            and "0.0.0.0/0" in str(_get_val(ingress, "cidr_blocks", []))
        ):
            return Finding(
                id="SG-001",
                title="SSH open to the internet",
                description=f"{node_id} allows SSH (port 22) from 0.0.0.0/0.",
                severity=Severity.HIGH,
                resource_type=attrs["resource_type"],
                resource_name=attrs["resource_name"],
                file_path=attrs["file_path"],
                mitre_technique="T1190",
                mitre_tactic="Initial Access",
                remediation='cidr_blocks = ["10.0.0.0/8"]  # Restrict to private ranges',
                source="static",
            )
    return None


def _check_admin_iam_policy(node_id: str, attrs: dict) -> Finding | None:
    if attrs["resource_type"] not in ("aws_iam_role_policy", "aws_iam_policy"):
        return None
    config_str = str(attrs["config"])
    if '"*"' in config_str or "'*'" in config_str:
        return Finding(
            id="IAM-001",
            title="Wildcard IAM policy",
            description=f"{node_id} grants Action:* and/or Resource:* — full admin access.",
            severity=Severity.CRITICAL,
            resource_type=attrs["resource_type"],
            resource_name=attrs["resource_name"],
            file_path=attrs["file_path"],
            mitre_technique="T1078.004",
            mitre_tactic="Privilege Escalation",
            remediation="Replace Action: '*' with specific actions required by the workload.",
            source="static",
        )
    return None


def _check_public_s3(node_id: str, attrs: dict) -> Finding | None:
    if attrs["resource_type"] != "aws_s3_bucket_acl":
        return None
    config_str = str(attrs["config"])
    if "public-read" in config_str or "public-read-write" in config_str:
        return Finding(
            id="S3-001",
            title="S3 bucket publicly readable",
            description=f"{node_id} sets ACL to public-read, exposing all objects.",
            severity=Severity.HIGH,
            resource_type=attrs["resource_type"],
            resource_name=attrs["resource_name"],
            file_path=attrs["file_path"],
            mitre_technique="T1530",
            mitre_tactic="Collection",
            remediation='acl = "private"',
            source="static",
        )
    return None


def _check_unencrypted_ebs(node_id: str, attrs: dict) -> Finding | None:
    if attrs["resource_type"] != "aws_instance":
        return None
    config = attrs["config"]
    for block in _get_list(config, "root_block_device"):
        if str(_get_val(block, "encrypted", "false")).lower() == "false":
            return Finding(
                id="EBS-001",
                title="Unencrypted EBS root volume",
                description=f"{node_id} has an unencrypted root volume.",
                severity=Severity.MEDIUM,
                resource_type=attrs["resource_type"],
                resource_name=attrs["resource_name"],
                file_path=attrs["file_path"],
                mitre_technique="T1005",
                mitre_tactic="Collection",
                remediation="encrypted = true",
                source="static",
            )
    return None


def _check_public_ec2(node_id: str, attrs: dict) -> Finding | None:
    if attrs["resource_type"] != "aws_instance":
        return None
    config = attrs["config"]
    if str(_get_val(config, "associate_public_ip_address", "false")).lower() == "true":
        return Finding(
            id="EC2-001",
            title="EC2 instance has public IP",
            description=f"{node_id} is directly reachable from the internet.",
            severity=Severity.MEDIUM,
            resource_type=attrs["resource_type"],
            resource_name=attrs["resource_name"],
            file_path=attrs["file_path"],
            mitre_technique="T1190",
            mitre_tactic="Initial Access",
            remediation="associate_public_ip_address = false",
            source="static",
        )
    return None


def _get_list(config: dict | list, key: str) -> list:
    if isinstance(config, list):
        config = config[0] if config else {}
    val = config.get(key, [])
    if isinstance(val, dict):
        return [val]
    return val if isinstance(val, list) else []


def _get_val(config: dict | list, key: str, default=None):
    if isinstance(config, list):
        config = config[0] if config else {}
    return config.get(key, default)
