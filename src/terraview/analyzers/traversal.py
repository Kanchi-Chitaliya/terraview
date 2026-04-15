import networkx as nx
from terraview.findings.models import Finding, Severity


def run_graph_checks(graph: nx.DiGraph) -> list[Finding]:
    """Run graph traversal checks to find cross-resource attack chains."""
    findings = []
    findings.extend(_check_public_ec2_to_admin_role(graph))
    findings.extend(_check_public_ec2_to_sensitive_bucket(graph))
    return findings


def _check_public_ec2_to_admin_role(graph: nx.DiGraph) -> list[Finding]:
    """
    Detect: public EC2 + open SG → instance profile → admin IAM role.
    This is the classic cloud privilege escalation chain.
    """
    findings = []

    for node_id, attrs in graph.nodes(data=True):
        if attrs["resource_type"] != "aws_instance":
            continue

        config = attrs["config"]
        if isinstance(config, list):
            config = config[0]

        is_public = str(config.get("associate_public_ip_address", "false")).lower() == "true"
        if not is_public:
            continue

        # Walk: ec2 → instance_profile → iam_role → iam_role_policy
        profile_nodes = _get_neighbors_of_type(graph, node_id, "aws_iam_instance_profile")
        sg_nodes = _get_neighbors_of_type(graph, node_id, "aws_security_group")

        for profile in profile_nodes:
            role_nodes = _get_neighbors_of_type(graph, profile, "aws_iam_role")
            for role in role_nodes:
                policy_nodes = _get_predecessors_of_type(graph, role, "aws_iam_role_policy")
                for policy in policy_nodes:
                    policy_config = str(graph.nodes[policy]["config"])
                    if '"*"' not in policy_config and "'*'" not in policy_config:
                        continue

                    open_sgs = [
                        sg for sg in sg_nodes
                        if _sg_has_open_ssh(graph.nodes[sg]["config"])
                    ]

                    blast_radius = [node_id, profile, role, policy] + open_sgs

                    findings.append(Finding(
                        id="CHAIN-001",
                        title="Public EC2 with open SSH leads to admin IAM role",
                        description=(
                            f"{node_id} is internet-exposed with a public IP "
                            f"and open SSH (port 22). It is attached to {profile}, "
                            f"which grants {role} — a role with wildcard admin permissions "
                            f"via {policy}. An attacker with SSH access can query the instance "
                            f"metadata service (IMDS) to retrieve temporary credentials for "
                            f"the admin role and pivot to any resource in the AWS account."
                        ),
                        severity=Severity.CRITICAL,
                        resource_type=attrs["resource_type"],
                        resource_name=attrs["resource_name"],
                        file_path=attrs["file_path"],
                        mitre_technique="T1552.005",
                        mitre_tactic="Credential Access → Privilege Escalation",
                        remediation=(
                            "1. Set associate_public_ip_address = false\n"
                            "2. Restrict security group to known CIDRs\n"
                            "3. Replace Action:'*' with least-privilege actions"
                        ),
                        blast_radius=blast_radius,
                        source="graph",
                    ))

    return findings


def _check_public_ec2_to_sensitive_bucket(graph: nx.DiGraph) -> list[Finding]:
    """
    Detect: public EC2 → admin role → S3 bucket with public ACL.
    Data exfiltration chain.
    """
    findings = []

    public_buckets = [
        n for n, a in graph.nodes(data=True)
        if a["resource_type"] == "aws_s3_bucket_acl"
        and "public-read" in str(a["config"])
    ]

    if not public_buckets:
        return findings

    for node_id, attrs in graph.nodes(data=True):
        if attrs["resource_type"] != "aws_instance":
            continue

        config = attrs["config"]
        if isinstance(config, list):
            config = config[0]

        is_public = str(config.get("associate_public_ip_address", "false")).lower() == "true"
        if not is_public:
            continue

        profile_nodes = _get_neighbors_of_type(graph, node_id, "aws_iam_instance_profile")
        for profile in profile_nodes:
            role_nodes = _get_neighbors_of_type(graph, profile, "aws_iam_role")
            for role in role_nodes:
                policy_nodes = _get_predecessors_of_type(graph, role, "aws_iam_role_policy")
                for policy in policy_nodes:
                    policy_config = str(graph.nodes[policy]["config"])
                    if '"*"' not in policy_config:
                        continue

                    for bucket in public_buckets:
                        findings.append(Finding(
                            id="CHAIN-002",
                            title="Data exfiltration path: public EC2 → admin role → public S3",
                            description=(
                                f"{node_id} is internet-exposed and has admin IAM credentials "
                                f"via {profile} → {role}. {bucket} is publicly readable. "
                                f"An attacker can exfiltrate all S3 data without authentication "
                                f"via the bucket ACL, or use the EC2 credentials to access "
                                f"any private bucket in the account."
                            ),
                            severity=Severity.CRITICAL,
                            resource_type=attrs["resource_type"],
                            resource_name=attrs["resource_name"],
                            file_path=attrs["file_path"],
                            mitre_technique="T1530",
                            mitre_tactic="Collection → Exfiltration",
                            remediation=(
                                "1. Set S3 ACL to private\n"
                                "2. Enable S3 Block Public Access at account level\n"
                                "3. Restrict IAM role to minimum required S3 actions"
                            ),
                            blast_radius=[node_id, profile, role, policy, bucket],
                            source="graph",
                        ))

    return findings


def _get_neighbors_of_type(graph: nx.DiGraph, node: str, resource_type: str) -> list[str]:
    return [
        n for n in graph.successors(node)
        if graph.nodes[n]["resource_type"] == resource_type
    ]


def _get_predecessors_of_type(graph: nx.DiGraph, node: str, resource_type: str) -> list[str]:
    return [
        n for n in graph.predecessors(node)
        if graph.nodes[n]["resource_type"] == resource_type
    ]


def _sg_has_open_ssh(config) -> bool:
    if isinstance(config, list):
        config = config[0] if config else {}
    for ingress in config.get("ingress", []):
        if isinstance(ingress, list):
            ingress = ingress[0] if ingress else {}
        if (ingress.get("from_port") == 22 and
                "0.0.0.0/0" in str(ingress.get("cidr_blocks", []))):
            return True
    return False
