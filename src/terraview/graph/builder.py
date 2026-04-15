import re
import networkx as nx
from terraview.parsers.hcl_parser import parse_hcl_directory


def clean_key(key: str) -> str:
    """Strip quotes that python-hcl2 adds to keys."""
    return key.strip('"')


def build_graph(path: str) -> nx.DiGraph:
    """Build a directed resource graph from a Terraform directory."""
    resources = parse_hcl_directory(path)
    graph = nx.DiGraph()

    # Add all resources as nodes
    for resource_type, instances in resources.items():
        rtype = clean_key(resource_type)
        for resource_name, data in instances.items():
            rname = clean_key(resource_name)
            node_id = f"{rtype}.{rname}"
            graph.add_node(node_id, 
                resource_type=rtype,
                resource_name=rname,
                file_path=data["file_path"],
                config=data["config"],
            )

    # Add edges by detecting references between resources
    for node_id, attrs in list(graph.nodes(data=True)):
        refs = _find_references(attrs["config"])
        for ref in refs:
            if ref in graph.nodes:
                graph.add_edge(node_id, ref, relationship="references")

    return graph


def _find_references(config: object) -> list[str]:
    """Recursively find all resource references in a config block."""
    refs = []
    config_str = str(config)
    # Match patterns like aws_iam_role.ec2_role or aws_s3_bucket.data
    pattern = r'\b(aws_[a-z_]+)\.([a-z_][a-z0-9_]*)\b'
    matches = re.findall(pattern, config_str)
    for resource_type, resource_name in matches:
        refs.append(f"{resource_type}.{resource_name}")
    return refs
