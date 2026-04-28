import re
import networkx as nx
from terraview.parsers.hcl_parser import parse_hcl_directory


def clean_key(key: str) -> str:
    """Strip quotes that python-hcl2 adds to keys."""
    return key.strip('"')


def build_graph_from_plan(plan_path: str) -> nx.DiGraph:
    """Build a directed resource graph from a terraform show -json plan file."""
    from terraview.parsers.plan_parser import parse_plan_json
    resources, explicit_refs = parse_plan_json(plan_path)
    graph = nx.DiGraph()

    for resource_type, instances in resources.items():
        for resource_name, data in instances.items():
            node_id = f"{resource_type}.{resource_name}"
            graph.add_node(
                node_id,
                resource_type=resource_type,
                resource_name=resource_name,
                file_path=data["file_path"],
                config=data["config"],
                change_action=data["change_action"],
            )

    for node_id, refs in explicit_refs.items():
        if node_id not in graph.nodes:
            continue
        for ref in refs:
            if ref in graph.nodes:
                graph.add_edge(node_id, ref, relationship="references")

    return graph


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
    for value in _iter_config_values(config):
        if isinstance(value, str):
            refs.extend(_extract_references(value))
    return refs


def _iter_config_values(config: object):
    if isinstance(config, dict):
        for value in config.values():
            yield from _iter_config_values(value)
    elif isinstance(config, list):
        for item in config:
            yield from _iter_config_values(item)
    else:
        yield config


_NON_RESOURCE_PREFIXES = {"var", "local", "module", "data", "path", "each", "self"}


def _extract_references(value: str) -> list[str]:
    refs = []
    pattern = r'\b([a-zA-Z][a-zA-Z0-9_]*)\.([a-zA-Z][a-zA-Z0-9_]*)\b'
    for resource_type, resource_name in re.findall(pattern, value):
        if resource_type not in _NON_RESOURCE_PREFIXES:
            refs.append(f"{resource_type}.{resource_name}")
    return refs
