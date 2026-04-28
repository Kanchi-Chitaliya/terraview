import json
import networkx as nx
from terraview.findings.models import Finding, Severity
from terraview.providers import get_provider

SYSTEM_PROMPT = """You are an expert AWS cloud security architect reviewing 
Terraform infrastructure code for security risks.

You will be given a summary of cloud resources and their relationships as a 
graph, along with findings already detected by static analysis.

Your job is to identify:
1. Additional security risks not caught by static rules
2. Architectural weaknesses that create risk even if no single resource is 
   misconfigured
3. Missing security controls (logging, monitoring, backups, etc.)

For each finding respond ONLY with a JSON array. Each item must have:
- id: string (prefix LLM-)
- title: string (short, specific)
- description: string (explain the risk clearly)
- severity: one of CRITICAL, HIGH, MEDIUM, LOW, INFO
- resource_name: string (resource name only, e.g. web not aws_instance.web)
- resource_type: string (e.g. aws_instance)
- mitre_technique: string (ATT&CK technique ID)
- mitre_tactic: string (ATT&CK tactic name)
- remediation: string (specific Terraform fix)
- blast_radius: array of strings (affected resource ids)

Return ONLY the JSON array, no markdown, no explanation."""


def run_llm_checks(
    graph: nx.DiGraph,
    existing_findings: list[Finding],
    provider_name: str = None,
    model: str = None,
) -> list[Finding]:
    """Use LLM reasoning to find risks beyond static and graph checks."""
    print(f"\n  Initializing LLM provider ({provider_name or 'anthropic'})...")
    provider = get_provider(provider_name, model)
    print(f"  Provider ready: {provider.name()}")

    print(f"  Building resource graph summary ({graph.number_of_nodes()} nodes, "
          f"{graph.number_of_edges()} edges)...")
    graph_summary = _build_graph_summary(graph)
    findings_summary = _build_findings_summary(existing_findings)

    print(f"  Sending to {provider.name()} for architectural analysis...")
    print(f"  Context: {graph.number_of_nodes()} resources, "
          f"{len(existing_findings)} existing findings")
    print("  This may take 15-30 seconds...")

    changed = [
        nid for nid, a in graph.nodes(data=True)
        if a.get("change_action", "no-op") not in ("no-op", "")
    ]
    change_note = (
        f"\n\nNote: {len(changed)} resource(s) are actively changing in this plan "
        f"(marked [CREATE], [UPDATE], [DELETE], or [REPLACE]). "
        f"Prioritise risks introduced by these changes."
        if changed else ""
    )

    user_prompt = f"""## Resource graph

{graph_summary}

## Already detected findings

{findings_summary}

Identify additional security risks not already covered above.
Focus on architectural gaps, missing controls, and subtle risks.{change_note}"""

    try:
        response = provider.complete(SYSTEM_PROMPT, user_prompt)
        findings = _parse_response(response, graph)
        print(f"  LLM analysis complete: {len(findings)} additional findings identified")
        return findings
    except Exception as e:
        print(f"  LLM analysis failed: {e}")
        return []


def _build_graph_summary(graph: nx.DiGraph) -> str:
    lines = ["Resources:"]
    for node_id, attrs in graph.nodes(data=True):
        change = attrs.get("change_action", "")
        tag = f" [{change.upper()}]" if change and change != "no-op" else ""
        lines.append(f"  - {node_id}{tag} ({attrs['file_path']})")

    lines.append("\nRelationships:")
    for src, dst in graph.edges():
        lines.append(f"  - {src} --> {dst}")

    lines.append("\nResource configs:")
    for node_id, attrs in graph.nodes(data=True):
        config = attrs.get("config", {})
        if isinstance(config, list):
            config = config[0] if config else {}
        config_str = json.dumps(config, default=str)[:500]
        lines.append(f"  {node_id}: {config_str}")

    return "\n".join(lines)


def _build_findings_summary(findings: list[Finding]) -> str:
    if not findings:
        return "None"
    lines = []
    for f in findings:
        lines.append(f"  - [{f.severity.value}] {f.id}: {f.title}")
    return "\n".join(lines)


def _clean_resource_name(resource_type: str, resource_name: str) -> str:
    """Remove accidental type prefix if LLM included it in the name."""
    prefix = resource_type + "."
    if resource_name.startswith(prefix):
        return resource_name[len(prefix):]
    return resource_name


def _sanitize_response(response: str) -> str:
    response = response.strip()
    if response.startswith("```"):
        response = response.split("\n", 1)[1]
        response = response.rsplit("```", 1)[0]
    return response.strip()


def _parse_response(response: str, graph: nx.DiGraph) -> list[Finding]:
    findings = []
    try:
        response = _sanitize_response(response)
        items = json.loads(response)
        for item in items:
            severity = Severity[item.get("severity", "MEDIUM")]
            resource_type = item.get("resource_type", "unknown")
            resource_name = _clean_resource_name(
                resource_type,
                item.get("resource_name", "unknown")
            )
            node_id = f"{resource_type}.{resource_name}"
            file_path = "unknown"
            if node_id in graph.nodes:
                file_path = graph.nodes[node_id].get("file_path", "unknown")
            findings.append(Finding(
                id=item.get("id", "LLM-000"),
                title=item.get("title", ""),
                description=item.get("description", ""),
                severity=severity,
                resource_type=resource_type,
                resource_name=resource_name,
                file_path=file_path,
                mitre_technique=item.get("mitre_technique"),
                mitre_tactic=item.get("mitre_tactic"),
                remediation=item.get("remediation"),
                blast_radius=item.get("blast_radius", []),
                source="llm",
            ))
    except json.JSONDecodeError as e:
        print(f"  Failed to parse LLM JSON response: {e}")
        print(f"  Raw response: {response[:500]}")
    except Exception as e:
        print(f"  Unexpected error parsing LLM response: {e}")
        print(f"  Raw response: {response[:500]}")
    return findings
