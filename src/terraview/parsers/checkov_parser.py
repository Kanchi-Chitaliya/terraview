import json
from terraview.findings.models import Finding, Severity


def parse_checkov_output(
    json_path: str,
    enrich: bool = True,
    provider_name: str = None,
    model: str = None,
) -> list[Finding]:
    """
    Parse Checkov JSON output into terraview findings.

    When enrich=True, findings missing severity or remediation are sent
    to the LLM in a single batch call for enrichment. This covers the
    Checkov free tier which returns null severity on most checks.
    """
    with open(json_path) as f:
        data = json.load(f)

    results = data if isinstance(data, list) else [data]

    findings = []
    for result in results:
        failed = result.get("results", {}).get("failed_checks", [])
        for check in failed:
            findings.append(_parse_check(check))

    if enrich:
        needs_enrichment = [
            f for f in findings
            if f.severity == Severity.MEDIUM and not f.remediation
        ]
        if needs_enrichment:
            print(f"  Enriching {len(needs_enrichment)} Checkov findings via LLM...")
            _enrich_findings(needs_enrichment, provider_name, model)

    return findings


def _parse_check(check: dict) -> Finding:
    check_id = check.get("check_id", "CKV-UNKNOWN")
    severity = _map_severity(check.get("severity"))

    resource = check.get("resource", "unknown")
    parts = resource.split(".", 1)
    resource_type = parts[0] if len(parts) == 2 else "unknown"
    resource_name = parts[1] if len(parts) == 2 else resource

    line_range = check.get("file_line_range", [None, None])
    line_number = line_range[0] if line_range else None

    file_path = (
        check.get("repo_file_path")
        or check.get("file_path")
        or "unknown"
    )

    return Finding(
        id=check_id,
        title=check.get("check_name", check_id),
        description=check.get("check_name", ""),
        severity=severity,
        resource_type=resource_type,
        resource_name=resource_name,
        file_path=file_path,
        line_number=line_number,
        remediation=check.get("guideline") or check.get("description"),
        source="static",
    )


def _map_severity(reported: str | None) -> Severity:
    """Map Checkov severity string to our enum. Defaults to MEDIUM when null."""
    if not reported:
        return Severity.MEDIUM
    return {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
    }.get(reported.upper(), Severity.MEDIUM)


def _enrich_findings(findings: list[Finding], provider_name: str | None, model: str | None):
    """
    Single LLM call to enrich a batch of findings with severity and remediation.
    Mutates findings in place.
    """
    try:
        from terraview.providers import get_provider
        provider = get_provider(provider_name, model)

        # Build a compact list for the LLM to work through
        items = [
            {"index": i, "check_id": f.id, "check_name": f.title, "resource_type": f.resource_type}
            for i, f in enumerate(findings)
        ]

        system = """You are an AWS security expert. You will be given a list of 
Checkov security check failures. For each one return a JSON array where each 
item has:
- index: same index as input
- severity: one of CRITICAL, HIGH, MEDIUM, LOW, INFO
- remediation: a short specific Terraform fix (1-3 lines of HCL)

Base severity on real-world exploitability and blast radius.
Return ONLY the JSON array, no markdown, no explanation."""

        user = f"Enrich these Checkov findings:\n{json.dumps(items, indent=2)}"

        response = provider.complete(system, user)
        response = response.strip()
        if response.startswith("```"):
            response = response.split("\n", 1)[1].rsplit("```", 1)[0]

        enriched = json.loads(response)
        for item in enriched:
            idx = item.get("index")
            if idx is None or idx >= len(findings):
                continue
            sev = item.get("severity", "MEDIUM")
            findings[idx].severity = Severity[sev] if sev in Severity.__members__ else Severity.MEDIUM
            findings[idx].remediation = item.get("remediation")

    except Exception as e:
        print(f"  Checkov enrichment failed, using defaults: {e}")
