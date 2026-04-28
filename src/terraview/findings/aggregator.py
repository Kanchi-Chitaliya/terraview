from terraview.findings.models import Finding, Severity

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """
    Merge findings that refer to the same check on the same resource across sources.
    When the same (resource_type, resource_name, id) appears more than once,
    keep the highest-severity version.
    """
    seen: dict[tuple, int] = {}
    result: list[Finding] = []

    for f in findings:
        key = (f.resource_type, f.resource_name, f.id)
        if key not in seen:
            seen[key] = len(result)
            result.append(f)
        else:
            idx = seen[key]
            existing = result[idx]
            if _SEVERITY_RANK[f.severity] < _SEVERITY_RANK[existing.severity]:
                result[idx] = f

    return result
