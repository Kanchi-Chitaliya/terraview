import json
from terraview.findings.models import Finding, Severity

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def generate_sarif(findings: list[Finding], scan_path: str) -> str:
    """
    Produce a SARIF 2.1.0 document from findings.
    GitHub Actions renders SARIF as inline PR annotations when uploaded via
    the upload-sarif action.
    """
    rules_index: dict[str, int] = {}
    rules: list[dict] = []

    for f in findings:
        if f.id not in rules_index:
            rules_index[f.id] = len(rules)
            rule: dict = {
                "id": f.id,
                "name": _to_camel(f.id),
                "shortDescription": {"text": f.title},
                "helpUri": (
                    f"https://attack.mitre.org/techniques/{f.mitre_technique.replace('.', '/')}"
                    if f.mitre_technique else "https://github.com/kanchichitaliya/terraview"
                ),
                "properties": {"tags": ["security", "terraform"]},
            }
            if f.remediation:
                rule["help"] = {"text": f.remediation}
            rules.append(rule)

    results: list[dict] = []
    for f in findings:
        result: dict = {
            "ruleId": f.id,
            "ruleIndex": rules_index[f.id],
            "level": _LEVEL[f.severity],
            "message": {"text": f.description or f.title},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": _relative_uri(f.file_path, scan_path),
                            "uriBaseId": "%SRCROOT%",
                        },
                        **({"region": {"startLine": f.line_number}} if f.line_number else {}),
                    }
                }
            ],
        }
        if f.blast_radius:
            result["relatedLocations"] = [
                {"message": {"text": r}, "id": i}
                for i, r in enumerate(f.blast_radius)
            ]
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "terraview",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/kanchichitaliya/terraview",
                        "rules": rules,
                    }
                },
                "results": results,
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _relative_uri(file_path: str, scan_path: str) -> str:
    """Return a URI relative to scan_path, falling back to the raw path."""
    try:
        from pathlib import Path
        rel = Path(file_path).relative_to(Path(scan_path).resolve())
        return str(rel)
    except (ValueError, TypeError):
        return file_path


def _to_camel(rule_id: str) -> str:
    """SG-001 → SgRule001, CKV_AWS_1 → CkvAws1."""
    return "".join(p.capitalize() for p in rule_id.replace("_", "-").split("-"))
