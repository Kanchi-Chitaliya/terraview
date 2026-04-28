import json
from terraview.output.sarif import generate_sarif, _to_camel
from terraview.findings.models import Finding, Severity


def _f(id: str, severity: Severity, line: int = None, mitre: str = None) -> Finding:
    return Finding(
        id=id, title="Test finding", description="A risk was found.",
        severity=severity, resource_type="aws_instance", resource_name="web",
        file_path="/project/main.tf", line_number=line,
        mitre_technique=mitre, mitre_tactic="Initial Access" if mitre else None,
        remediation="associate_public_ip_address = false",
        source="static",
    )


def test_valid_sarif_schema():
    sarif = json.loads(generate_sarif([_f("EC2-001", Severity.HIGH)], "/project"))
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1


def test_tool_name():
    sarif = json.loads(generate_sarif([_f("EC2-001", Severity.HIGH)], "/project"))
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "terraview"


def test_result_count_matches_findings():
    findings = [_f("EC2-001", Severity.HIGH), _f("SG-001", Severity.CRITICAL)]
    sarif = json.loads(generate_sarif(findings, "/project"))
    assert len(sarif["runs"][0]["results"]) == 2


def test_rules_deduplicated():
    findings = [_f("SG-001", Severity.HIGH), _f("SG-001", Severity.HIGH)]
    sarif = json.loads(generate_sarif(findings, "/project"))
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1


def test_severity_mapping():
    sarif = json.loads(generate_sarif([
        _f("A", Severity.CRITICAL),
        _f("B", Severity.MEDIUM),
        _f("C", Severity.INFO),
    ], "/project"))
    levels = {r["ruleId"]: r["level"] for r in sarif["runs"][0]["results"]}
    assert levels["A"] == "error"
    assert levels["B"] == "warning"
    assert levels["C"] == "note"


def test_line_number_included_when_present():
    sarif = json.loads(generate_sarif([_f("EC2-001", Severity.HIGH, line=42)], "/project"))
    region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"].get("region")
    assert region == {"startLine": 42}


def test_no_region_when_line_number_absent():
    sarif = json.loads(generate_sarif([_f("EC2-001", Severity.HIGH)], "/project"))
    physical = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert "region" not in physical


def test_mitre_uri_in_rule_help():
    sarif = json.loads(generate_sarif([_f("X-001", Severity.HIGH, mitre="T1190")], "/project"))
    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert "T1190" in rule["helpUri"]


def test_to_camel():
    assert _to_camel("SG-001") == "Sg001"
    assert _to_camel("CKV_AWS_1") == "CkvAws1"
    assert _to_camel("CHAIN-001") == "Chain001"
