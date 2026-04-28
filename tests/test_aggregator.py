from terraview.findings.aggregator import deduplicate
from terraview.findings.models import Finding, Severity


def _f(id: str, severity: Severity, source: str = "static", name: str = "web") -> Finding:
    return Finding(
        id=id, title="t", description="d", severity=severity,
        resource_type="aws_instance", resource_name=name,
        file_path="main.tf", source=source,
    )


def test_unique_findings_are_kept():
    findings = [_f("A-001", Severity.HIGH), _f("A-002", Severity.MEDIUM)]
    assert len(deduplicate(findings)) == 2


def test_exact_duplicate_is_collapsed():
    findings = [_f("A-001", Severity.HIGH), _f("A-001", Severity.HIGH)]
    result = deduplicate(findings)
    assert len(result) == 1


def test_higher_severity_wins_on_same_key():
    findings = [
        _f("IAM-001", Severity.MEDIUM, source="static"),
        _f("IAM-001", Severity.CRITICAL, source="llm"),
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0].severity == Severity.CRITICAL


def test_lower_severity_does_not_replace_higher():
    findings = [
        _f("IAM-001", Severity.CRITICAL, source="llm"),
        _f("IAM-001", Severity.LOW, source="static"),
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0].severity == Severity.CRITICAL


def test_same_id_different_resource_both_kept():
    findings = [
        _f("SG-001", Severity.HIGH, name="web"),
        _f("SG-001", Severity.HIGH, name="db"),
    ]
    assert len(deduplicate(findings)) == 2


def test_order_preserved_for_unique_findings():
    findings = [_f("C", Severity.LOW), _f("B", Severity.HIGH), _f("A", Severity.CRITICAL)]
    result = deduplicate(findings)
    assert [f.id for f in result] == ["C", "B", "A"]
