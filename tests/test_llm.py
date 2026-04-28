from terraview.analyzers.llm import _sanitize_response, _clean_resource_name


def test_sanitize_response_removes_markdown_fences():
    raw = "```json\n[{'id': 'LLM-001'}]\n```"
    sanitized = _sanitize_response(raw)
    assert sanitized.startswith("[")
    assert sanitized.endswith("]")


def test_clean_resource_name_strips_type_prefix():
    resource_type = "aws_instance"
    resource_name = "aws_instance.web"
    assert _clean_resource_name(resource_type, resource_name) == "web"


def test_clean_resource_name_keeps_name_without_prefix():
    resource_type = "aws_instance"
    resource_name = "web"
    assert _clean_resource_name(resource_type, resource_name) == "web"
