import json
import tempfile
import os
from terraview.parsers.plan_parser import parse_plan_json


def _write_plan(data: dict) -> str:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
    json.dump(data, f)
    f.close()
    return f.name


MINIMAL_PLAN = {
    "format_version": "1.2",
    "planned_values": {
        "root_module": {
            "resources": [
                {
                    "address": "aws_instance.web",
                    "type": "aws_instance",
                    "name": "web",
                    "values": {"associate_public_ip_address": True},
                },
                {
                    "address": "aws_security_group.ssh",
                    "type": "aws_security_group",
                    "name": "ssh",
                    "values": {"ingress": [{"from_port": 22, "cidr_blocks": ["0.0.0.0/0"]}]},
                },
            ]
        }
    },
    "resource_changes": [
        {
            "address": "aws_instance.web",
            "change": {
                "actions": ["create"],
                "after": {"associate_public_ip_address": True},
            },
        },
        {
            "address": "aws_security_group.ssh",
            "change": {"actions": ["no-op"], "after": None},
        },
    ],
    "configuration": {
        "root_module": {
            "resources": [
                {
                    "type": "aws_instance",
                    "name": "web",
                    "expressions": {
                        "vpc_security_group_ids": {
                            "references": ["aws_security_group.ssh.id", "aws_security_group.ssh"]
                        }
                    },
                }
            ]
        }
    },
}


def test_parse_resources():
    path = _write_plan(MINIMAL_PLAN)
    try:
        resources, _ = parse_plan_json(path)
        assert "aws_instance" in resources
        assert "web" in resources["aws_instance"]
        assert "aws_security_group" in resources
    finally:
        os.unlink(path)


def test_change_action_from_resource_changes():
    path = _write_plan(MINIMAL_PLAN)
    try:
        resources, _ = parse_plan_json(path)
        assert resources["aws_instance"]["web"]["change_action"] == "create"
        assert resources["aws_security_group"]["ssh"]["change_action"] == "no-op"
    finally:
        os.unlink(path)


def test_after_values_take_precedence_over_planned_values():
    # after_map has the resolved value; planned_values.values is the fallback
    path = _write_plan(MINIMAL_PLAN)
    try:
        resources, _ = parse_plan_json(path)
        assert resources["aws_instance"]["web"]["config"]["associate_public_ip_address"] is True
    finally:
        os.unlink(path)


def test_replace_action():
    plan = {**MINIMAL_PLAN, "resource_changes": [
        {"address": "aws_instance.web", "change": {"actions": ["create", "delete"], "after": {}}},
        {"address": "aws_security_group.ssh", "change": {"actions": ["no-op"], "after": {}}},
    ]}
    path = _write_plan(plan)
    try:
        resources, _ = parse_plan_json(path)
        assert resources["aws_instance"]["web"]["change_action"] == "replace"
    finally:
        os.unlink(path)


def test_references_extracted_from_configuration():
    path = _write_plan(MINIMAL_PLAN)
    try:
        _, refs = parse_plan_json(path)
        assert "aws_instance.web" in refs
        assert "aws_security_group.ssh" in refs["aws_instance.web"]
    finally:
        os.unlink(path)


def test_non_resource_prefixes_excluded_from_refs():
    plan = {**MINIMAL_PLAN}
    plan["configuration"] = {
        "root_module": {
            "resources": [{
                "type": "aws_instance",
                "name": "web",
                "expressions": {
                    "tags": {"references": ["var.env", "local.name", "aws_security_group.ssh"]},
                },
            }]
        }
    }
    path = _write_plan(plan)
    try:
        _, refs = parse_plan_json(path)
        assert refs.get("aws_instance.web") == ["aws_security_group.ssh"]
    finally:
        os.unlink(path)


def test_child_modules_are_traversed():
    plan = {
        "format_version": "1.2",
        "planned_values": {
            "root_module": {
                "resources": [],
                "child_modules": [{
                    "resources": [{
                        "address": "module.net.aws_vpc.main",
                        "type": "aws_vpc",
                        "name": "main",
                        "values": {"cidr_block": "10.0.0.0/16"},
                    }]
                }]
            }
        },
        "resource_changes": [
            {"address": "module.net.aws_vpc.main",
             "change": {"actions": ["create"], "after": {"cidr_block": "10.0.0.0/16"}}},
        ],
        "configuration": {"root_module": {"resources": [], "child_modules": []}},
    }
    path = _write_plan(plan)
    try:
        resources, _ = parse_plan_json(path)
        assert "aws_vpc" in resources
        assert "main" in resources["aws_vpc"]
    finally:
        os.unlink(path)
