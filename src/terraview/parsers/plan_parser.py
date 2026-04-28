import json

_NON_RESOURCE_PREFIXES = {"var", "local", "module", "data", "path", "each", "self"}


def parse_plan_json(plan_path: str) -> tuple[dict, dict]:
    """
    Parse a `terraform show -json` plan file.

    Returns:
        resources: dict[type][name] = {config, file_path, change_action}
        references: dict[node_id] = list[node_id]  (from configuration block)
    """
    with open(plan_path) as f:
        plan = json.load(f)

    change_map: dict[str, str] = {}
    after_map: dict[str, dict] = {}
    for rc in plan.get("resource_changes", []):
        address = rc["address"]
        actions = rc.get("change", {}).get("actions", ["no-op"])
        if "create" in actions and "delete" in actions:
            change_map[address] = "replace"
        elif "create" in actions:
            change_map[address] = "create"
        elif "update" in actions:
            change_map[address] = "update"
        elif "delete" in actions:
            change_map[address] = "delete"
        else:
            change_map[address] = "no-op"
        after_map[address] = rc.get("change", {}).get("after") or {}

    resources: dict = {}
    _extract_module_resources(
        plan.get("planned_values", {}).get("root_module", {}),
        resources,
        change_map,
        after_map,
        plan_path,
    )

    references: dict = {}
    _extract_config_references(
        plan.get("configuration", {}).get("root_module", {}),
        references,
    )

    return resources, references


def _extract_module_resources(
    module: dict,
    resources: dict,
    change_map: dict,
    after_map: dict,
    plan_path: str,
) -> None:
    for resource in module.get("resources", []):
        address = resource["address"]
        rtype = resource["type"]
        rname = resource["name"]
        # after_map has fully resolved post-apply values; fall back to planned_values
        config = after_map.get(address) or resource.get("values", {})
        resources.setdefault(rtype, {})[rname] = {
            "config": config,
            "file_path": plan_path,
            "change_action": change_map.get(address, "no-op"),
        }
    for child in module.get("child_modules", []):
        _extract_module_resources(child, resources, change_map, after_map, plan_path)


def _extract_config_references(module: dict, references: dict) -> None:
    for resource in module.get("resources", []):
        node_id = f"{resource['type']}.{resource['name']}"
        refs: set[str] = set()
        _collect_expression_refs(resource.get("expressions", {}), refs)
        if refs:
            references[node_id] = list(refs)
    for child in module.get("child_modules", []):
        _extract_config_references(child, references)


def _collect_expression_refs(expressions: dict, refs: set[str]) -> None:
    if not isinstance(expressions, dict):
        return
    for value in expressions.values():
        if isinstance(value, dict):
            if "references" in value:
                for ref in value["references"]:
                    parts = ref.split(".")
                    if len(parts) >= 2 and parts[0] not in _NON_RESOURCE_PREFIXES:
                        refs.add(f"{parts[0]}.{parts[1]}")
            else:
                _collect_expression_refs(value, refs)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _collect_expression_refs(item, refs)
