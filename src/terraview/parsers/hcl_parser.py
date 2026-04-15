import hcl2
from pathlib import Path


def parse_hcl_directory(path: str) -> dict:
    """Parse all .tf files in a directory into a unified resource map."""
    resources = {}
    tf_files = list(Path(path).rglob("*.tf"))

    if not tf_files:
        raise FileNotFoundError(f"No .tf files found in {path}")

    for tf_file in tf_files:
        parsed = _parse_file(tf_file)
        for resource_block in parsed.get("resource", []):
            for resource_type, instances in resource_block.items():
                if resource_type not in resources:
                    resources[resource_type] = {}
                for resource_name, config in instances.items():
                    resources[resource_type][resource_name] = {
                        "config": config,
                        "file_path": str(tf_file),
                    }

    return resources


def _parse_file(file_path: Path) -> dict:
    """Parse a single .tf file."""
    with open(file_path, "r") as f:
        try:
            return hcl2.load(f)
        except Exception as e:
            print(f"Warning: could not parse {file_path}: {e}")
            return {}
