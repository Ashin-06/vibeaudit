"""Parse every YAML file that GitHub or pre-commit loads (action.yml, .pre-commit-hooks.yaml, workflows) with
a real YAML parser. An invalid action.yml cannot be loaded by any workflow that uses the action, and nothing
else in the test suite would notice. Needs PyYAML (installed only in the CI step that runs this)."""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    files = [ROOT / "action.yml", ROOT / ".pre-commit-hooks.yaml"] + sorted((ROOT / ".github").rglob("*.yml"))
    bad = 0
    for f in files:
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except yaml.YAMLError as e:
            print(f"{f.relative_to(ROOT)}: invalid YAML: {e}".replace("\n", " "))
            bad += 1
            continue
        if not isinstance(data, (dict, list)):
            print(f"{f.relative_to(ROOT)}: not a YAML mapping or list")
            bad += 1
    if not bad:
        print(f"ok: {len(files)} YAML files parse")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
