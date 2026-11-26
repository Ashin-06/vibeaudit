"""`vibeaudit init`: create starter configuration, pre-commit hook and CI workflow in one step."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from . import __version__
from .files import Project
from .scanner import _stack

STARTER_CONFIG = """# vibeaudit configuration (see README.md#configuration)
fail-on = "high"
min-severity = "low"
exclude = ["dist/**", "build/**", "vendor/**"]
disable = []

# Project conventions (examples):
# auth-helpers = ["require_org_member", "withWorkspaceAuth"]
# sanitizers = ["clean_sql_input"]
# public-paths = ["/api/health", "/api/public/*"]
"""


def _precommit_yaml(version: str) -> str:
    return (
        "repos:\n"
        "  - repo: https://github.com/Ashin-06/vibeaudit\n"
        f"    rev: v{version}\n"
        "    hooks:\n"
        "      - id: vibeaudit\n"
    )


def _github_workflow(version: str) -> str:
    return (
        "name: vibeaudit\n"
        "on: [push, pull_request]\n"
        "permissions:\n"
        "  contents: read\n"
        "  security-events: write\n"
        "jobs:\n"
        "  audit:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v5\n"
        "        with:\n"
        "          fetch-depth: 0\n"
        f"      - uses: Ashin-06/vibeaudit@v{version}\n"
        "        with:\n"
        "          fail-on: high\n"
        "      - uses: github/codeql-action/upload-sarif@v3\n"
        "        if: always()\n"
        "        with:\n"
        "          sarif_file: vibeaudit.sarif\n"
    )


def _gitlab_ci(version: str) -> str:
    return (
        "include:\n"
        f"  - remote: https://raw.githubusercontent.com/Ashin-06/vibeaudit/v{version}/ci/gitlab-ci.yml\n"
    )


def _circleci_config(version: str) -> str:
    return (
        "version: 2.1\n"
        "jobs:\n"
        "  vibeaudit:\n"
        "    docker:\n"
        "      - image: cimg/python:3.12\n"
        "    steps:\n"
        "      - checkout\n"
        "      - run:\n"
        "          name: Install and scan with vibeaudit\n"
        "          command: |\n"
        f'            python -m pip install --quiet "vibeaudit @ git+https://github.com/Ashin-06/vibeaudit.git@v{version}"\n'
        "            vibeaudit scan . --fail-on high --no-color\n"
        "workflows:\n"
        "  audit:\n"
        "    jobs:\n"
        "      - vibeaudit\n"
    )


def run(root: Path, ci: str = "github", hook: bool = True, force: bool = False) -> Dict[str, Any]:
    """Write starter `.vibeaudit.toml`, pre-commit hook and CI template without overwriting unless `force=True`."""
    project = Project(root)
    stack = _stack(project)
    targets: List[tuple] = [(".vibeaudit.toml", STARTER_CONFIG)]
    if hook:
        targets.append((".pre-commit-config.yaml", _precommit_yaml(__version__)))
    if ci == "github":
        targets.append((".github/workflows/vibeaudit.yml", _github_workflow(__version__)))
    elif ci == "gitlab":
        targets.append((".gitlab-ci.yml", _gitlab_ci(__version__)))
    elif ci == "circleci":
        targets.append((".circleci/config.yml", _circleci_config(__version__)))

    created: List[str] = []
    skipped: List[Dict[str, str]] = []
    for rel, content in targets:
        dest = root / rel
        if dest.exists() and not force:
            reason = "already exists"
            try:
                if rel == ".pre-commit-config.yaml" and "vibeaudit" in dest.read_text(encoding="utf-8", errors="replace"):
                    reason = "already configures vibeaudit"
            except OSError:
                pass
            skipped.append({"file": rel, "reason": reason})
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8", newline="\n")
        created.append(rel)
    return {"root": str(root), "stack": stack, "created": created, "skipped": skipped}
