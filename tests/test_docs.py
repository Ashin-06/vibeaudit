"""The documentation must match the code: every flag, rule, config key, example and input it shows."""
import re
import subprocess
import sys
from pathlib import Path

from helpers import materialize

import vibeaudit
from vibeaudit import config, plugins
from vibeaudit.cli import build_parser
from vibeaudit.rules import RULES

ROOT = Path(__file__).parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def _blocks(lang):
    return re.findall(r"```" + lang + r"\n(.*?)```", README, re.S)


def _all_flags():
    flags = set()
    parser = build_parser()
    for action in parser._actions:
        flags.update(action.option_strings)
        for sub in getattr(action, "choices", None) or {}:
            if hasattr(action.choices[sub], "_actions"):
                for a in action.choices[sub]._actions:
                    flags.update(a.option_strings)
    return flags


def test_every_flag_in_the_docs_exists():
    known = _all_flags()
    for doc in ("README.md", "CONTRIBUTING.md"):
        text = (ROOT / doc).read_text(encoding="utf-8")
        # flags written as `--flag` in prose and tables, or inside vibeaudit command lines
        mentioned = set(re.findall(r"`(--[a-z][a-z-]+)", text))
        for line in re.findall(r"^vibeaudit .*$", text, re.M):
            mentioned.update(re.findall(r"(?<![\w-])(--[a-z][a-z-]+)", line))
        pip_and_git = {"--depth", "--index-url", "--extra-index-url", "--upgrade"}
        unknown = sorted(f for f in mentioned - known - pip_and_git)
        assert unknown == [], f"{doc} mentions flags that do not exist: {unknown}"


def test_every_scan_flag_is_documented():
    scan = build_parser()._subparsers._group_actions[0].choices["scan"]  # type: ignore[union-attr]
    flags = {f for a in scan._actions for f in a.option_strings if f.startswith("--") and f != "--help"}
    missing = sorted(f for f in flags if f not in README)
    assert missing == [], f"README does not document: {missing}"


def test_rule_counts_and_catalogue_are_current():
    static = [r for r in RULES.values() if r.category != "llm-review"]
    categories = {r.category for r in static}
    assert f"{len(static)} rules in {len(categories)} categories" in README
    out = subprocess.run([sys.executable, str(ROOT / "tools" / "gen_rules_doc.py"), "--check"], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    catalogue = (ROOT / "docs" / "RULES.md").read_text(encoding="utf-8")
    assert all(f"### {rid}" in catalogue for rid in RULES)
    for rid in set(re.findall(r"\b(?:SEC|DEP|BE|FE|AUTH|CFG|LLM|QA|DATA|REL|UI|API|AI)\d{3}\b", README)):
        assert rid in RULES, f"README mentions unknown rule {rid}"


def test_config_example_parses_and_lists_every_key():
    (example,) = [b for b in _blocks("toml") if "auth-helpers" in b]
    parsed = config.parse(config.tomllib.loads(example), "README")
    assert parsed["auth_helpers"] == ["require_org_member", "withWorkspaceAuth"]
    documented = set(re.findall(r"\b([a-z]+(?:-[a-z]+)+|[a-z]+)\s*=", example)) | set(
        re.findall(r"`([a-z]+(?:-[a-z]+)*)`", README.split("Other keys:")[1].split("\n\n")[0]))
    assert {k.replace("_", "-") for k in config.KEYS} <= documented


def test_python_examples_run(tmp_path):
    plugin_src, api_src = [b for b in _blocks("python") if "route_rule" in b or "project_options" in b]
    namespace: dict = {}
    try:
        exec(compile(plugin_src, "README plugin example", "exec"), namespace)  # noqa: S102 - our own README
        assert {"ORG001", "ORG002"} <= set(plugins.REGISTRY)
    finally:
        for rid in ("ORG001", "ORG002"):
            plugins.unregister(rid)
    root = materialize("vuln_flask_llm", tmp_path)
    exec(compile(api_src.replace("path/to/project", str(root).replace("\\", "/")), "README API example", "exec"), {})  # noqa: S102


def test_action_inputs_hook_and_versions_match():
    action = (ROOT / "action.yml").read_text(encoding="utf-8")
    inputs = re.findall(r"^  ([a-z-]+):\n    description", action.split("inputs:")[1].split("outputs:")[0], re.M)
    documented = re.search(r"Inputs: (.*?)\n\n", README, re.S).group(1)  # type: ignore[union-attr]
    assert inputs and all(f"`{i}`" in documented for i in inputs), (inputs, documented)
    hooks = (ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8")
    assert re.search(r"- id: (\S+)", hooks).group(1) == "vibeaudit" and "- id: vibeaudit" in README  # type: ignore[union-attr]
    versions = set(re.findall(r"(?:@|rev: )v(\d+\.\d+\.\d+)", README))
    assert versions == {vibeaudit.__version__}, versions


def test_docs_are_plain_ascii():
    for doc in ("README.md", "CONTRIBUTING.md", "SECURITY.md", "CHANGELOG.md", "docs/RULES.md"):
        data = (ROOT / doc).read_bytes()
        assert all(b < 127 for b in data), doc
