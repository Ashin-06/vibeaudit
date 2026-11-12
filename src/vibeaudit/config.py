"""Project configuration: `.vibeaudit.toml`, or a `[tool.vibeaudit]` table in `pyproject.toml`.

Command line flags override the file. Keys may use dashes or underscores (`fail-on` or `fail_on`).
Unknown keys and wrong types are errors, so a typo cannot silently weaken a scan.

Note for reviewers of third-party code: the configuration lives in the scanned repository, so it can
disable rules or exclude paths. Use `--no-config` when the repository itself is not trusted.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict, Optional, Tuple

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised on 3.9 / 3.10
    import tomli as tomllib  # type: ignore[no-redef]

from .model import SEVERITIES

LIST = "list of strings"
KEYS: Dict[str, str] = {
    "exclude": LIST, "disable": LIST, "auth_helpers": LIST, "sanitizers": LIST, "public_paths": LIST,
    "fail_on": "severity or none", "min_severity": "severity", "external": "string", "baseline": "string",
    "llm": "string", "llm_model": "string", "offline": "boolean", "max_file_size": "integer",
    "llm_max_requests": "integer", "file_timeout": "number", "include_preview": "boolean",
    "gate_severe_preview": "boolean", "monorepo": "boolean",
}


class ConfigError(Exception):
    pass


def _check(key: str, value: object, where: str) -> object:
    kind = KEYS[key]
    ok = {
        LIST: isinstance(value, list) and all(isinstance(v, str) for v in value),
        "string": isinstance(value, str),
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool) and value >= 0,
        "number": isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0,
        "severity": value in SEVERITIES,
        "severity or none": value in SEVERITIES[:4] + ["none"],
    }[kind]
    if not ok:
        raise ConfigError(f"{where}: `{key}` must be a {kind}, got {value!r}")
    if key == "llm" and value not in ("gemini", "openai", "anthropic"):
        raise ConfigError(f"{where}: `llm` must be gemini, openai or anthropic")
    return value


def parse(table: dict, where: str) -> Dict[str, object]:
    if not isinstance(table, dict):
        raise ConfigError(f"{where}: the vibeaudit settings must be a table")
    out: Dict[str, object] = {}
    for raw_key, value in table.items():
        key = str(raw_key).replace("-", "_")
        if key not in KEYS:
            raise ConfigError(f"{where}: unknown setting `{raw_key}` (known: {', '.join(sorted(KEYS))})")
        out[key] = _check(key, value, where)
    return out


def load(root: Path, explicit: Optional[str] = None) -> Tuple[Dict[str, object], Optional[str]]:
    """Return (settings, path of the file they came from)."""
    if explicit:
        path = Path(explicit)
        candidates = [path]
        if not path.is_file():
            raise ConfigError(f"config file not found: {explicit}")
    else:
        candidates = [root / ".vibeaudit.toml", root / "pyproject.toml"]
    for path in candidates:
        if not path.is_file():
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (ValueError, OSError, UnicodeDecodeError) as e:
            if path.name == "pyproject.toml" and not explicit:
                continue  # someone else's broken pyproject is not our problem
            raise ConfigError(f"{path}: cannot read TOML: {e}") from None
        if path.name == "pyproject.toml":
            table = data.get("tool", {}).get("vibeaudit") if isinstance(data.get("tool"), dict) else None
            if table is None:
                if explicit:
                    raise ConfigError(f"{path}: no [tool.vibeaudit] table")
                continue
        else:
            table = data.get("tool", {}).get("vibeaudit", data) if isinstance(data.get("tool"), dict) else data
        return parse(table, str(path)), str(path)
    return {}, None


def project_options(root: str, config: Optional[str] = None, **overrides):
    """Options for scanning `root` with its own configuration file (or `config`) applied, then `overrides` on
    top. Used by the Python API, the MCP server, `vibeaudit routes` and `vibeaudit feedback`, so every entry
    point sees the same auth helpers, sanitizers, exclusions and disabled rules as `vibeaudit scan`.

    The file's `llm` keys are left out: the config is part of the scanned repository, and these entry points
    (the LSP server and watch re-scan on every edit, an agent calls the MCP tools often) have no --no-config,
    so a repository must not be able to make them send its code to a model provider on the user's key. Only
    `vibeaudit scan` reads them; pass llm= here to turn it on."""
    from .scanner import Options

    cfg, cfg_path = load(Path(root), config)
    baseline = cfg.get("baseline")
    if baseline and cfg_path:
        baseline = str(Path(cfg_path).parent / str(baseline))
    disabled = {x.strip() for d in cfg.get("disable", []) for x in str(d).split(",") if x.strip()}  # type: ignore[attr-defined]
    values = {
        "offline": bool(cfg.get("offline", False)), "excludes": list(cfg.get("exclude", [])),  # type: ignore[call-overload]
        "disabled": disabled, "min_severity": cfg.get("min_severity", "low"),  # as the CLI "external": cfg.get("external", "auto"),
        "baseline": baseline, "max_file_bytes": cfg.get("max_file_size", 1_000_000), "llm": None,
        "llm_model": cfg.get("llm_model"), "llm_max_requests": cfg.get("llm_max_requests", 10),
        "file_timeout": float(cfg.get("file_timeout", 30.0)),  # type: ignore[arg-type]
        "auth_helpers": list(cfg.get("auth_helpers", [])), "sanitizers": list(cfg.get("sanitizers", [])),  # type: ignore[call-overload]
        "public_paths": list(cfg.get("public_paths", [])),  # type: ignore[call-overload]
        "include_preview": bool(cfg.get("include_preview", False)),
        "gate_severe_preview": bool(cfg.get("gate_severe_preview", True)),
    }
    values.update(overrides)
    return Options(**values)
