"""vibeaudit: security and quality audit for AI-generated and LLM-powered applications.

Library use:

    from vibeaudit import scan, project_options
    result = scan("path/to/project")  # the project's .vibeaudit.toml / [tool.vibeaudit] applies
    result = scan("path/to/project", project_options("path/to/project", offline=True))  # with overrides
    for finding in result.findings:
        print(finding.severity, finding.rule_id, finding.file, finding.line, finding.message)

An explicit `Options(...)` is used exactly as given, without the project's configuration file.
Custom rules: see `vibeaudit.plugins` (`rule`, `route_rule`, `file_rule`).
"""

__version__ = "0.8.4"

__all__ = ["__version__", "scan", "Options", "project_options", "Result", "Finding", "Route", "rule", "route_rule", "file_rule"]


def __getattr__(name):  # lazy, so `import vibeaudit` stays cheap
    if name == "project_options":
        from .config import project_options

        return project_options
    if name in ("scan", "Options"):
        from . import scanner

        return getattr(scanner, name)
    if name == "Result":
        from .report import Result

        return Result
    if name in ("Finding", "Route"):
        from . import model

        return getattr(model, name)
    if name in ("rule", "route_rule", "file_rule"):
        from . import plugins

        return getattr(plugins, name)
    raise AttributeError(f"module 'vibeaudit' has no attribute {name!r}")
