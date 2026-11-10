"""vibeaudit: security and quality audit for AI-generated and LLM-powered applications.

Library use:

    from vibeaudit import scan, Options
    result = scan("path/to/project", Options(offline=True))
    for finding in result.findings:
        print(finding.severity, finding.rule_id, finding.file, finding.line, finding.message)

Custom rules: see `vibeaudit.plugins` (`rule`, `route_rule`, `file_rule`).
"""

__version__ = "0.3.0"

__all__ = ["__version__", "scan", "Options", "Result", "Finding", "Route", "rule", "route_rule", "file_rule"]


def __getattr__(name):  # lazy, so `import vibeaudit` stays cheap
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
