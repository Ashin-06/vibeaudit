"""Java and Kotlin configuration checks (preview): JAVA002-JAVA004.

JAVA002: Spring Boot Actuator endpoints exposed (`include=*`, or env/heapdump/... without security), or shutdown on.
JAVA003: a Spring Security chain that permits every request.
JAVA004: polymorphic deserialization left open (Jackson default typing, class-based type ids, XStream without an
allow-list).
"""
from __future__ import annotations

import re
from typing import Callable

from .files import Project, SourceFile
from .guard import finditer

Add = Callable[..., None]  # JvmScanner.add(sf, rule, line, message, severity="")

CONFIG_FILE = re.compile(r"(?:^|/)(?:application|bootstrap)(?:-[\w.]+)?\.(?:properties|ya?ml)$")
EXPOSE_PROP = re.compile(r"(?m)^[ \t]*management\.endpoints\.web\.exposure\.include[ \t]*[:=][ \t]*([^\n#]{1,200})")
# YAML: `exposure:` then, within a few lines, `include: "*"` or `include: env,health` or a `- env` list
EXPOSE_YAML = re.compile(r"(?m)^[ \t]*exposure:[ \t]*\n(?:[ \t]+[^\n]*\n){0,3}?[ \t]+include:[ \t]*((?:[^\n#]{1,200})|(?:\n[ \t]+-[^\n]{1,60}){1,12})")
SENSITIVE = re.compile(r"(?i)\*|\b(?:env|heapdump|threaddump|configprops|beans|logfile|shutdown|mappings|loggers|jolokia|httpexchanges|httptrace)\b")
SHUTDOWN = re.compile(r"(?m)^[ \t]*(?:management\.endpoint\.shutdown\.(?:enabled|access)[ \t]*[:=][ \t]*(?:true|unrestricted)"
                      r"|shutdown:\s*\n[ \t]+(?:enabled:[ \t]*true|access:[ \t]*unrestricted))")

PERMIT_ALL = re.compile(
    r"\banyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)"
    r"|\b(?:requestMatchers|antMatchers|mvcMatchers)\s*\(\s*\"/\*\*\"\s*\)\s*\.\s*permitAll\s*\(\s*\)"
    r"|\bauthorize\s*\(\s*(?:anyRequest|\"/\*\*\")\s*,\s*permitAll\s*\)"
    r"|\bignoring\s*\(\s*\)\s*\.\s*(?:requestMatchers|antMatchers)\s*\(\s*\"/\*\*\"\s*\)")

DEFAULT_TYPING = re.compile(r"\.\s*(?:enableDefaultTyping|activateDefaultTyping(?:AsProperty)?)\s*\(|\bJsonTypeInfo\s*\.\s*Id\s*\.\s*(?:CLASS|MINIMAL_CLASS)\b")
SAFE_TYPING = re.compile(r"\bBasicPolymorphicTypeValidator\b|\bPolymorphicTypeValidator\b(?![^;\n]{0,80}LaissezFaire)")
XSTREAM = re.compile(r"\bnew\s+XStream\s*\(|\bXStream\s*\(")
XSTREAM_SAFE = re.compile(r"\.\s*(?:allowTypes\w*|addPermission|setupDefaultSecurity|denyTypes\w*)\s*\(")


def run(project: Project, security_present: bool, add: Add) -> None:
    for sf in project.files:
        if sf.text is None or sf.is_test or sf.is_example:
            continue
        if CONFIG_FILE.search(sf.rel):
            _actuator(sf, security_present, add)
        elif sf.rel.endswith((".java", ".kt", ".kts")):
            _code(sf, add)


def _actuator(sf: SourceFile, security_present: bool, add: Add) -> None:
    text = sf.text or ""
    if "management" not in text:
        return
    for m in list(finditer(EXPOSE_PROP, text)) + list(finditer(EXPOSE_YAML, text)):
        value = m.group(1)
        hits = SENSITIVE.findall(value)
        if hits and ("*" in hits or not security_present):
            add(sf, "JAVA002", sf.line_at(m.start()),
                f"Actuator exposes {', '.join(sorted(set(h.strip() for h in hits)))} over HTTP"
                + ("" if security_present else " and the project has no Spring Security configuration")
                + ": these endpoints reveal configuration and secrets, or dump the heap.")
    for m in finditer(SHUTDOWN, text):
        add(sf, "JAVA002", sf.line_at(m.start()), "The Actuator shutdown endpoint is enabled: one request stops the application.")


def _code(sf: SourceFile, add: Add) -> None:
    text = sf.text or ""
    for m in finditer(PERMIT_ALL, text):
        add(sf, "JAVA003", sf.line_at(m.start()),
            "The security chain permits every request, so no endpoint needs a login unless it checks one itself.")
    if DEFAULT_TYPING.search(text) and not SAFE_TYPING.search(text):
        m = DEFAULT_TYPING.search(text)
        add(sf, "JAVA004", sf.line_at(m.start()),  # type: ignore[union-attr]
            "Jackson reads class names from the JSON (default typing or class-based type ids) with no allow-list of "
            "subtypes: a gadget class in the classpath gives remote code execution.")
    if XSTREAM.search(text) and not XSTREAM_SAFE.search(text):
        m = XSTREAM.search(text)
        add(sf, "JAVA004", sf.line_at(m.start()),  # type: ignore[union-attr]
            "XStream deserializes any type here (no allowTypes or setupDefaultSecurity): untrusted XML gives remote code execution.")
