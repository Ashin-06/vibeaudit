"""Run established scanners when they are installed and fold their results into the report.

vibeaudit does not reimplement what gitleaks, osv-scanner, bandit and semgrep already do well;
it orchestrates them, normalises the output, and removes duplicates of its own findings.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .heuristics import mask
from .model import Finding

TOOLS = ("gitleaks", "osv-scanner", "bandit", "semgrep")
NEEDS_NETWORK = {"osv-scanner", "semgrep"}
TIMEOUT = 600


def _rel(root: Path, path: str) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = root / p
    try:
        return p.resolve().relative_to(root).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


def _run(cmd: List[str]) -> Optional[str]:
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=TIMEOUT, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.decode("utf-8", "replace")


# ---------------------------------------------------------------- parsers
def parse_gitleaks(data: list, root: Path) -> List[Finding]:
    out = []
    for r in data or []:
        secret = str(r.get("Secret", ""))
        line = str(r.get("Line") or r.get("Match") or "").strip()
        if secret:
            line = line.replace(secret, mask(secret))
        out.append(Finding(
            "gitleaks:" + str(r.get("RuleID", "secret")), _rel(root, str(r.get("File", ""))), int(r.get("StartLine") or 1),
            str(r.get("Description") or "Secret detected"), "high", line[:200], source="gitleaks",
            title=str(r.get("Description") or "Secret detected"), category="secrets",
            why="gitleaks matched a known credential format.", fix="Revoke and rotate the credential, then remove it from git history."))
    return out


# Bandit checks that a built-in rule already covers with data flow (and therefore with fewer false
# alarms). When vibeaudit decides such a line is safe, bandit must not bring the alarm back.
BANDIT_COVERED = {
    "B101",  # assert: not a security issue in application code
    "B102", "B307",  # exec / eval -> BE003, LLM002
    "B201",  # flask debug=True -> BE011
    "B301", "B506",  # pickle / yaml.load -> BE004
    "B501",  # requests verify=False -> BE013
    "B602", "B605",  # shell=True / os.system -> BE002
    "B608",  # SQL built from strings -> BE001 (knows placeholder-only formatting is safe)
}


def parse_bandit(data: dict, root: Path) -> List[Finding]:
    out = []
    sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    for r in (data or {}).get("results", []):
        if r.get("test_id") in BANDIT_COVERED or r.get("issue_confidence") == "LOW" or r.get("issue_severity") == "LOW":
            continue
        cwe = (r.get("issue_cwe") or {}).get("id")
        out.append(Finding(
            "bandit:" + str(r.get("test_id")), _rel(root, str(r.get("filename", ""))), int(r.get("line_number") or 1),
            str(r.get("issue_text", "")), sev_map.get(str(r.get("issue_severity")), "medium"),
            str(r.get("code", "")).strip().split("\n")[0][:200], source="bandit",
            title=str(r.get("test_name", "bandit finding")).replace("_", " "), category="backend",
            why=str(r.get("issue_text", "")), fix="See " + str(r.get("more_info", "the bandit documentation")),
            cwe=f"CWE-{cwe}" if cwe else ""))
    return out


def parse_semgrep(data: dict, root: Path) -> List[Finding]:
    out = []
    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    for r in (data or {}).get("results", []):
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        cwe = meta.get("cwe")
        cwe = cwe[0] if isinstance(cwe, list) and cwe else cwe or ""
        check = str(r.get("check_id", "semgrep"))
        out.append(Finding(
            "semgrep:" + check.rsplit(".", 1)[-1], _rel(root, str(r.get("path", ""))), int((r.get("start") or {}).get("line") or 1),
            str(extra.get("message", "")).strip()[:400], sev_map.get(str(extra.get("severity")), "medium"),
            str(extra.get("lines", "")).strip().split("\n")[0][:200], source="semgrep",
            title=check.rsplit(".", 1)[-1].replace("-", " "), category="backend",
            why=str(extra.get("message", "")).strip()[:400], fix=str(extra.get("fix") or "See the semgrep rule documentation: " + check),
            cwe=str(cwe).split(":")[0]))
    return out


def parse_osv_scanner(data: dict, root: Path) -> List[Finding]:
    out = []
    sev_map = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}
    order = ["critical", "high", "medium", "low"]
    for res in (data or {}).get("results", []):
        src = _rel(root, str((res.get("source") or {}).get("path", "")))
        for pkg in res.get("packages", []):
            info = pkg.get("package") or {}
            vulns = pkg.get("vulnerabilities") or []
            if not vulns:
                continue
            sev = "low"
            for v in vulns:
                s = sev_map.get(str((v.get("database_specific") or {}).get("severity", "")).upper(), "high")
                sev = s if order.index(s) < order.index(sev) else sev
            ids = ", ".join(sorted(v.get("id", "?") for v in vulns)[:6])
            out.append(Finding(
                "osv-scanner:vulnerable-package", src, 1,
                f"{info.get('name')} {info.get('version')} has {len(vulns)} known vulnerabilities ({ids}).", sev,
                source="osv-scanner", title="Dependency with known vulnerabilities", category="supply-chain",
                why="The resolved version has published security advisories.", fix="Upgrade to a fixed version."))
    return out


PARSERS: Dict[str, Callable] = {"gitleaks": parse_gitleaks, "bandit": parse_bandit, "semgrep": parse_semgrep,
                                "osv-scanner": parse_osv_scanner}


def available(name: str) -> bool:
    return shutil.which(name) is not None


def run_tool(name: str, root: Path) -> Optional[List[Finding]]:
    if name == "gitleaks":
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "gitleaks.json")
            base = ["--report-format", "json", "--report-path", report, "--exit-code", "0", "--no-banner"]
            _run(["gitleaks", "dir", str(root)] + base)
            if not os.path.exists(report):
                _run(["gitleaks", "detect", "--no-git", "--source", str(root)] + base)
            try:
                data = json.loads(Path(report).read_text(encoding="utf-8") or "[]")
            except (OSError, ValueError):
                return None
        return parse_gitleaks(data, root)
    if name == "bandit":
        raw = _run(["bandit", "-r", str(root), "-f", "json", "-q", "-x", ",".join(
            str(root / d) for d in ("node_modules", ".venv", "venv", "tests", "test", "build", "dist"))])
    elif name == "semgrep":
        raw = _run(["semgrep", "scan", "--config", "p/default", "--json", "--metrics", "off", "--quiet", str(root)])
    elif name == "osv-scanner":
        raw = _run(["osv-scanner", "scan", "source", "-r", "--format", "json", str(root)])
        if not raw or not raw.lstrip().startswith("{"):
            raw = _run(["osv-scanner", "--format", "json", "-r", str(root)])
    else:
        return None
    if not raw:
        return None
    try:
        data = json.loads(raw[raw.index("{"):])
    except ValueError:
        return None
    return PARSERS[name](data, root)
