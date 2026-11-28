"""Run established scanners when they are installed and fold their results into the report.

vibeaudit does not reimplement what gitleaks, osv-scanner, bandit and semgrep already do well;
it orchestrates them, normalises the output, and removes duplicates of its own findings.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Optional

from .heuristics import mask
from .model import Finding
from .store import loads_json

TOOLS = ("gitleaks", "osv-scanner", "bandit", "semgrep")
NEEDS_NETWORK = {"osv-scanner", "semgrep"}
TIMEOUT = 600
MAX_ISOLATION_STAGE_FILES = 5_000
MAX_ISOLATION_STAGE_BYTES = 50 * 1024 * 1024
_STAGE_SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "build", "dist", "__pycache__", ".semgrep",
}
_SEMGREP_IGNORE_NAMES = {".semgrepignore", ".gitignore", ".semgrep.yml", ".semgrep.yaml"}
LAST_ISOLATION: Dict[str, Dict[str, str]] = {}


def _rel(root: Path, path: str) -> str:
    p = Path(path)
    if not p.is_absolute():
        p = root / p
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(path).as_posix()


def _default_run(cmd: List[str], cwd: Optional[str] = None) -> Optional[str]:
    try:
        out = subprocess.run(cmd, capture_output=True, stdin=subprocess.DEVNULL, cwd=cwd, timeout=TIMEOUT, check=False)  # noqa: S603 - fixed binary + arguments in caller
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.decode("utf-8", "replace")


_run = _default_run


def _invoke_run(cmd: List[str], cwd: Optional[Path] = None) -> Optional[str]:
    if cwd is not None and _run is _default_run:
        return _default_run(cmd, cwd=str(cwd))
    return _run(cmd)


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


def detect_repo_configs(root: Path) -> Dict[str, List[str]]:
    """Detect repo-local configuration or ignore files that external scanners may honor."""
    found: Dict[str, List[str]] = {}

    def _add(tool: str, rel: str) -> None:
        bucket = found.setdefault(tool, [])
        if rel not in bucket:
            bucket.append(rel)

    for rel in (".gitleaks.toml", "gitleaks.toml", ".gitleaksignore"):
        if (root / rel).exists():
            _add("gitleaks", rel)
    for rel in (".bandit", "bandit.yaml", "bandit.yml"):
        if (root / rel).exists():
            _add("bandit", rel)
    pyp = root / "pyproject.toml"
    if pyp.is_file():
        try:
            text = pyp.read_text(encoding="utf-8", errors="ignore")
            if "[tool.bandit]" in text:
                _add("bandit", "pyproject.toml [tool.bandit]")
        except OSError:
            pass
    for rel in (".semgrepignore", ".semgrep.yml", ".semgrep.yaml", ".semgrep"):
        if (root / rel).exists():
            _add("semgrep", rel)
    try:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in _STAGE_SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))
            )
            if ".semgrepignore" in filenames:
                rel_path = Path(dirpath).relative_to(root) / ".semgrepignore"
                _add("semgrep", rel_path.as_posix())
    except OSError:
        pass
    if (root / "osv-scanner.toml").exists():
        _add("osv-scanner", "osv-scanner.toml")
    return found


def _stage_semgrep_tree(root: Path, dest: Path) -> Optional[str]:
    """Stage regular repository files into `dest` omitting repo-controlled Semgrep config/ignore files."""
    file_count = 0
    total_bytes = 0
    try:
        dest.mkdir(parents=True, exist_ok=True)
        for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
            dirnames[:] = sorted(
                d for d in dirnames
                if d not in _STAGE_SKIP_DIRS and not os.path.islink(os.path.join(dirpath, d))
            )
            rel_dir = os.path.relpath(dirpath, root)
            for fname in sorted(filenames):
                if fname in _SEMGREP_IGNORE_NAMES:
                    continue
                src = Path(dirpath) / fname
                if src.is_symlink() or not src.is_file():
                    continue
                st = src.stat()
                file_count += 1
                total_bytes += st.st_size
                if file_count > MAX_ISOLATION_STAGE_FILES or total_bytes > MAX_ISOLATION_STAGE_BYTES:
                    return "repository exceeded staging limit"
                out_dir = dest if rel_dir == "." else dest / rel_dir
                out_dir.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, out_dir / fname)
        (dest / ".semgrepignore").write_text("", encoding="utf-8")
    except OSError as exc:
        return f"staging failed ({exc})"
    return None


def run_tool(name: str, root: Path, no_config: bool = False) -> Optional[List[Finding]]:
    """Run an external scanner. When `no_config` is True, isolate it from repo-committed ignore/config files."""
    if name == "gitleaks":
        LAST_ISOLATION["gitleaks"] = {
            "isolation": "full" if no_config else "none",
            "detail": "default config, empty ignore file, --ignore-gitleaks-allow" if no_config else "project config enabled",
        }
        with tempfile.TemporaryDirectory() as tmp:
            report = os.path.join(tmp, "gitleaks.json")
            base = ["--report-format", "json", "--report-path", report, "--exit-code", "0", "--no-banner"]
            if no_config:
                gl_cfg = Path(tmp) / "gitleaks.toml"
                gl_cfg.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
                gl_ignore = Path(tmp) / ".gitleaksignore"
                gl_ignore.write_text("", encoding="utf-8")
                extra = ["--config", str(gl_cfg), "--gitleaks-ignore-path", str(gl_ignore), "--ignore-gitleaks-allow"]
            else:
                extra = []
            _invoke_run(["gitleaks", "dir", str(root)] + extra + base)
            if not os.path.exists(report):
                _invoke_run(["gitleaks", "detect", "--no-git", "--source", str(root)] + extra + base)
            try:
                data = loads_json(Path(report).read_text(encoding="utf-8") or "[]")
            except (OSError, ValueError):
                return None
        return parse_gitleaks(data, root)
    parse_root = root
    if name == "bandit":
        LAST_ISOLATION["bandit"] = {
            "isolation": "full" if no_config else "none",
            "detail": "temporary empty skips config" if no_config else "project config enabled",
        }
        excl = ",".join(str(root / d) for d in ("node_modules", ".venv", "venv", "tests", "test", "build", "dist"))
        if no_config:
            with tempfile.TemporaryDirectory() as tmp:
                cfg = Path(tmp) / "bandit.yaml"
                cfg.write_text("skips: []\n", encoding="utf-8")
                raw = _invoke_run(["bandit", "-c", str(cfg), "-r", str(root), "-f", "json", "-q", "-x", excl])
        else:
            raw = _invoke_run(["bandit", "-r", str(root), "-f", "json", "-q", "-x", excl])
    elif name == "semgrep":
        base_cmd = ["semgrep", "scan", "--config", "p/default", "--json", "--metrics", "off", "--quiet"]
        if no_config:
            semgrep_cfgs = detect_repo_configs(root).get("semgrep", [])
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                if semgrep_cfgs:
                    stage_dir = tmp_path / "repo"
                    stage_err = _stage_semgrep_tree(root, stage_dir)
                    if stage_err is None:
                        LAST_ISOLATION["semgrep"] = {
                            "isolation": "full",
                            "detail": "staged shadow tree omitting repo .semgrepignore/.semgrep configs",
                        }
                        parse_root = stage_dir.resolve()
                        raw = _invoke_run(base_cmd + ["--no-git-ignore", str(stage_dir)], cwd=stage_dir)
                    else:
                        LAST_ISOLATION["semgrep"] = {
                            "isolation": "partial",
                            "detail": f"repo contains .semgrepignore and {stage_err}",
                        }
                        raw = _invoke_run(base_cmd + ["--no-git-ignore", str(root)], cwd=tmp_path)
                else:
                    LAST_ISOLATION["semgrep"] = {
                        "isolation": "full",
                        "detail": "--no-git-ignore with isolated working directory (no repo .semgrepignore)",
                    }
                    raw = _invoke_run(base_cmd + ["--no-git-ignore", str(root)], cwd=tmp_path)
        else:
            LAST_ISOLATION["semgrep"] = {"isolation": "none", "detail": "project config enabled"}
            raw = _invoke_run(base_cmd + [str(root)])
    elif name == "osv-scanner":
        LAST_ISOLATION["osv-scanner"] = {
            "isolation": "full" if no_config else "none",
            "detail": "temporary empty osv-scanner.toml" if no_config else "project config enabled",
        }
        if no_config:
            with tempfile.TemporaryDirectory() as tmp:
                cfg = Path(tmp) / "osv-scanner.toml"
                cfg.write_text("", encoding="utf-8")
                raw = _invoke_run(["osv-scanner", "scan", "source", "-r", "--config", str(cfg), "--format", "json", str(root)])
                if not raw or not raw.lstrip().startswith("{"):
                    raw = _invoke_run(["osv-scanner", "--config", str(cfg), "--format", "json", "-r", str(root)])
        else:
            raw = _invoke_run(["osv-scanner", "scan", "source", "-r", "--format", "json", str(root)])
            if not raw or not raw.lstrip().startswith("{"):
                raw = _invoke_run(["osv-scanner", "--format", "json", "-r", str(root)])
    else:
        return None
    if not raw:
        return None
    try:
        data = loads_json(raw[raw.index("{"):])
    except ValueError:
        return None
    return PARSERS[name](data, parse_root)
