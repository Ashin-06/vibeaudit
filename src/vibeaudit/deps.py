"""Dependency checks: hallucinated packages (registry lookups), typosquats, new packages and known CVEs (OSV)."""
from __future__ import annotations

import datetime as dt
import gzip
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from importlib import resources
from typing import Callable, Dict, List, Optional, Set, Tuple

from .files import Project, SourceFile
from .model import Finding

try:  # Python 3.11+
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - exercised on 3.9 / 3.10
    import tomli as tomllib  # type: ignore[no-redef]

Emit = Callable[[Finding], None]
USER_AGENT = "vibeaudit (+https://github.com/Ashin-06/vibeaudit)"
TIMEOUT = 10
NEW_PACKAGE_DAYS = 30


@dataclass
class Dep:
    name: str
    ecosystem: str  # "PyPI" or "npm"
    file: str
    line: int
    version: Optional[str] = None  # exact pinned version, when known
    checkable: bool = True  # False for private registries, git/file/url specs


def pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _load_popular(fn: str) -> List[str]:
    data = resources.files("vibeaudit").joinpath("data", fn).read_bytes()
    return gzip.decompress(data).decode("utf-8").split()


_POPULAR: Dict[str, Tuple[Set[str], List[str]]] = {}


def popular(ecosystem: str) -> Tuple[Set[str], List[str]]:
    """(every known-popular name, the most popular names that typosquatters target)."""
    if ecosystem not in _POPULAR:
        names = _load_popular("pypi_top.txt.gz" if ecosystem == "PyPI" else "npm_top.txt.gz")
        if ecosystem == "PyPI":
            names = [pep503(n) for n in names]
        _POPULAR[ecosystem] = (set(names), names[:3000])
    return _POPULAR[ecosystem]


def edit_distance_one(a: str, b: str) -> bool:
    """True when a and b differ by one insert, delete, substitution or adjacent swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i:] == b[i + 1:]


def typosquat_target(name: str, ecosystem: str) -> Optional[str]:
    known, targets = popular(ecosystem)
    key = pep503(name) if ecosystem == "PyPI" else name.lower()
    if key in known or len(key) < 5:
        return None
    scoped = key.startswith("@")
    squashed = re.sub(r"[-_.]", "", key)
    for t in targets:
        if t.startswith("@") != scoped or len(t) < 5:
            continue
        if edit_distance_one(key, t) or (squashed == re.sub(r"[-_.]", "", t) and key != t):
            return t
    return None


# ------------------------------------------------------------------ parsing
REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _line_of(sf: SourceFile, needle: str) -> int:
    rx = re.compile(r"(?<![\w.@/-])" + re.escape(needle) + r"(?![\w-])", re.I)
    for i, ln in enumerate(sf.lines, 1):
        if rx.search(ln):
            return i
    return 1


def parse_requirement(spec: str) -> Optional[Tuple[str, Optional[str]]]:
    spec = spec.split("#", 1)[0].split(";", 1)[0].strip()
    if not spec or spec.startswith("-") or "://" in spec or spec.startswith((".", "/", "git+")) or " @ " in spec:
        return None
    m = REQ_LINE.match(spec)
    if not m:
        return None
    rest = m.group(3).strip()
    pin = re.fullmatch(r"===?\s*([A-Za-z0-9.+!_-]+)", rest)
    return m.group(1), (pin.group(1) if pin else None)


def collect(project: Project) -> List[Dep]:
    deps: List[Dep] = []
    npm_private_scopes: Set[str] = set()
    for f in project.files:
        if f.rel.rsplit("/", 1)[-1] == ".npmrc" and f.text:
            npm_private_scopes |= set(re.findall(r"^\s*(@[\w-]+):registry\s*=", f.text, re.M))
    for f in project.files:
        if f.text is None or f.is_test:
            continue
        name = f.rel.rsplit("/", 1)[-1]
        if re.fullmatch(r"requirements[\w.-]*\.(?:txt|in)", name) or re.search(r"(?:^|/)requirements/[^/]+\.txt$", f.rel):
            private = bool(re.search(r"^\s*--(?:index-url|extra-index-url)|^\s*-i\s", f.text, re.M))
            for i, line in enumerate(f.lines, 1):
                parsed = parse_requirement(line)
                if parsed:
                    deps.append(Dep(parsed[0], "PyPI", f.rel, i, parsed[1], not private))
        elif name == "pyproject.toml":
            try:
                data = tomllib.loads(f.text)
            except (ValueError, TypeError):
                continue
            specs: List[str] = list(data.get("project", {}).get("dependencies", []) or [])
            for group in (data.get("project", {}).get("optional-dependencies", {}) or {}).values():
                specs += list(group or [])
            for group in (data.get("dependency-groups", {}) or {}).values():
                specs += [s for s in group or [] if isinstance(s, str)]
            poetry = data.get("tool", {}).get("poetry", {})
            pnames = list((poetry.get("dependencies") or {}).keys())
            for grp in (poetry.get("group") or {}).values():
                pnames += list((grp.get("dependencies") or {}).keys())
            specs += [n for n in pnames if n.lower() != "python"]
            own = pep503(str(data.get("project", {}).get("name", "") or poetry.get("name", "")))
            for spec in specs:
                parsed = parse_requirement(str(spec))
                if parsed and pep503(parsed[0]) != own:
                    deps.append(Dep(parsed[0], "PyPI", f.rel, _line_of(f, parsed[0]), parsed[1]))
        elif name == "package.json":
            try:
                data = json.loads(f.text)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            locked = _npm_lock_versions(project, f)
            for key in ("dependencies", "devDependencies", "optionalDependencies"):
                section = data.get(key)
                if not isinstance(section, dict):
                    continue
                for dep, ver in section.items():
                    ver = str(ver)
                    real = dep
                    if ver.startswith("npm:"):
                        real = ver[4:].rsplit("@", 1)[0] if ver[4:].count("@") > (1 if ver[4:].startswith("@") else 0) else ver[4:]
                    ok = not re.match(r"(?:file|link|workspace|portal|git|git\+\w+|github|https?):", ver) and "/" not in ver.split("@")[0]
                    scope = real.split("/")[0] if real.startswith("@") else ""
                    if scope in npm_private_scopes:
                        ok = False
                    exact = locked.get(dep) or (ver if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", ver) else None)
                    deps.append(Dep(real, "npm", f.rel, _line_of(f, '"' + dep + '"'), exact, ok))
    return deps


def _npm_lock_versions(project: Project, pkg: SourceFile) -> Dict[str, str]:
    base = pkg.rel.rsplit("/", 1)[0] + "/" if "/" in pkg.rel else ""
    path = project.root / (base + "package-lock.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out: Dict[str, str] = {}
    for key, val in (data.get("packages") or {}).items():
        if key.startswith("node_modules/") and key.count("node_modules/") == 1 and isinstance(val, dict) and "version" in val:
            out[key[len("node_modules/"):]] = str(val["version"])
    for key, val in (data.get("dependencies") or {}).items():
        if isinstance(val, dict) and "version" in val:
            out.setdefault(key, str(val["version"]))
    return out


# ------------------------------------------------------------------ network
def _get_json(url: str, data: Optional[bytes] = None) -> Tuple[int, Optional[dict]]:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, "Accept": "application/json",
                                                          **({"Content-Type": "application/json"} if data else {})})
    for attempt in range(2):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 - fixed https hosts
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                return e.code, None
            if attempt:
                return e.code, None
        except (urllib.error.URLError, OSError, ValueError):
            if attempt:
                return 0, None
    return 0, None


def registry_info(dep: Dep) -> Tuple[str, Optional[dt.datetime], str]:
    """Return (status, first_release, note); status is ok | missing | malware | error."""
    if dep.ecosystem == "PyPI":
        code, data = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(pep503(dep.name))}/json")
        if code in (404, 410):
            return "missing", None, ""
        if not data:
            return "error", None, ""
        times = [f.get("upload_time_iso_8601") for files in (data.get("releases") or {}).values() for f in files]
        times = [t for t in times if t]
        first = min(times) if times else None
        return "ok", _parse_time(first), ""
    code, data = _get_json("https://registry.npmjs.org/" + dep.name.replace("/", "%2F"))
    if code in (404, 410):
        return "missing", None, ""
    if not data:
        return "error", None, ""
    latest = (data.get("dist-tags") or {}).get("latest", "")
    if latest == "0.0.1-security" or "security holding" in str(data.get("description", "")).lower():
        return "malware", None, "removed from npm for security reasons (malware)"
    return "ok", _parse_time((data.get("time") or {}).get("created")), ""


def _parse_time(s: Optional[str]) -> Optional[dt.datetime]:
    if not s:
        return None
    try:
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)


OSV_SEV = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def osv_lookup(deps: List[Dep]) -> Dict[Tuple[str, str, str], List[dict]]:
    pinned = [d for d in deps if d.version and d.checkable]
    uniq = sorted({(d.ecosystem, d.name, d.version) for d in pinned})  # type: ignore[misc]
    out: Dict[Tuple[str, str, str], List[dict]] = {}
    if not uniq:
        return out
    ids_for: Dict[Tuple[str, str, str], List[str]] = {}
    for i in range(0, len(uniq), 500):
        chunk = uniq[i:i + 500]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in chunk]}).encode()
        code, data = _get_json("https://api.osv.dev/v1/querybatch", body)
        if not data:
            raise ConnectionError("OSV query failed")
        for key, res in zip(chunk, data.get("results", [])):
            ids = [v["id"] for v in (res or {}).get("vulns", []) if "id" in v]
            if ids:
                ids_for[key] = ids
    all_ids = sorted({i for ids in ids_for.values() for i in ids})[:200]
    with ThreadPoolExecutor(8) as ex:
        details = dict(zip(all_ids, ex.map(lambda i: _get_json(f"https://api.osv.dev/v1/vulns/{i}")[1], all_ids)))
    for key, ids in ids_for.items():
        out[key] = [details.get(i) or {"id": i} for i in ids]
    return out


def _fixed_versions(vuln: dict, name: str, ecosystem: str = "") -> List[str]:
    fixed = []
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package") or {}
        if str(pkg.get("name", "")).lower() not in (name.lower(), pep503(name)):
            continue
        if ecosystem and pkg.get("ecosystem") and pkg.get("ecosystem") != ecosystem:
            continue
        for rng in aff.get("ranges", []) or []:
            fixed += [ev["fixed"] for ev in rng.get("events", []) if "fixed" in ev]
    return fixed


# ------------------------------------------------------------------ checks
class DepScanner:
    def __init__(self, project: Project, emit: Emit, offline: bool):
        self.p = project
        self.emit = emit
        self.offline = offline
        self.notes: List[str] = []

    def add(self, dep: Dep, rule: str, msg: str, sev: str = "") -> None:
        sf = self.p.get(dep.file)
        self.emit(Finding(rule, dep.file, dep.line, msg, sev, sf.line(dep.line).strip() if sf else ""))

    def run(self) -> None:
        deps = collect(self.p)
        if not deps:
            return
        squats: Dict[Tuple[str, str], str] = {}
        for d in deps:
            if not d.checkable:
                continue
            target = typosquat_target(d.name, d.ecosystem)
            if target:
                squats[(d.ecosystem, d.name)] = target
        if self.offline:
            for d in deps:
                if (d.ecosystem, d.name) in squats:
                    self.add(d, "DEP002", f"`{d.name}` is one character away from the popular package `{squats[(d.ecosystem, d.name)]}`.")
            return
        known_pypi, _ = popular("PyPI")
        known_npm, _ = popular("npm")
        to_check = sorted({(d.ecosystem, d.name) for d in deps if d.checkable and not (
            (d.ecosystem == "PyPI" and pep503(d.name) in known_pypi) or (d.ecosystem == "npm" and d.name.lower() in known_npm))})
        by_key = {(d.ecosystem, d.name): d for d in deps}
        with ThreadPoolExecutor(8) as ex:
            infos = dict(zip(to_check, ex.map(lambda k: registry_info(by_key[k]), to_check)))
        errors = sum(1 for s, _t, _n in infos.values() if s == "error")
        if errors:
            self.notes.append(f"{errors} registry lookups failed (network); those packages were not verified.")
        now = dt.datetime.now(dt.timezone.utc)
        for d in deps:
            key = (d.ecosystem, d.name)
            status, first, note = infos.get(key, ("ok", None, ""))
            if status == "missing":
                self.add(d, "DEP001", f"`{d.name}` does not exist on {'PyPI' if d.ecosystem == 'PyPI' else 'npm'}.")
                continue
            if status == "malware":
                self.add(d, "DEP001", f"`{d.name}` was {note}.")
                continue
            if key in squats:
                old = first is not None and (now - first).days > 2 * 365
                self.add(d, "DEP002", f"`{d.name}` is one character away from the popular package `{squats[key]}`.",
                         "low" if old else "")
            if first is not None and (now - first).days < NEW_PACKAGE_DAYS:
                self.add(d, "DEP003", f"`{d.name}` was first published {max(0, (now - first).days)} days ago.")
        try:
            vulns = osv_lookup(deps)
        except ConnectionError:
            self.notes.append("OSV vulnerability lookup failed (network); known CVEs were not checked.")
            return
        reported = set()
        for d in deps:
            key = (d.ecosystem, d.name, d.version or "")
            if key not in vulns or (d.file, key) in reported:
                continue
            reported.add((d.file, key))
            items = vulns[key]
            sev = "low"
            for v in items:
                s = OSV_SEV.get(str((v.get("database_specific") or {}).get("severity", "")).upper(), "high")
                sev = s if ["critical", "high", "medium", "low"].index(s) < ["critical", "high", "medium", "low"].index(sev) else sev
            ids = ", ".join(sorted(v.get("id", "?") for v in items)[:6]) + (" ..." if len(items) > 6 else "")
            fix = _upgrade_target(items, d)
            fix = f" Upgrade to at least {fix}." if fix else ""
            self.add(d, "DEP004", f"{d.name} {d.version} has {len(items)} known vulnerabilities ({ids}).{fix}", sev)


def _upgrade_target(items: List[dict], d: Dep) -> Optional[str]:
    """Smallest version that fixes every advisory: per advisory the first fix above the current
    version (stable releases preferred), then the highest of those."""
    current = _vkey(d.version or "0")
    needed = []
    for v in items:
        later = [f for f in _fixed_versions(v, d.name, d.ecosystem) if _vkey(f) > current]
        stable = [f for f in later if re.fullmatch(r"[\d.]+", f)]
        pool = stable or later
        if pool:
            needed.append(min(pool, key=_vkey))
    return max(needed, key=_vkey) if needed else None


def _vkey(v: str) -> Tuple:
    return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.+-]", v))
