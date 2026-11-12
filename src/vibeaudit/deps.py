"""Dependency checks: hallucinated packages (registry lookups), typosquats, new packages and known CVEs (OSV)."""
from __future__ import annotations

import datetime as dt
import functools
import gzip
import http.client
import json
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Callable, Dict, List, Optional, Set, Tuple

from .files import Project, SourceFile
from .model import Finding
from .store import TimedCache

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
    from .updater import data_bytes

    return gzip.decompress(data_bytes(fn)).decode("utf-8").split()


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
    """Every declared dependency. Computed once per project (the quality and dependency scanners both need
    it), and kept by a long-lived Project while the manifests and lockfiles it read are unchanged."""
    from . import files

    cached = getattr(project, "_deps", None)
    if cached is not None and files.still_valid(project, cached[0]):
        if files.READS is not None:
            files.READS.update(cached[0])  # a step that uses the result depends on what it was computed from
        return list(cached[1])
    reads: dict = {}
    saved, files.READS = files.READS, reads
    try:
        result = _collect(project)
    finally:
        files.READS = saved
    if saved is not None:
        saved.update(reads)
    project._deps = (reads, result)  # type: ignore[attr-defined]
    return list(result)


def _collect(project: Project) -> List[Dep]:
    deps: List[Dep] = []
    npm_private_scopes: Set[str] = set()
    for f in project.files:
        if f.rel.rsplit("/", 1)[-1] == ".npmrc" and f.text:
            npm_private_scopes |= set(re.findall(r"^\s*(@[\w-]+):registry\s*=", f.text, re.M))
    for f in project.files:
        name = f.rel.rsplit("/", 1)[-1]
        requirements = bool(re.fullmatch(r"requirements[\w.-]*\.(?:txt|in)", name) or re.search(r"(?:^|/)requirements/[^/]+\.txt$", f.rel))
        # the name first: only manifests are read, so a long-lived Project keeps the result while code changes
        if not (requirements or name in ("pyproject.toml", "package.json")) or f.is_test or f.text is None:
            continue
        if requirements:
            private = bool(re.search(r"^\s*(?:--index-url\b|-i\s)", f.text, re.M))  # PyPI replaced by another index
            for i, line in enumerate(f.lines, 1):
                parsed = parse_requirement(line)
                if parsed:
                    deps.append(Dep(parsed[0], "PyPI", f.rel, i, parsed[1], not private))
        elif name == "pyproject.toml":
            try:
                data = tomllib.loads(f.text)
            except (ValueError, TypeError):
                continue
            # Every level is checked for its type: a hand-edited or broken pyproject must not stop the scan.
            def strings(value) -> List[str]:
                return [s for s in value if isinstance(s, str)] if isinstance(value, list) else []

            table = _dict(data.get("project"))
            specs: List[str] = strings(table.get("dependencies"))
            for group in _dict(table.get("optional-dependencies")).values():
                specs += strings(group)
            for group in _dict(data.get("dependency-groups")).values():
                specs += strings(group)
            poetry = _dict(_dict(data.get("tool")).get("poetry"))
            pnames = list(_dict(poetry.get("dependencies")).keys())
            for grp in _dict(poetry.get("group")).values():
                pnames += list(_dict(_dict(grp).get("dependencies")).keys())
            specs += [n for n in pnames if n.lower() != "python"]
            own = pep503(str(table.get("name", "") or poetry.get("name", "")))
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
    _fill_from_lockfiles(project, deps)
    return deps


PY_LOCKS = ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock")
JS_LOCKS = ("pnpm-lock.yaml", "yarn.lock", "bun.lock")


def _fill_from_lockfiles(project: Project, deps: List[Dep]) -> None:
    """Resolve exact versions from the lockfile next to each manifest, so OSV can check them."""
    cache: Dict[Tuple[str, str], Tuple[str, str]] = {}
    for d in deps:
        if d.version or not d.checkable:
            continue
        folder = d.file.rsplit("/", 1)[0] if "/" in d.file else ""
        for lock in (PY_LOCKS if d.ecosystem == "PyPI" else JS_LOCKS):
            key = (folder, lock)
            if key not in cache:
                path = project.root / folder / lock if folder else project.root / lock
                try:
                    from .files import file_signature

                    cache[key] = (lock, path.read_text(encoding="utf-8", errors="replace") if file_signature(path) else "")
                except OSError:
                    cache[key] = (lock, "")
            version = _locked_version(*cache[key], d)
            if version:
                d.version = version
                break


@functools.lru_cache(maxsize=8)
def _parsed_toml(text: str) -> Optional[dict]:
    """A lockfile parsed once, not once per dependency looked up in it (a poetry.lock takes seconds)."""
    try:
        return tomllib.loads(text)
    except (ValueError, TypeError):
        return None


@functools.lru_cache(maxsize=8)
def _parsed_json(text: str) -> object:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _locked_version(lock: str, text: str, d: Dep) -> Optional[str]:
    if not text:
        return None
    name = re.escape(d.name)
    if lock in ("poetry.lock", "uv.lock", "pdm.lock"):
        data = _parsed_toml(text)
        if data is None:
            return None
        for pkg in data.get("package", []) if isinstance(data.get("package"), list) else []:
            if isinstance(pkg, dict) and pep503(str(pkg.get("name", ""))) == pep503(d.name) and isinstance(pkg.get("version"), str):
                return pkg["version"]
        return None
    if lock == "Pipfile.lock":
        data = _parsed_json(text)
        if data is None:
            return None
        for section in ("default", "develop"):
            for pkg, info in _dict(_dict(data).get(section)).items():
                if pep503(pkg) == pep503(d.name) and isinstance(_dict(info).get("version"), str):
                    return info["version"].lstrip("=")
        return None
    if lock == "pnpm-lock.yaml":
        for rx in (r"^\s+'?" + name + r"'?:\n\s+specifier: [^\n]*\n\s+version: '?([0-9][^\s('\n]*)",  # v6 / v9 importers
                   r"^\s+'?" + name + r"'?: '?([0-9][^\s('\n]*)",  # v5 importers
                   r"^\s+'?/?" + name + r"@([0-9][^:(\s']*)'?:"):  # packages section
            m = re.search(rx, text, re.M)
            if m:
                return m.group(1)
        return None
    if lock == "yarn.lock":
        m = re.search(r'^"?' + name + r'@[^\n]*:\n\s+version:? "?([0-9][^"\s]*)', text, re.M)
        return m.group(1) if m else None
    if lock == "bun.lock":
        m = re.search(r'"' + name + r'": \["' + name + r'@([0-9][^"]*)"', text)
        return m.group(1) if m else None
    return None


def _npm_lock_versions(project: Project, pkg: SourceFile) -> Dict[str, str]:
    base = pkg.rel.rsplit("/", 1)[0] + "/" if "/" in pkg.rel else ""
    path = project.root / (base + "package-lock.json")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    out: Dict[str, str] = {}
    if not isinstance(data, dict):
        return out
    for key, val in _dict(data.get("packages")).items():
        if key.startswith("node_modules/") and key.count("node_modules/") == 1 and isinstance(val, dict) and "version" in val:
            out[key[len("node_modules/"):]] = str(val["version"])
    for key, val in _dict(data.get("dependencies")).items():
        if isinstance(val, dict) and "version" in val:
            out.setdefault(key, str(val["version"]))
    return out


# ------------------------------------------------------------------ network
RETRY_STATUS = {408, 425, 429, 500, 502, 503, 504}
MAX_ATTEMPTS = 3
MAX_RETRY_AFTER = 10.0
BREAKER_THRESHOLD = 5  # consecutive transport failures before a host is considered down for this run


class _Breaker:
    """Stops hammering a host that is down, so an outage costs seconds, not minutes."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.failures: Dict[str, int] = {}

    def open(self, host: str) -> bool:
        with self.lock:
            return self.failures.get(host, 0) >= BREAKER_THRESHOLD

    def record(self, host: str, ok: bool) -> None:
        with self.lock:
            self.failures[host] = 0 if ok else self.failures.get(host, 0) + 1

    def reset(self) -> None:
        with self.lock:
            self.failures.clear()


BREAKER = _Breaker()


def _retry_after(err: urllib.error.HTTPError, attempt: int) -> float:
    try:
        value = float(err.headers.get("Retry-After", "")) if err.headers else -1.0
    except (TypeError, ValueError):
        value = -1.0
    if value < 0:
        value = 0.5 * (2 ** attempt)
    return min(value, MAX_RETRY_AFTER)


def _get_json(url: str, data: Optional[bytes] = None) -> Tuple[int, Optional[dict]]:
    """GET (or POST when `data` is given) a JSON document.

    Returns (status, document). status is the HTTP status, or 0 when the request could not be completed
    (timeout, DNS, connection reset, rate limited after retries, invalid JSON). The document is None
    unless a JSON object came back with status 200. Only a definite 404/410 means "does not exist".
    """
    host = urllib.parse.urlsplit(url).netloc
    if BREAKER.open(host):
        return 0, None
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, "Accept": "application/json",
                                                          **({"Content-Type": "application/json"} if data else {})})
    for attempt in range(MAX_ATTEMPTS):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 - fixed https hosts
                status = getattr(resp, "status", 200)
                doc = json.loads(resp.read().decode("utf-8"))
            BREAKER.record(host, True)
            if status == 200 and isinstance(doc, dict):
                return status, doc
            return 0, None
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                BREAKER.record(host, True)
                return e.code, None
            if e.code not in RETRY_STATUS or attempt == MAX_ATTEMPTS - 1:
                BREAKER.record(host, e.code not in RETRY_STATUS)
                return 0, None
            time.sleep(_retry_after(e, attempt))
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException):
            if attempt == MAX_ATTEMPTS - 1 or BREAKER.open(host):
                BREAKER.record(host, False)
                return 0, None
            time.sleep(0.5 * (2 ** attempt))
    return 0, None


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


REGISTRY_CACHE = TimedCache("registry.json", 24 * 3600)
OSV_CACHE = TimedCache("osv.json", 24 * 3600)


def save_caches() -> None:
    REGISTRY_CACHE.save()
    OSV_CACHE.save()


def registry_info(dep: Dep) -> Tuple[str, Optional[dt.datetime], str]:
    """Return (status, first_release, note); status is ok | missing | malware | error.

    Answers are cached for a day; "missing" only for an hour, because a name can be registered at any time."""
    key = f"{dep.ecosystem}:{pep503(dep.name) if dep.ecosystem == 'PyPI' else dep.name.lower()}"
    hit = REGISTRY_CACHE.get(key)
    if isinstance(hit, list) and len(hit) == 3 and (hit[0] != "missing" or REGISTRY_CACHE.get(key, ttl=3600) is not None):
        return str(hit[0]), _parse_time(hit[1]), str(hit[2])
    status, first, note = _registry_lookup(dep)
    if status != "error":
        REGISTRY_CACHE.put(key, [status, first.isoformat() if first else None, note])
    return status, first, note


def _registry_lookup(dep: Dep) -> Tuple[str, Optional[dt.datetime], str]:
    if dep.ecosystem == "PyPI":
        code, data = _get_json(f"https://pypi.org/pypi/{urllib.parse.quote(pep503(dep.name))}/json")
        if code in (404, 410):
            return "missing", None, ""
        if not data:
            return "error", None, ""
        times = []
        for files in _dict(data.get("releases")).values():
            for f in files if isinstance(files, list) else []:
                if isinstance(f, dict) and isinstance(f.get("upload_time_iso_8601"), str):
                    times.append(f["upload_time_iso_8601"])
        return "ok", _parse_time(min(times) if times else None), ""
    code, data = _get_json("https://registry.npmjs.org/" + urllib.parse.quote(dep.name, safe="@"))
    if code in (404, 410):
        return "missing", None, ""
    if not data:
        return "error", None, ""
    latest = str(_dict(data.get("dist-tags")).get("latest", ""))
    if latest == "0.0.1-security" or "security holding" in str(data.get("description", "")).lower():
        return "malware", None, "removed from npm for security reasons (malware)"
    created = _dict(data.get("time")).get("created")
    return "ok", _parse_time(created if isinstance(created, str) else None), ""


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
        _code, data = _get_json("https://api.osv.dev/v1/querybatch", body)
        results = data.get("results") if data else None
        if not isinstance(results, list) or len(results) != len(chunk):
            raise ConnectionError("OSV query failed")
        for key, res in zip(chunk, results):
            vulns = _dict(res).get("vulns")
            ids = [str(v["id"]) for v in vulns if isinstance(v, dict) and "id" in v] if isinstance(vulns, list) else []
            if ids:
                ids_for[key] = ids
    all_ids = sorted({i for ids in ids_for.values() for i in ids})[:200]
    details = {i: OSV_CACHE.get(i) for i in all_ids}
    todo = [i for i, d in details.items() if not isinstance(d, dict)]
    with ThreadPoolExecutor(8) as ex:
        fetched = dict(zip(todo, ex.map(lambda i: _get_json(f"https://api.osv.dev/v1/vulns/{urllib.parse.quote(i)}")[1], todo)))
    for i, doc in fetched.items():
        details[i] = doc
        if isinstance(doc, dict):
            # only what the report uses: an advisory body can be tens of kilobytes
            OSV_CACHE.put(i, {k: doc[k] for k in ("id", "summary", "affected", "database_specific", "severity") if k in doc})
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
        try:
            self._run()
        finally:
            save_caches()

    def _run(self) -> None:
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
            from . import bundle

            trans = locked_packages(self.p, deps)
            found, missing = bundle.offline_vulns(deps + trans)
            used = sorted({d.ecosystem for d in deps if d.version and d.checkable} - set(missing))
            if used:
                self.notes.append("Offline: known vulnerabilities checked against the imported OSV index ("
                                  + ", ".join(f"{e} from {bundle.index_age(e)}" for e in used) + ").")
            if missing:
                self.notes.append(f"Offline: known vulnerabilities of {', '.join(missing)} packages were not checked "
                                  "(import a bundle made with `vibeaudit update --export FILE --osv ...`).")
            self._report_vulns(deps, found)
            self._report_vulns(trans, found, transitive=True)
            return
        known_pypi, _ = popular("PyPI")
        known_npm, _ = popular("npm")
        to_check = sorted({(d.ecosystem, d.name) for d in deps if d.checkable and not (
            (d.ecosystem == "PyPI" and pep503(d.name) in known_pypi) or (d.ecosystem == "npm" and d.name.lower() in known_npm))})
        by_key = {(d.ecosystem, d.name): d for d in deps}
        BREAKER.reset()
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
        self._report_vulns(deps, vulns)
        trans = locked_packages(self.p, deps)
        try:
            vulns = osv_lookup(trans) if trans else {}
        except ConnectionError:
            self.notes.append("OSV lookup of the lockfiles' transitive dependencies failed (network); they were not checked.")
            return
        self._report_vulns(trans, vulns, transitive=True)

    def _report_vulns(self, deps: List[Dep], vulns: Dict[Tuple[str, str, str], List[dict]], transitive: bool = False) -> None:
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
            if transitive:
                fix = f" Version {fix} fixes them." if fix else ""
                self.add(d, "DEP009", f"{d.name} {d.version}, installed as a dependency of another package, has {len(items)} "
                                      f"known {_vulns(len(items))} ({ids}).{fix} Update the package that pulls it in, or pin "
                                      "a fixed version with an override (npm `overrides`, pnpm/yarn `resolutions`, a "
                                      "constraint for Python).", sev)
                continue
            fix = f" Upgrade to at least {fix}." if fix else ""
            self.add(d, "DEP004", f"{d.name} {d.version} has {len(items)} known {_vulns(len(items))} ({ids}).{fix}", sev)


def _vulns(n: int) -> str:
    return "vulnerability" if n == 1 else "vulnerabilities"


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


# ------------------------------------------------------------------ transitive dependencies (DEP009)
LOCK_MANIFESTS = {"package.json": "npm", "pyproject.toml": "PyPI", "Pipfile": "PyPI"}
LOCKS = {"npm": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"),
         "PyPI": ("poetry.lock", "uv.lock", "pdm.lock", "Pipfile.lock")}
MAX_LOCK_BYTES = 30_000_000


def locked_packages(project: Project, direct: List[Dep]) -> List[Dep]:
    """Packages installed through a lockfile that no manifest names: the transitive dependencies. Packages the
    lockfile marks as development-only are left out. One Dep per (lockfile, name, version)."""
    from .files import file_signature

    direct_names = {(d.ecosystem, pep503(d.name) if d.ecosystem == "PyPI" else d.name) for d in direct}
    out: List[Dep] = []
    folders = sorted({(f.rel.rsplit("/", 1)[0] if "/" in f.rel else "", LOCK_MANIFESTS[f.rel.rsplit("/", 1)[-1]])
                      for f in project.files if f.rel.rsplit("/", 1)[-1] in LOCK_MANIFESTS})
    for folder, eco in folders:
        for lock in LOCKS[eco]:
            path = project.root / folder / lock if folder else project.root / lock
            try:
                if not file_signature(path) or path.stat().st_size > MAX_LOCK_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            rel = f"{folder}/{lock}" if folder else lock
            seen: Set[Tuple[str, str]] = set()
            for name, version, line in _lock_entries(lock, text):
                key = pep503(name) if eco == "PyPI" else name
                if (eco, key) in direct_names or (key, version) in seen or not re.match(r"\d", version):
                    continue
                seen.add((key, version))
                out.append(Dep(name, eco, rel, line, version))
            break  # one lockfile per folder, as the package manager uses
    return out


def _line_at(offsets: List[int], off: int) -> int:
    import bisect

    return bisect.bisect_right(offsets, off) + 1


def _lock_entries(lock: str, text: str) -> List[Tuple[str, str, int]]:
    """(name, version, line) of every non-development package in a lockfile."""
    newlines = [m.start() for m in re.finditer("\n", text)]
    line = functools.partial(_line_at, newlines)
    out: List[Tuple[str, str, int]] = []
    if lock == "package-lock.json":
        data = _dict(_parsed_json(text))
        where = {m.group(1): m.start() for m in re.finditer(r'(?m)^\s*"((?:[^"\n]*/)?node_modules/[^"\n]+)":\s*\{', text)}
        for key, val in _dict(data.get("packages")).items():
            if "node_modules/" not in key or not isinstance(val, dict) or val.get("dev") or val.get("devOptional") or val.get("link"):
                continue
            version = val.get("version")
            if isinstance(version, str):
                out.append((key.rsplit("node_modules/", 1)[1], version, line(where.get(key, 0))))
    elif lock in ("poetry.lock", "uv.lock", "pdm.lock"):
        data = _parsed_toml(text) or {}
        starts = [m.start() for m in re.finditer(r"(?m)^\[\[package\]\]", text)]
        for i, pkg in enumerate(data.get("package", []) if isinstance(data.get("package"), list) else []):
            if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str) or not isinstance(pkg.get("version"), str):
                continue
            groups = pkg.get("groups")
            if pkg.get("category") == "dev" or (isinstance(groups, list) and groups and not {"main", "default"} & set(groups)):
                continue
            out.append((pkg["name"], pkg["version"], line(starts[i]) if i < len(starts) else 1))
    elif lock == "Pipfile.lock":
        default_at = max(text.find('"default"'), 0)
        for name, info in _dict(_dict(_parsed_json(text)).get("default")).items():
            version = _dict(info).get("version")
            if isinstance(version, str):
                m = re.compile(r'(?m)^\s*"%s":\s*\{' % re.escape(name)).search(text, default_at)
                out.append((name, version.lstrip("="), line(m.start()) if m else 1))
    elif lock == "pnpm-lock.yaml":
        start = re.search(r"(?m)^packages:\s*$", text)
        if start:
            end = re.search(r"(?m)^\S", text[start.end():])
            section = start.end() + (end.start() if end else len(text) - start.end())
            for m in re.finditer(r"(?m)^  '?/?((?:@[^@/\s']+/)?[^@/\s'(]+)[@/](\d[^\s:'()]*)[^\n]*:[ \t]*\n((?:    [^\n]*\n){0,40})",
                                 text[start.end():section]):
                if re.search(r"(?m)^    dev: true$", m.group(3)):
                    continue
                out.append((m.group(1), m.group(2), line(start.end() + m.start())))
    elif lock == "yarn.lock":
        for m in re.finditer(r'(?m)^"?((?:@[^@/\s"]+/)?[^@\s"]+)@[^\n]*:\n(?:  [^\n]*\n){0,3}?  version:? "?(\d[^"\s]*)', text):
            if "use.local" not in m.group(2):  # a workspace package
                out.append((m.group(1), m.group(2), line(m.start())))
    elif lock == "bun.lock":
        for m in re.finditer(r'(?m)^\s*"[^"\n]+":\s*\[\s*"((?:@[^@/"]+/)?[^@"]+)@(\d[^"]*)"', text):
            out.append((m.group(1), m.group(2), line(m.start())))
    return out
