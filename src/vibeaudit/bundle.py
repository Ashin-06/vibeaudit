"""Offline and air-gapped use: a data bundle made on a connected machine and imported on one without network.

    vibeaudit update --export bundle.zip --osv PyPI,npm    # connected machine
    vibeaudit update --import bundle.zip                    # air-gapped machine, then: vibeaudit scan --offline

The bundle holds the data files `vibeaudit update` refreshes (popular-package lists, retired model ids, the
signed threat feed when one is installed) and,
with --osv, a compact vulnerability index per ecosystem built from OSV's public dumps. Every member is listed
with its SHA-256 in manifest.json; an import accepts only known member names, checks sizes, hashes and
contents, and writes nothing until the whole bundle is valid.

The index keeps, per package, each advisory's explicitly listed affected versions (OSV lists them for PyPI
and npm) and its version ranges (for the "upgrade to" advice). An offline scan reports a pinned version that
is listed as affected. Advisories with ranges but no version list cannot be matched without the registry's
version order and are counted, not used.
"""
from __future__ import annotations

import datetime as dt
import gzip
import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__
from .store import cache_dir, loads_json, write_atomic

OSV_DUMP = "https://osv-vulnerabilities.storage.googleapis.com/{}/all.zip"
ECOSYSTEMS = ("PyPI", "npm")
MAX_DUMP = 1_500_000_000  # bytes of one OSV all.zip download
MAX_INDEX = 400_000_000  # bytes of one uncompressed index
MAX_DATA = 10_000_000
FORMAT = 1


class BundleError(Exception):
    pass


def norm(name: str, ecosystem: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name.lower()


# ------------------------------------------------------------------ the index
def build_index(dump: bytes, ecosystem: str) -> Tuple[bytes, Dict[str, int]]:
    """A gzipped JSON index from an OSV all.zip of one ecosystem, and counts for the log."""
    packages: Dict[str, List[dict]] = {}
    counts = {"advisories": 0, "used": 0, "without_versions": 0}
    with zipfile.ZipFile(io.BytesIO(dump)) as z:
        for info in z.infolist():
            if not info.filename.endswith(".json") or info.file_size > 20_000_000:
                continue
            try:
                doc = loads_json(z.read(info))
            except ValueError:
                continue
            if not isinstance(doc, dict) or doc.get("withdrawn"):
                continue
            counts["advisories"] += 1
            used = False
            for aff in doc.get("affected") or []:
                pkg = (aff or {}).get("package") or {}
                if pkg.get("ecosystem") != ecosystem or not isinstance(pkg.get("name"), str):
                    continue
                versions = [v for v in aff.get("versions") or [] if isinstance(v, str)]
                if not versions:
                    counts["without_versions"] += 1
                    continue
                severity = (doc.get("database_specific") or {}).get("severity")
                packages.setdefault(norm(pkg["name"], ecosystem), []).append({
                    "id": str(doc.get("id", "?")), "summary": str(doc.get("summary", ""))[:300],
                    "database_specific": {"severity": severity} if isinstance(severity, str) else {},
                    "affected": [{"package": pkg, "ranges": aff.get("ranges") or []}], "versions": versions})
                used = True
            counts["used"] += used
    index = {"format": FORMAT, "ecosystem": ecosystem, "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
             "counts": counts, "packages": packages}
    return gzip.compress(json.dumps(index, separators=(",", ":")).encode("utf-8")), counts


def _check_index(data: bytes, ecosystem: str) -> dict:
    try:
        raw = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_INDEX + 1)
    except (OSError, EOFError) as e:
        raise BundleError(f"the {ecosystem} index is not gzip data ({e})") from None
    if len(raw) > MAX_INDEX:
        raise BundleError(f"the {ecosystem} index is larger than {MAX_INDEX} bytes")
    try:
        index = loads_json(raw)
    except ValueError:
        raise BundleError(f"the {ecosystem} index is not JSON") from None
    if not (isinstance(index, dict) and index.get("format") == FORMAT and index.get("ecosystem") == ecosystem
            and isinstance(index.get("packages"), dict)):
        raise BundleError(f"the {ecosystem} index has an unknown format")
    for name, entries in index["packages"].items():
        if not (isinstance(name, str) and isinstance(entries, list) and all(
                isinstance(e, dict) and isinstance(e.get("id"), str) and isinstance(e.get("versions"), list) for e in entries)):
            raise BundleError(f"the {ecosystem} index has a malformed entry for {name!r}")
    return index


_LOADED: Dict[str, Optional[dict]] = {}


def index_path(ecosystem: str) -> Path:
    return cache_dir() / "osv" / f"{ecosystem}.json.gz"


def load_index(ecosystem: str) -> Optional[dict]:
    """The imported index for an ecosystem, or None."""
    if ecosystem not in _LOADED:
        try:
            _LOADED[ecosystem] = _check_index(index_path(ecosystem).read_bytes(), ecosystem)
        except (OSError, BundleError):
            _LOADED[ecosystem] = None
    return _LOADED[ecosystem]


def version_key(version: str, ecosystem: str) -> str:
    """Versions that are equal compare equal: PEP 440 ignores trailing zero release segments (OSV lists Django
    "3.2", a requirement pins "3.2.0"); npm versions are exact semver strings."""
    v = version.strip().lower()
    v = v[1:] if v.startswith("v") else v
    if ecosystem != "PyPI":
        return v
    m = re.match(r"(\d+(?:\.\d+)*)(.*)$", v)
    if not m:
        return v
    parts = [str(int(p)) for p in m.group(1).split(".")]
    while len(parts) > 1 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts) + m.group(2)


def offline_vulns(deps) -> Tuple[Dict[Tuple[str, str, str], List[dict]], List[str]]:
    """Known vulnerabilities of pinned dependencies from the imported indexes (no network), in the shape
    deps.osv_lookup() returns, and the ecosystems that had no index."""
    out: Dict[Tuple[str, str, str], List[dict]] = {}
    missing = set()
    for d in deps:
        if not d.version or not d.checkable:
            continue
        index = load_index(d.ecosystem)
        if index is None:
            missing.add(d.ecosystem)
            continue
        want = version_key(d.version, d.ecosystem)
        hits = [e for e in index["packages"].get(norm(d.name, d.ecosystem), [])
                if any(version_key(v, d.ecosystem) == want for v in e["versions"])]
        if hits:
            out[(d.ecosystem, d.name, d.version)] = [{k: v for k, v in e.items() if k != "versions"} for e in hits]
    return out, sorted(missing)


def index_age(ecosystem: str) -> Optional[str]:
    index = load_index(ecosystem)
    return str(index.get("created")) if index else None


# ------------------------------------------------------------------ bundles
def export(path: Path, osv: List[str], log: Callable[[str], None], fetch: Optional[Callable[[str], bytes]] = None) -> None:
    """Write a bundle with the current data files and, for each ecosystem in `osv`, a freshly built index."""
    from .updater import FILES, data_bytes

    from . import feed

    members: Dict[str, bytes] = {f"data/{name}": data_bytes(name) for name in FILES}
    if feed.cached() is not None:  # signed, so the air-gapped machine checks it the same way
        members[f"data/{feed.FEED}"] = (cache_dir() / "data" / feed.FEED).read_bytes()
    for eco in osv:
        if eco not in ECOSYSTEMS:
            raise BundleError(f"unknown ecosystem {eco!r} (use {', '.join(ECOSYSTEMS)})")
        log(f"downloading the OSV {eco} dump ...")
        dump = (fetch or _download)(OSV_DUMP.format(eco))
        data, counts = build_index(dump, eco)
        log(f"OSV {eco}: {counts['used']} of {counts['advisories']} advisories indexed "
            f"({counts['without_versions']} affected entries list no versions and are left out)")
        members[f"osv/{eco}.json.gz"] = data
    manifest = {"format": FORMAT, "vibeaudit": __version__, "created": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "files": {name: {"sha256": hashlib.sha256(b).hexdigest(), "size": len(b)} for name, b in members.items()}}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(manifest, indent=2))
        for name, b in members.items():
            z.writestr(name, b)
    if not write_atomic(path, buf.getvalue()):
        raise BundleError(f"cannot write {path}")
    log(f"wrote {path} ({len(buf.getvalue())} bytes, {len(members)} files)")


def import_bundle(path: Path, log: Callable[[str], None]) -> None:
    """Validate the whole bundle, then install it into the user cache."""
    from . import feed
    from .updater import FILES, forget_loaded_data

    allowed = {f"data/{n}" for n in FILES} | {f"data/{feed.FEED}"} | {f"osv/{e}.json.gz" for e in ECOSYSTEMS}
    try:
        z = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as e:
        raise BundleError(f"not a bundle: {e}") from None
    with z:
        try:
            manifest = loads_json(z.read("manifest.json"))
        except (KeyError, ValueError):
            raise BundleError("the bundle has no valid manifest.json") from None
        listed = manifest.get("files") if isinstance(manifest, dict) and manifest.get("format") == FORMAT else None
        if not isinstance(listed, dict):
            raise BundleError("the bundle's manifest has an unknown format")
        names = {i.filename for i in z.infolist()} - {"manifest.json"}
        if names != set(listed) or not names <= allowed:
            raise BundleError("the bundle's files do not match its manifest or are not vibeaudit data: "
                              + ", ".join(sorted((names ^ set(listed)) | (names - allowed))))
        contents: Dict[str, bytes] = {}
        for info in z.infolist():
            if info.filename == "manifest.json":
                continue
            cap = MAX_DATA if info.filename.startswith("data/") else MAX_INDEX
            if info.file_size > cap:
                raise BundleError(f"{info.filename} is larger than {cap} bytes")
            data = z.read(info)
            meta = listed[info.filename]
            if not isinstance(meta, dict) or hashlib.sha256(data).hexdigest() != meta.get("sha256"):
                raise BundleError(f"{info.filename} does not match the SHA-256 in the manifest")
            if info.filename == f"data/{feed.FEED}":
                try:
                    feed.open_feed(data)  # an expired feed is still installed; scans warn and use the shipped data
                except feed.FeedError as e:
                    raise BundleError(f"{info.filename}: {e}") from None
            elif info.filename.startswith("data/"):
                if not FILES[info.filename[5:]](data):
                    raise BundleError(f"{info.filename} failed validation")
            else:
                _check_index(data, info.filename[4:-len(".json.gz")])
            contents[info.filename] = data
    for name, data in contents.items():
        target = cache_dir() / name
        if not write_atomic(target, data):
            raise BundleError(f"cannot write {target}")
        log(f"installed {name}")
    _LOADED.clear()
    forget_loaded_data()
    log(f"imported a bundle made by vibeaudit {manifest.get('vibeaudit', '?')} on {manifest.get('created', '?')}")


def _download(url: str) -> bytes:
    import urllib.request

    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "vibeaudit-update"}), timeout=300) as resp:  # noqa: S310
        data = resp.read(MAX_DUMP + 1)
    if len(data) > MAX_DUMP:
        raise BundleError("the OSV dump is larger than expected")
    return data
