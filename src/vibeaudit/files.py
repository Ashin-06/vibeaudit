"""Find the files to scan and give the checks cheap, cached access to them."""
from __future__ import annotations

import bisect
import fnmatch
import json
import os
import re
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "jspm_packages", "vendor",
    "venv", ".venv", "virtualenv", "__pycache__", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "site-packages", "dist", "build", "out", ".next", ".nuxt",
    ".output", ".svelte-kit", ".vercel", ".netlify", ".turbo", ".parcel-cache", ".cache",
    "coverage", "htmlcov", ".idea", ".vscode", "target", ".gradle", "Pods", ".expo",
    ".terraform", ".serverless", "storybook-static", ".docusaurus", ".angular",
}
BUNDLE_DIRS = {"dist", "build", "out"}
BUNDLE_EXTS = {".js", ".mjs", ".cjs", ".html", ".htm"}
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp", ".tiff", ".avif", ".heic",
    ".pdf", ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".whl",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".mov",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".pyc", ".pyo", ".class", ".o", ".a", ".wasm",
    ".db", ".sqlite", ".sqlite3", ".parquet", ".pkl", ".pickle", ".pt", ".pth", ".onnx",
    ".safetensors", ".h5", ".npy", ".npz", ".psd", ".sketch", ".fig", ".mo", ".lockb",
}
LOCKFILES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock",
    "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock", "composer.lock", "Gemfile.lock",
    "go.sum", "pdm.lock",
}
JS_EXTS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"}
HTML_EXTS = {".html", ".htm", ".jinja", ".jinja2", ".j2", ".hbs", ".ejs"}
DEFAULT_MAX_BYTES = 1_000_000

TEST_PATH_RE = re.compile(
    r"(^|/)(tests?|__tests__|__mocks__|spec|specs|e2e|cypress|playwright|fixtures?|testdata|mocks?)/"
    r"|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)conftest\.py$"
    r"|\.(test|spec|stories|story|cy)\.[cm]?[jt]sx?$",
    re.I,
)
ENV_FILE_RE = re.compile(r"(^|/)\.env(\.[\w.-]+)?$")
ENV_EXAMPLE_RE = re.compile(r"\.(example|sample|template|dist|defaults?|tmpl|tpl)$", re.I)


def kind_of(rel: str) -> str:
    name = rel.rsplit("/", 1)[-1]
    low = name.lower()
    ext = os.path.splitext(low)[1]
    if ENV_FILE_RE.search(rel):
        return "env"
    if ext == ".py":
        return "py"
    if ext in JS_EXTS:
        return "js"
    if ext in HTML_EXTS:
        return "html"
    if ext == ".sql":
        return "sql"
    if low in ("dockerfile", "containerfile") or low.startswith(("dockerfile.", "containerfile.")) or low.endswith((".dockerfile", ".containerfile")):
        return "docker"
    if re.search(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", rel):
        return "workflow"
    if re.match(r"(docker-)?compose[\w.-]*\.ya?ml$", low):
        return "compose"
    if low.endswith(".rules") or low == "database.rules.json":
        return "rules"
    if ext in (".yml", ".yaml"):
        return "yaml"
    if ext == ".json":
        return "json"
    return "other"


class SourceFile:
    def __init__(self, root: Path, rel: str, max_bytes: int = DEFAULT_MAX_BYTES):
        self.root = root
        self.rel = rel
        self.path = root / rel
        self.kind = kind_of(rel)
        self.is_test = bool(TEST_PATH_RE.search(rel))
        self.is_lockfile = rel.rsplit("/", 1)[-1] in LOCKFILES
        self.max_bytes = max_bytes
        self._text: Optional[str] = None
        self._raw: Optional[str] = None  # content of a generated bundle: secrets are checked, code rules are not
        self.secrets_only = False  # committed build output (dist/, build/, out/)
        self._loaded = False
        self._line_starts: Optional[List[int]] = None
        self._lines: Optional[List[str]] = None
        self.is_client = False  # set by the JS scanner
        self.cache: Dict[str, object] = {}  # per-file scratch space for scanners

    @property
    def text(self) -> Optional[str]:
        if not self._loaded:
            self._loaded = True
            try:
                size = self.path.stat().st_size
                if size > self.max_bytes:
                    return None
                data = self.path.read_bytes()
            except OSError:
                return None
            if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
                try:
                    data = data.decode("utf-16").encode("utf-8")
                except UnicodeDecodeError:
                    return None
            if b"\x00" in data[:8192]:
                return None
            text = data.decode("utf-8-sig", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
            # Minified bundles and committed build output are generated code: code findings there are noise,
            # but a key baked into a bundle is still a leak, so the text stays available as `raw_text`.
            nl = text.count("\n") + 1
            if self.secrets_only or (self.kind in ("js", "html") and len(text) > 5000 and len(text) / nl > 500):
                self._raw = text
                return None
            self._text = text
        return self._text

    @property
    def raw_text(self) -> Optional[str]:
        """The file's text, also for generated bundles whose `text` is None (used by the secret scanner)."""
        text = self.text
        return text if text is not None else self._raw

    @property
    def lines(self) -> List[str]:
        if self._lines is None:
            self._lines = (self.raw_text or "").split("\n")
        return self._lines

    def line_at(self, offset: int) -> int:
        if self._line_starts is None:
            t = self.raw_text or ""
            self._line_starts = [0] + [m.end() for m in re.finditer("\n", t)]
        return bisect.bisect_right(self._line_starts, offset)

    def line(self, n: int) -> str:
        if 1 <= n <= len(self.lines):
            return self.lines[n - 1]
        return ""


def _git(root: Path, *args: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", "-C", str(root), *args], capture_output=True, timeout=60, check=False
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.decode("utf-8", "replace")


def _matches(rel: str, patterns: Iterable[str]) -> bool:
    for pat in patterns:
        p = pat.strip().lstrip("/").rstrip("/")
        if not p:
            continue
        if fnmatch.fnmatch(rel, p) or fnmatch.fnmatch(rel, p + "/*") or rel.startswith(p + "/"):
            return True
        if "/" not in p and any(fnmatch.fnmatch(part, p) for part in rel.split("/")):
            return True
    return False


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root)
        return True
    except (ValueError, OSError, RuntimeError):
        return False


def read_ignore_file(path: Path) -> List[str]:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith("#")]


def gitignore_covers(root: Path, rel: str) -> bool:
    """Rough .gitignore check used when the folder is not a git checkout.

    Like git, every .gitignore between the root and the file applies, with patterns relative to the
    directory that holds it; a deeper file can re-include with `!`.
    """
    parts = rel.split("/")
    ignored = False
    for depth in range(len(parts)):
        base = "/".join(parts[:depth])
        sub = "/".join(parts[depth:])
        for pat in read_ignore_file(root / base / ".gitignore" if base else root / ".gitignore"):
            if pat.startswith("!"):
                if _matches(sub, [pat[1:]]):
                    ignored = False
            elif _matches(sub, [pat]):
                ignored = True
    return ignored


class Project:
    def __init__(self, root: Path, excludes: Iterable[str] = (), max_bytes: int = DEFAULT_MAX_BYTES):
        self.root = root.resolve()
        self.excludes = list(excludes) + read_ignore_file(self.root / ".vibeauditignore")
        self.excludes.append("vibeaudit-report*")
        self.max_bytes = max_bytes
        self.is_git = False
        self.tracked: Set[str] = set()
        self.untracked: Set[str] = set()
        self.files: List[SourceFile] = []
        self._by_rel: Dict[str, SourceFile] = {}
        self._pkg_cache: Dict[str, Optional[dict]] = {}
        self._venv_cache: Dict[str, bool] = {}
        self._discover()

    def _discover(self) -> None:
        rels: List[str] = []
        inside = _git(self.root, "rev-parse", "--is-inside-work-tree")
        if inside and inside.strip() == "true":
            cached = _git(self.root, "ls-files", "-z", "--cached")
            others = _git(self.root, "ls-files", "-z", "--others", "--exclude-standard")
            if cached is not None and others is not None:
                self.is_git = True
                self.tracked = {p for p in cached.split("\0") if p}
                self.untracked = {p for p in others.split("\0") if p}
                rels = sorted(self.tracked | self.untracked)
        if not self.is_git:
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")
                               and not (Path(dirpath) / d / "pyvenv.cfg").exists()]
                base = Path(dirpath).relative_to(self.root).as_posix()
                for fn in filenames:
                    rels.append(fn if base == "." else base + "/" + fn)
            rels.sort()
        for rel in rels:
            parts = rel.split("/")
            skipped = {p for p in parts[:-1] if p in SKIP_DIRS}
            # committed build output is still checked for secrets (a key inlined into a deployed bundle leaks)
            bundle = bool(skipped) and skipped <= BUNDLE_DIRS and self.is_git and rel in self.tracked \
                and os.path.splitext(rel)[1].lower() in BUNDLE_EXTS
            if (skipped and not bundle) or self._in_venv(parts):
                continue
            if os.path.splitext(rel)[1].lower() in BINARY_EXTS:
                continue
            if _matches(rel, self.excludes):
                continue
            if not self.is_git and ENV_FILE_RE.search(rel) and gitignore_covers(self.root, rel):
                continue  # a local, ignored .env is how secrets are supposed to live
            path = self.root / rel
            if not path.is_file():
                continue
            if path.is_symlink() and not _inside(path, self.root):
                continue  # a link out of the repository (for example to ~/.ssh) is not part of the project
            sf = SourceFile(self.root, rel, self.max_bytes)
            sf.secrets_only = bundle
            self.files.append(sf)
            self._by_rel[rel] = sf

    def _in_venv(self, parts: List[str]) -> bool:
        """True when a parent folder is a Python virtual environment (it has pyvenv.cfg)."""
        for depth in range(1, len(parts)):
            d = "/".join(parts[:depth])
            if d not in self._venv_cache:
                self._venv_cache[d] = (self.root / d / "pyvenv.cfg").is_file()
            if self._venv_cache[d]:
                return True
        return False

    def get(self, rel: str) -> Optional[SourceFile]:
        return self._by_rel.get(rel)

    def of_kind(self, *kinds: str) -> List[SourceFile]:
        return [f for f in self.files if f.kind in kinds]

    def package_json(self, rel_dir: str) -> Optional[dict]:
        if rel_dir not in self._pkg_cache:
            sf = self.get((rel_dir + "/" if rel_dir else "") + "package.json")
            data = None
            if sf and sf.text:
                try:
                    data = json.loads(sf.text)
                except ValueError:
                    data = None
            self._pkg_cache[rel_dir] = data if isinstance(data, dict) else None
        return self._pkg_cache[rel_dir]

    def nearest_package_json(self, rel: str) -> Optional[dict]:
        parts = rel.split("/")[:-1]
        while True:
            pkg = self.package_json("/".join(parts))
            if pkg is not None:
                return pkg
            if not parts:
                return None
            parts.pop()

    def js_deps(self, rel: str) -> Set[str]:
        pkg = self.nearest_package_json(rel) or {}
        deps: Set[str] = set()
        for key in ("dependencies", "devDependencies", "peerDependencies"):
            v = pkg.get(key)
            if isinstance(v, dict):
                deps.update(v)
        return deps

    def all_js_deps(self) -> Set[str]:
        deps: Set[str] = set()
        for f in self.files:
            if f.rel.rsplit("/", 1)[-1] == "package.json":
                d = f.rel.rsplit("/", 1)[0] if "/" in f.rel else ""
                pkg = self.package_json(d) or {}
                for key in ("dependencies", "devDependencies", "peerDependencies"):
                    v = pkg.get(key)
                    if isinstance(v, dict):
                        deps.update(v)
        return deps

    def anchor(self) -> str:
        """A file to attach project-wide findings to (SARIF needs a location)."""
        for name in ("package.json", "pyproject.toml", "requirements.txt", "README.md", "readme.md"):
            if self.get(name):
                return name
        for f in self.files:
            if f.kind in ("py", "js"):
                return f.rel
        return self.files[0].rel if self.files else "."
