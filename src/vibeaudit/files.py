"""Find the files to scan and give the checks cheap, cached access to them."""
from __future__ import annotations

import bisect
import fnmatch
import json
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "bower_components", "jspm_packages", "vendor",
    "venv", ".venv", "virtualenv", "__pycache__", ".tox", ".nox", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "site-packages", "dist", "build", "out", ".next", ".nuxt",
    ".output", ".svelte-kit", ".vercel", ".netlify", ".turbo", ".parcel-cache", ".cache",
    "coverage", "htmlcov", ".idea", "target", ".gradle", "Pods", ".expo",  # .vscode is read: mcp.json, agent settings
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
    r"|(^|/)test_[^/]*\.py$|_test\.py$|(^|/)(conftest|tests?)\.py$"
    r"|\.(test|spec|stories|story|cy)\.[cm]?[jt]sx?$",
    re.I,
)
# demo code shipped beside a library (flask/examples, express/examples): not the deployed application
EXAMPLE_PATH_RE = re.compile(r"(^|/)examples?/", re.I)
# one-off jobs run by a developer (migrations, management commands, seed and setup scripts): a query per loop
# iteration or an f-string of constant identifiers there is not a request-time N+1 or an injection
ONE_OFF_PATH_RE = re.compile(
    r"(^|/)(migrations|alembic|management/commands|scripts?|seeds?|seeders|bin)/"
    r"|(^|/)(seed|seeds|create[-_]tables?|setup[-_]db|db[-_]reset|reset[-_]db|migrate[\w-]*|(?:placeholder|sample|seed|mock|dummy)[-_]?data)"
    r"\.(?:py|[cm]?[jt]s)$", re.I)
# well-known libraries copied into the project unminified (static/jquery/jquery.js, bootstrap.css)
VENDORED_NAME_RE = re.compile(
    r"(^|/)(?:jquery|bootstrap|materialize|popper|lodash|underscore|moment|angular|d3|chart|fontawesome|font-awesome"
    r"|select2|datatables|tinymce|codemirror|highlight|prism|swagger-ui)[\w.-]*\.(?:js|css)$", re.I)
# a vendored copy of a built library kept readable: "// Original source: .../dist/x-min.js"
VENDORED_HEADER_RE = re.compile(r"(?im)^[ \t]*(?://|/\*|\*)[^\n]*(?:original source:|\bdist/[\w.-]+\.js\b|\w[.-]min\.js\b)")
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


# While a replayable scan step runs (guard.StepMemo), every file it reads is recorded here, so the step can be
# skipped on the next scan of the same Project when none of those files changed.
READS: Optional[Dict[str, "SourceFile"]] = None


def _read(sf: "SourceFile") -> None:
    if READS is not None:
        READS[sf.rel] = sf


# Value dependencies: a replayable step that needs one fact about another file (or the disk) rather than the
# whole file records ("kind", args...) -> value in READS; before a replay, VALUES[kind](project, *args) must
# give the same value again.
VALUES: Dict[str, Callable[..., object]] = {}


def untracked(fn: Callable[..., object], *args: object) -> object:
    """fn(*args) without recording the files it reads (for computing a value dependency)."""
    global READS
    saved, READS = READS, None
    try:
        return fn(*args)
    finally:
        READS = saved


def depend(key: tuple, value: object) -> None:
    if READS is not None:
        READS[key] = value  # type: ignore[index]


def _disk(path: Path, what: str) -> bool:
    return path.is_file() if what == "file" else path.is_dir() if what == "dir" else path.exists()


def probe(path: Path, what: str) -> bool:
    """path.is_file() / is_dir() / exists() for a path that may be outside the scanned files (excluded or
    generated). A replayable step records the answer, and is replayed only while the answer is the same."""
    got = _disk(path, what)
    depend(("disk", str(path), what), got)
    return got


VALUES["disk"] = lambda project, path, what: _disk(Path(path), what)


def file_signature(path: Path) -> Optional[Tuple[int, int]]:
    """(mtime_ns, size) of a file read straight from disk (lockfiles), recorded as a value dependency."""
    try:
        st = path.stat()
    except OSError:
        sig = None
    else:
        sig = (st.st_mtime_ns, st.st_size) if stat.S_ISREG(st.st_mode) else None
    depend(("file", str(path)), sig)
    return sig


VALUES["file"] = lambda project, path: _signature_of(Path(path))


def _signature_of(path: Path) -> Optional[Tuple[int, int]]:
    try:
        st = path.stat()
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size) if stat.S_ISREG(st.st_mode) else None


def still_valid(project: "Project", reads: Dict[object, object]) -> bool:
    """Every file (or value) a cached result was computed from is unchanged."""
    return all(VALUES[k[0]](project, *k[1:]) == v if isinstance(k, tuple) else project._by_rel.get(k) is v  # type: ignore[index]
               for k, v in reads.items())


def has(sf: "SourceFile", rx: "re.Pattern[str]", text: Optional[str] = None) -> bool:
    """rx.search() on the file's text (or on `text`, a view of it), remembered in sf.cache: a long-lived
    Project (vibeaudit watch, lsp) then searches only changed files for project-wide evidence."""
    key = ("has", rx.pattern, rx.flags, text is not None)
    hit = sf.cache.get(key)
    _read(sf)
    if hit is None:
        hit = sf.cache[key] = bool(rx.search(sf.text or "" if text is None else text))
    return hit  # type: ignore[return-value]


DEV_SETTINGS_RE = re.compile(r"(?:^|/)(?:settings/(?:dev|development|local|test|testing)|settings_(?:dev|local|test))\.py$")


def production_overrides(project: "Project", rel: str, name: str) -> bool:
    """Django-style split settings: a value in base.py or dev.py that production.py (prod.py) sets again, or a
    development-only settings file. Such a DEBUG = True or SECRET_KEY literal never reaches production."""
    if DEV_SETTINGS_RE.search(rel):
        return True
    folder = rel.rsplit("/", 1)[0] if "/" in rel else ""
    assign = re.compile(r"(?m)^[ \t]*%s\s*=" % re.escape(name))
    return any(f.rel != rel and f.kind == "py" and (f.rel.rsplit("/", 1)[0] if "/" in f.rel else "") == folder
               and re.search(r"(?:^|/)(?:production|prod|live)\.py$", f.rel) and assign.search(f.text or "")
               for f in project.files)


def _generated(text: str, kind: str) -> bool:
    """Minified (long lines on average and some very long ones) or a vendored build kept readable. HTML pages
    keep the stricter test: an inline SVG or data URI makes long lines in a hand-written page."""
    lines = text.split("\n")
    average = len(text) / len(lines)
    if kind == "html":
        return average > 500
    if average > 200 and max(map(len, lines)) > 500:
        return True
    return bool(VENDORED_HEADER_RE.search(text[:1000]))


class SourceFile:
    def __init__(self, root: Path, rel: str, max_bytes: int = DEFAULT_MAX_BYTES):
        self.root = root
        self.rel = rel
        self.path = root / rel
        self.kind = kind_of(rel)
        self.is_test = bool(TEST_PATH_RE.search(rel))
        self.is_example = bool(EXAMPLE_PATH_RE.search(rel))
        self.is_one_off = bool(ONE_OFF_PATH_RE.search(rel))
        self.is_vendored = bool(VENDORED_NAME_RE.search(rel))
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
        self.signature: Optional[tuple] = None  # (mtime_ns, size) when discovered; see Project.refresh
        self.overlay: Optional[bytes] = None  # unsaved editor content used instead of the file (language server)

    @property
    def text(self) -> Optional[str]:
        _read(self)
        if not self._loaded:
            self._loaded = True
            try:
                if self.overlay is not None:
                    data = self.overlay
                elif self.path.stat().st_size > self.max_bytes:
                    return None
                else:
                    data = self.path.read_bytes()
            except OSError:
                return None
            if len(data) > self.max_bytes:
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
            if self.secrets_only or (self.kind in ("js", "html") and len(text) > 5000 and (self.is_vendored or _generated(text, self.kind))):
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
            ["git", "-C", str(root), *args], capture_output=True, stdin=subprocess.DEVNULL, timeout=60, check=False
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
        self._base_excludes = list(excludes)
        self.max_bytes = max_bytes
        self.is_git = False
        self.tracked: Set[str] = set()
        self.binary: Set[str] = set()  # images, fonts and other binary files: listed, never read
        self.untracked: Set[str] = set()
        self.files: List[SourceFile] = []
        self._by_rel: Dict[str, SourceFile] = {}
        self.step_memo = None  # a guard.StepMemo when a long-lived caller (vibeaudit watch) wants steps replayed
        self.overlays: Dict[str, bytes] = {}  # rel -> unsaved editor content, applied on the next refresh()
        self._pkg_cache: Dict[str, Optional[dict]] = {}
        self._venv_cache: Dict[str, bool] = {}
        self._discover()

    def refresh(self) -> Set[str]:
        """Look at the files again and keep every file whose size and modification time are unchanged, with
        what scanners cached for it (text, parse trees, lexer views). Returns the paths that were added,
        changed or removed. Used by long-lived callers such as `vibeaudit watch`."""
        old = self._by_rel
        self._discover(old)
        changed = {rel for rel, sf in self._by_rel.items() if old.get(rel) is not sf} | (set(old) - set(self._by_rel))
        if set(old) != set(self._by_rel):
            self.__dict__.pop("_deps", None)  # deps.collect() looks for manifests among the files
        if self.step_memo is not None and (set(old) != set(self._by_rel) or any(
                kind_of(rel) not in ("py", "js", "html") for rel in changed)):
            # a file added or removed, or a manifest or config file changed: settings read outside the replayable
            # steps (the file list, git status, deployment config) may have changed, so nothing is replayed
            self.step_memo.clear()
        return changed

    def _discover(self, previous: Optional[Dict[str, "SourceFile"]] = None) -> None:
        self.excludes = self._base_excludes + read_ignore_file(self.root / ".vibeauditignore") + ["vibeaudit-report*"]
        self.tracked, self.untracked, self.binary = set(), set(), set()
        self.files, self._by_rel = [], {}
        self._pkg_cache, self._venv_cache = {}, {}
        self.is_git = False
        rels: List[str] = []
        # one git call (a re-scan in `vibeaudit watch` pays for every process): -t tags untracked files "?";
        # outside a repository it fails and the folder is walked instead
        listed = _git(self.root, "ls-files", "-z", "-t", "--cached", "--others", "--exclude-standard")
        if listed is not None:
            self.is_git = True
            for entry in listed.split("\0"):
                if len(entry) > 2:
                    (self.untracked if entry[0] == "?" else self.tracked).add(entry[2:])
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
            if _matches(rel, self.excludes):
                continue
            if os.path.splitext(rel)[1].lower() in BINARY_EXTS:
                self.binary.add(rel)  # not read, but checks on asset links need to know it exists
                continue
            if not self.is_git and ENV_FILE_RE.search(rel) and gitignore_covers(self.root, rel):
                continue  # a local, ignored .env is how secrets are supposed to live
            path = self.root / rel
            try:
                st = os.lstat(path)  # one system call per file; a second one only for links
                if stat.S_ISLNK(st.st_mode):
                    if not _inside(path, self.root):
                        continue  # a link out of the repository (for example to ~/.ssh) is not part of the project
                    st = os.stat(path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            overlay = self.overlays.get(rel)
            sig = (st.st_mtime_ns, st.st_size) if overlay is None else ("overlay", len(overlay), hash(overlay))
            sf = previous.get(rel) if previous else None
            if sf is None or sf.signature != sig or sf.secrets_only != bundle:
                sf = SourceFile(self.root, rel, self.max_bytes)
                sf.signature = sig
                sf.overlay = overlay
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
        sf = self._by_rel.get(rel)
        if sf is not None:
            _read(sf)
        return sf

    def of_kind(self, *kinds: str) -> List[SourceFile]:
        return [f for f in self.files if f.kind in kinds]

    def package_json(self, rel_dir: str) -> Optional[dict]:
        self.get((rel_dir + "/" if rel_dir else "") + "package.json")  # records the read, also when cached below
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
