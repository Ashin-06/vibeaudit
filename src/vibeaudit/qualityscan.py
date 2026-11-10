"""Code completeness: unfinished stubs, imports of files or names that do not exist, and packages that are
imported but never declared (they work on the author's machine and crash on deploy)."""
from __future__ import annotations

import ast
import json
import os
import posixpath
import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from .deps import collect, pep503
from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Finding
from .stdlib import NODE_BUILTINS, PYTHON_STDLIB

Emit = Callable[[Finding], None]

# import name -> distribution names that provide it (only where the two differ by more than - and _)
IMPORT_TO_DIST: Dict[str, Tuple[str, ...]] = {
    "yaml": ("pyyaml",), "PIL": ("pillow",), "cv2": ("opencv-python", "opencv-python-headless", "opencv-contrib-python"),
    "sklearn": ("scikit-learn",), "skimage": ("scikit-image",), "bs4": ("beautifulsoup4",), "dotenv": ("python-dotenv",),
    "jwt": ("pyjwt",), "jose": ("python-jose",), "attr": ("attrs",), "dateutil": ("python-dateutil",),
    "magic": ("python-magic",), "docx": ("python-docx",), "pptx": ("python-pptx",), "multipart": ("python-multipart",),
    "socketio": ("python-socketio",), "engineio": ("python-engineio",), "telegram": ("python-telegram-bot",),
    "discord": ("discord.py", "py-cord"), "Crypto": ("pycryptodome", "pycrypto"), "Cryptodome": ("pycryptodomex",),
    "OpenSSL": ("pyopenssl",), "git": ("gitpython",), "serial": ("pyserial",), "usb": ("pyusb",), "fitz": ("pymupdf",),
    "psycopg2": ("psycopg2-binary", "psycopg2"), "psycopg": ("psycopg", "psycopg-binary"), "MySQLdb": ("mysqlclient",),
    "faiss": ("faiss-cpu", "faiss-gpu"), "sentencepiece": ("sentencepiece",), "google": ("google-*", "protobuf"),
    "googleapiclient": ("google-api-python-client",), "grpc": ("grpcio",), "pkg_resources": ("setuptools",),
    "setuptools": ("setuptools",), "markdown": ("markdown",), "ldap": ("python-ldap",), "zmq": ("pyzmq",),
    "win32api": ("pywin32",), "win32com": ("pywin32",), "lxml": ("lxml",), "Levenshtein": ("python-levenshtein", "levenshtein"),
    "slugify": ("python-slugify",), "jinja2": ("jinja2",), "speech_recognition": ("speechrecognition",),
    "tiktoken": ("tiktoken",), "llama_index": ("llama-index", "llama-index-core"), "ruamel": ("ruamel.yaml",),
    "azure": ("azure-*",), "mpl_toolkits": ("matplotlib",), "pydantic_core": ("pydantic",),
    "sentry_sdk": ("sentry-sdk",), "flask_sqlalchemy": ("flask-sqlalchemy",), "rest_framework": ("djangorestframework",),
    "corsheaders": ("django-cors-headers",), "environ": ("django-environ", "environs"), "storages": ("django-storages",),
    "debug_toolbar": ("django-debug-toolbar",), "crispy_forms": ("django-crispy-forms",), "allauth": ("django-allauth",),
    "celery": ("celery",), "kombu": ("kombu", "celery"), "starlette": ("starlette", "fastapi"), "pydantic": ("pydantic", "fastapi", "sqlmodel"),
    "anyio": ("anyio", "fastapi", "httpx", "starlette"), "httpcore": ("httpx",), "h11": ("httpx", "uvicorn"), "click": ("click", "flask", "typer"),
    "werkzeug": ("werkzeug", "flask"), "itsdangerous": ("itsdangerous", "flask"), "markupsafe": ("markupsafe", "jinja2", "flask"),
    "langchain_core": ("langchain-core", "langchain"), "langchain_community": ("langchain-community", "langchain"),
    "langchain_text_splitters": ("langchain-text-splitters", "langchain"), "sqlalchemy": ("sqlalchemy", "sqlmodel", "flask-sqlalchemy"),
    "urllib3": ("urllib3", "requests"), "certifi": ("certifi", "requests", "httpx"), "idna": ("idna", "requests", "httpx"),
    "charset_normalizer": ("charset-normalizer", "requests"), "dns": ("dnspython",), "nacl": ("pynacl",), "jwcrypto": ("jwcrypto",),
    "playhouse": ("peewee",), "botocore": ("botocore", "boto3"), "s3transfer": ("s3transfer", "boto3"),
    "psycopg_pool": ("psycopg-pool", "psycopg"), "langsmith": ("langsmith", "langchain", "langchain-core"),
    "typing_extensions": ("typing-extensions", "pydantic", "fastapi", "sqlalchemy", "anyio"), "google_auth_oauthlib": ("google-auth-oauthlib",),
    "django_filters": ("django-filter",), "rest_framework_jwt": ("drf-jwt", "djangorestframework-jwt"),
    "rest_framework_simplejwt": ("djangorestframework-simplejwt",), "knox": ("django-rest-knox",),
}
JS_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro", ".json", ".d.ts")
ASSET_EXT = re.compile(r"\.(css|scss|sass|less|styl|svg|png|jpe?g|gif|webp|avif|ico|bmp|woff2?|ttf|otf|eot|mp3|mp4|webm|wav|txt|md|mdx|html|wasm|graphql|gql|yaml|yml|toml|csv)$", re.I)
# Statements start at a line start or after `;` / `}`; only horizontal space may follow (a `\s*` there would
# rescan runs of blank lines from every line start), and the import clause is bounded.
JS_IMPORT = re.compile(
    r"""(?:^|[;}])[ \t]*import[ \t]+(type[ \t]+)?(?:([\w$*{}\s,]{1,2000}?)\s+from[ \t]*)?['"]([^'"\n]+)['"]"""
    r"""|(?:^|[;}])[ \t]*export[ \t]+(?:type[ \t]+)?(?:\*|\{[^}]{0,2000}\})(?:\s+as\s+[\w$]+)?\s+from[ \t]*['"]([^'"\n]+)['"]"""
    r"""|\brequire\s*\(\s*['"]([^'"\n]+)['"]\s*\)"""
    r"""|\bimport\s*\(\s*['"]([^'"\n]+)['"]\s*\)""",
    re.M,
)
# example and documentation code runs with whatever the reader installs, not with the project's dependencies
NOT_DEPLOYED = re.compile(r"(?i)(?:^|/)(?:examples?|docs?|samples?)/")
NOT_IMPLEMENTED_JS = re.compile(r"""\bthrow\s+new\s+Error\s*\(\s*['"`](?:not\s+(?:yet\s+)?implemented|unimplemented|implement\s+me|todo\b)[^'"`]*['"`]\s*\)""", re.I)


def _strip_jsonc(text: str) -> str:
    """tsconfig.json allows comments and trailing commas. The JS lexer removes comments without touching
    strings such as "@/*" (a naive regex treats that as the start of a block comment)."""
    from .lexer import js_views

    v = js_views(text)
    code = list(v.code)
    for m in re.finditer(r",(\s*[}\]])", v.bare):
        code[m.start()] = " "
    return "".join(code)


def _module_names(tree: ast.Module) -> Optional[Set[str]]:
    """Names a module defines at module level (also inside module-level if/try/with/for), names declared
    `global` inside functions, and names listed in __all__. Parameters and locals are not module names.
    None when a star import makes the set unknowable."""
    names: Set[str] = set()

    def targets(node: ast.AST) -> None:
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                names.add(n.id)

    def block(stmts) -> bool:
        for st in stmts:
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(st.name)
                if not isinstance(st, ast.ClassDef):
                    for n in ast.walk(st):
                        if isinstance(n, ast.Global):
                            names.update(n.names)
            elif isinstance(st, (ast.Import, ast.ImportFrom)):
                for a in st.names:
                    if a.name == "*":
                        return False
                    names.add((a.asname or a.name).split(".")[0])
            elif isinstance(st, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                for t in (st.targets if isinstance(st, ast.Assign) else [st.target]):
                    targets(t)
                    if isinstance(t, ast.Name) and t.id == "__all__" and isinstance(st.value, (ast.List, ast.Tuple)):
                        names.update(e.value for e in st.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str))
            elif isinstance(st, (ast.For, ast.AsyncFor)):
                targets(st.target)
                if not (block(st.body) and block(st.orelse)):
                    return False
            elif isinstance(st, (ast.If, ast.While)):
                if not (block(st.body) and block(st.orelse)):
                    return False
            elif isinstance(st, (ast.With, ast.AsyncWith)):
                for item in st.items:
                    if item.optional_vars is not None:
                        targets(item.optional_vars)
                if not block(st.body):
                    return False
            elif isinstance(st, ast.Try) or type(st).__name__ == "TryStar":
                for h in st.handlers:  # type: ignore[attr-defined]
                    if h.name:
                        names.add(h.name)
                    if not block(h.body):
                        return False
                if not (block(st.body) and block(st.orelse) and block(st.finalbody)):  # type: ignore[attr-defined]
                    return False
            elif isinstance(st, ast.Expr):
                for n in ast.walk(st):
                    if isinstance(n, ast.NamedExpr):
                        targets(n.target)
        return True

    return names if block(tree.body) else None


class QualityScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit
        self.declared_py: Set[str] = set()
        self.py_manifest = False
        self.reported_py: Set[str] = set()
        self.reported_js: Dict[str, Set[str]] = {}
        self._bases: Optional[Set[str]] = None

    def add(self, sf: SourceFile, rule: str, line: int, msg: str, sev: str = "") -> None:
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> None:
        GUARD.run("<project>", "dependency declarations", self._load_declared)
        self.local_py = self._local_python_names()
        self.ts_configs = self._ts_configs()
        for sf in self.p.files:
            if sf.text is None or sf.is_test:
                continue
            if sf.kind == "py":
                GUARD.run(sf.rel, "completeness checks", self._python, sf)
            elif sf.kind == "js":
                GUARD.run(sf.rel, "completeness checks", self._javascript, sf)

    # ----------------------------------------------------------- declared
    def _load_declared(self) -> None:
        for d in collect(self.p):
            if d.ecosystem == "PyPI":
                self.declared_py.add(pep503(d.name))
        for f in self.p.files:
            name = f.rel.rsplit("/", 1)[-1]
            if re.fullmatch(r"requirements[\w.-]*\.(?:txt|in)|pyproject\.toml|Pipfile|setup\.py|setup\.cfg", name):
                self.py_manifest = True
                if name in ("setup.py", "setup.cfg", "Pipfile") and f.text:
                    # install_requires / Pipfile entries: take every quoted or bare requirement-looking name
                    for m in re.finditer(r"""['"]?([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~;\[]|['"]\s*[,\]])""", f.text):
                        self.declared_py.add(pep503(m.group(1)))
                    if name == "setup.py" and "install_requires" not in f.text:
                        self.py_manifest = False  # dependencies are computed elsewhere; do not guess

    def _local_python_names(self) -> Set[str]:
        names: Set[str] = set()
        for f in self.p.files:
            parts = f.rel.split("/")
            for i, part in enumerate(parts):
                stem = part[:-3] if part.endswith(".py") else part
                if i == len(parts) - 1 and not part.endswith((".py", ".pyi", ".so", ".pyd", ".pyx")):
                    continue
                names.add(stem.split(".")[0])
        return names

    def _py_declared(self, top: str) -> bool:
        options = {pep503(top), pep503(top.replace("_", "-")), pep503("python-" + top), pep503(top + "-python"), pep503("py" + top)}
        for dist in IMPORT_TO_DIST.get(top, ()):
            if dist.endswith("*"):
                if any(d.startswith(pep503(dist[:-1])) for d in self.declared_py):
                    return True
            options.add(pep503(dist))
        name = pep503(top)
        # `structlog` from django-structlog, `oauthlib` from google-auth-oauthlib: a declared distribution whose
        # name contains the import name as a segment is taken to provide it
        return bool(options & self.declared_py) or any(d.startswith(name + "-") or name in d.split("-") for d in self.declared_py)

    # ------------------------------------------------------------- python
    def _python(self, sf: SourceFile) -> None:
        tree = sf.cache.get("ast")
        if tree is None:
            try:
                tree = ast.parse(sf.text or "")
            except (SyntaxError, ValueError, RecursionError):
                return
            sf.cache["ast"] = tree
        guarded = self._optional_import_nodes(tree)
        reported = self.reported_py  # one finding per undeclared package per project, not one per file
        for node in ast.walk(tree):
            GUARD.tick()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._python_stub(sf, node, tree)
            if id(node) in guarded:
                continue
            if isinstance(node, ast.ImportFrom) and node.level:
                self._relative_import(sf, node)
            elif isinstance(node, ast.ImportFrom) and node.module:
                self._absolute_import(sf, node, node.module, reported)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    self._absolute_import(sf, node, alias.name, reported)

    @staticmethod
    def _optional_import_nodes(tree: ast.AST) -> Set[int]:
        """Imports inside `try: ... except ImportError`, `if TYPE_CHECKING:` or a Python version or platform
        check (`if sys.version_info >= (3, 15):`, `if sys.platform == "win32":`) are optional by design."""
        out: Set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Try) and any(
                    h.type is None or re.search(r"ImportError|ModuleNotFoundError|Exception", ast.unparse(h.type)) for h in node.handlers):
                out.update(id(n) for st in node.body for n in ast.walk(st))
            elif isinstance(node, ast.If) and re.search(r"TYPE_CHECKING|version_info|\bplatform\b|os\.name", ast.unparse(node.test)):
                out.update(id(n) for st in node.body + node.orelse for n in ast.walk(st))
        return out

    def _absolute_import(self, sf: SourceFile, node: ast.AST, module: str, reported: Set[str]) -> None:
        top = module.split(".")[0]
        if not top or top in PYTHON_STDLIB or top == "__main__" or self._py_declared(top):
            return
        if top in self.local_py:
            if isinstance(node, ast.ImportFrom):
                self._local_absolute(sf, node, module)
            return
        if NOT_DEPLOYED.search(sf.rel):
            return  # examples and docs are not deployed with the project's dependencies
        if self.py_manifest and top not in reported and not self._py_declared(top):
            reported.add(top)
            self.add(sf, "QA007", node.lineno, f"`{top}` is imported but not declared in the project's Python dependencies.")  # type: ignore[attr-defined]

    def _module_file(self, base: str, dotted: str) -> Tuple[Optional[str], bool]:
        """(path of the module's file or __init__.py, whether the module exists at all)."""
        path = posixpath.normpath(posixpath.join(base, *dotted.split("."))) if dotted else base
        path = "" if path == "." else path
        for candidate in (path + ".py", path + ".pyi", posixpath.join(path, "__init__.py"), posixpath.join(path, "__init__.pyi")):
            if self.p.get(candidate.lstrip("/")):
                return candidate.lstrip("/"), True
        disk = self.p.root / path if path else self.p.root
        if disk.is_dir() or any((self.p.root / (path + ext)).exists() for ext in (".so", ".pyd", ".pyx", ".py")):
            return None, True  # namespace package, compiled or excluded module
        return None, False

    def _relative_import(self, sf: SourceFile, node: ast.ImportFrom) -> None:
        base = posixpath.dirname(sf.rel)
        for _ in range(node.level - 1):
            base = posixpath.dirname(base)
        self._check_from(sf, node, base, node.module or "")

    def _local_absolute(self, sf: SourceFile, node: ast.ImportFrom, module: str) -> None:
        """`from app.utils import x` where `app` is a package in this repository."""
        top = module.split(".")[0]
        marker = top + "/__init__.py"
        roots = {f.rel[: -len(marker)].rstrip("/") for f in self.p.files if ("/" + f.rel).endswith("/" + marker)}
        if len(roots) != 1:
            return  # no package, several packages with that name, or a plain module: do not guess
        self._check_from(sf, node, next(iter(roots)), module)

    def _check_from(self, sf: SourceFile, node: ast.ImportFrom, base: str, module: str) -> None:
        file, exists = self._module_file(base, module)
        label = "." * node.level + module
        if not exists:
            self.add(sf, "QA006", node.lineno, f"`from {label} import ...`: module `{label}` does not exist in the project.")
            return
        if file is None:
            return
        names = self._defined_names(file)
        if names is None:
            return
        pkg_dir = posixpath.dirname(file) if file.endswith(("__init__.py", "__init__.pyi")) else None
        for alias in node.names:
            if alias.name == "*" or alias.name in names:
                continue
            if pkg_dir is not None and self._module_file(pkg_dir, alias.name)[1]:
                continue  # a submodule of the package
            self.add(sf, "QA006", node.lineno, f"`{alias.name}` is imported from `{label}` but is not defined there.")

    def _defined_names(self, rel: str) -> Optional[Set[str]]:
        sf = self.p.get(rel)
        if sf is None or sf.text is None:
            return None
        tree = sf.cache.get("ast")
        if tree is None:
            try:
                tree = ast.parse(sf.text)
            except (SyntaxError, ValueError, RecursionError):
                return None
            sf.cache["ast"] = tree
        names = _module_names(tree)
        if names is None or "__getattr__" in names or re.search(r"globals\(\)\s*\[", sf.text or ""):
            return None
        return names

    def _subclassed(self) -> Set[str]:
        """Names of every class used as a base class somewhere in the project's Python code."""
        if self._bases is None:
            self._bases = set()
            for f in self.p.files:
                if f.kind != "py" or f.text is None or "class " not in f.text:
                    continue
                tree = f.cache.get("ast")
                if tree is None:
                    continue  # not parsed (syntax error): no base classes to learn from it
                for node in ast.walk(tree):  # type: ignore[arg-type]
                    if isinstance(node, ast.ClassDef):
                        self._bases.update(ast.unparse(b).split(".")[-1].split("[")[0] for b in node.bases)
        return self._bases

    def _python_stub(self, sf: SourceFile, fn: ast.AST, tree: ast.Module) -> None:
        body = [s for s in fn.body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str))]  # type: ignore[attr-defined]
        if len(body) != 1:
            return
        st = body[0]
        not_impl = isinstance(st, ast.Raise) and st.exc is not None and "NotImplementedError" in ast.unparse(st.exc)
        empty = isinstance(st, ast.Pass) or (isinstance(st, ast.Expr) and isinstance(st.value, ast.Constant) and st.value.value is Ellipsis)
        if not (not_impl or empty):
            return
        decorators = " ".join(ast.unparse(d) for d in fn.decorator_list)  # type: ignore[attr-defined]
        if re.search(r"abstract|overload|override|setter|deleter|property|staticmethod\b.*abstract", decorators):
            return
        owner = next((c for c in ast.walk(tree) if isinstance(c, ast.ClassDef) and fn in c.body), None)
        if owner is not None:
            bases = " ".join(ast.unparse(b) for b in owner.bases) + " " + " ".join(ast.unparse(k.value) for k in owner.keywords)
            if re.search(r"ABC|Protocol|Interface|Base|Mixin|Abstract|metaclass", bases + " " + owner.name) or empty:
                return  # interface methods and no-op hooks in classes are normal
            if owner.name in self._subclassed():
                return  # a class the project subclasses: NotImplementedError means "override me"
        is_route = bool(re.search(r"\.(?:route|get|post|put|patch|delete|api_route)\(|api_view", decorators))
        if is_route:
            self.add(sf, "QA005", fn.lineno, f"Route handler `{fn.name}()` is an unfinished stub.")  # type: ignore[attr-defined]
        elif not_impl:
            self.add(sf, "QA005", fn.lineno, f"`{fn.name}()` raises NotImplementedError.")  # type: ignore[attr-defined]


    # --------------------------------------------------------- javascript
    def _ts_configs(self) -> Dict[str, Tuple[List[Tuple[str, str]], Optional[str]]]:
        """Per tsconfig/jsconfig directory: (`paths` aliases as (prefix, target dir) pairs, baseUrl dir or None)."""
        out: Dict[str, Tuple[List[Tuple[str, str]], Optional[str]]] = {}
        for f in self.p.files:
            name = f.rel.rsplit("/", 1)[-1]
            if not re.fullmatch(r"(?:ts|js)config(?:\.[\w-]+)?\.json", name) or not f.text:
                continue
            try:
                data = json.loads(_strip_jsonc(f.text))
            except ValueError:
                continue
            opts = data.get("compilerOptions") if isinstance(data, dict) else None
            if not isinstance(opts, dict):
                continue
            folder = posixpath.dirname(f.rel)
            base = posixpath.normpath(posixpath.join(folder, str(opts.get("baseUrl", "."))))
            base = "" if base == "." else base
            aliases: List[Tuple[str, str]] = []
            for key, targets in (opts.get("paths") or {}).items() if isinstance(opts.get("paths"), dict) else []:
                if isinstance(targets, list) and targets and isinstance(targets[0], str) and key.endswith("*") and targets[0].endswith("*"):
                    tgt = posixpath.normpath(posixpath.join(base or ".", targets[0][:-1]))
                    aliases.append((key[:-1], "" if tgt == "." else tgt + "/"))
            previous = out.get(folder)
            if previous is None or name.startswith("tsconfig.json"):
                out[folder] = (sorted(aliases, key=lambda p: -len(p[0])), base if "baseUrl" in opts else None)
        return out

    def _ts_config_for(self, rel: str) -> Tuple[List[Tuple[str, str]], Optional[str]]:
        parts = rel.split("/")[:-1]
        while True:
            key = "/".join(parts)
            if key in self.ts_configs:
                return self.ts_configs[key]
            if not parts:
                return [], None
            parts.pop()

    def _resolve_js(self, sf: SourceFile, spec: str) -> Tuple[Optional[str], bool]:
        """(resolved file, whether it exists). Unresolvable aliases return (None, True): do not guess."""
        aliases, base_url = self._ts_config_for(sf.rel)
        if spec.startswith("."):
            base = posixpath.normpath(posixpath.join(posixpath.dirname(sf.rel), spec))
        else:
            alias = next(((p, t) for p, t in aliases if spec.startswith(p)), None)
            if alias is None and base_url is not None:
                alias = ("", base_url + "/" if base_url else "")
            if alias is None:
                if spec.startswith(("@/", "~/")) and (self.p.root / "src").is_dir():
                    alias = (spec[:2], "src/")
                else:
                    return None, True
            base = posixpath.normpath(alias[1] + spec[len(alias[0]):])
        if ASSET_EXT.search(base):
            return None, True  # styles, images and other assets: the bundler's territory
        candidates = [base]
        stem, ext = os.path.splitext(base)
        if ext in (".js", ".jsx", ".mjs", ".cjs"):
            candidates += [stem + e for e in (".ts", ".tsx", ".mts", ".cts")]  # ESM TypeScript: './a.js' is a.ts
        candidates += [base + e for e in JS_EXTS] + [posixpath.join(base, "index" + e) for e in JS_EXTS]
        for c in candidates:
            if self.p.get(c):
                return c, True
            if (self.p.root / c).is_file():
                return None, True  # exists but excluded from the scan (generated code, too large)
        return None, False

    def _javascript(self, sf: SourceFile) -> None:
        v = sf.cache.get("views")
        code = v.code if v is not None else (sf.text or "")  # type: ignore[attr-defined]
        rel = sf.rel
        if rel.endswith(".d.ts"):
            return
        # @ts-nocheck counts only before the first statement (after any header comments); report its own line
        generated = re.search(r"\.gen(?:erated)?\.|(?:^|/)(?:generated|__generated__)/", rel) or re.search(
            r"(?i)auto-?generated|do not (?:edit|modify)|@generated|generated by", (sf.text or "")[:1000])
        nocheck = re.match(r"(?:\s|//[^\n]*\n|/\*(?:[^*]|\*(?!/)){0,5000}\*/)*?//[ \t]*@ts-nocheck\b", sf.text or "") \
            if rel.endswith((".ts", ".tsx")) and not generated else None  # generated code may skip type checks
        if nocheck:
            self.add(sf, "QA008", sf.line_at(nocheck.end() - 1), "TypeScript type checking is disabled for this whole file.")
        for m in finditer(NOT_IMPLEMENTED_JS, code):
            self.add(sf, "QA005", sf.line_at(m.start()), "Code throws a 'not implemented' error; this path is unfinished.")
        deno = "/supabase/functions/" in "/" + rel or self._near(rel, ("deno.json", "deno.jsonc", "import_map.json"))
        declared = None if deno else self._js_declared(rel)
        reported = self.reported_js.setdefault(self._package_dir(rel), set())  # once per package.json, not per file
        for m in finditer(JS_IMPORT, code):
            spec = m.group(3) or m.group(4) or m.group(5) or m.group(6)
            if not spec or "?" in spec or "!" in spec or "*" in spec or ":" in spec.split("/")[0] or spec.startswith("/"):
                continue
            # the match may start at the previous statement's `;` or `}`: report the line of the keyword itself
            line = sf.line_at(m.start() + re.search(r"[A-Za-z]", m.group(0)).start())  # type: ignore[union-attr]
            aliases, base_url = self._ts_config_for(rel)
            first = spec.split("/")[0]
            via_base_url = base_url is not None and not spec.startswith("@") and (
                (self.p.root / (base_url or ".") / first).exists() or any((self.p.root / (base_url or ".") / (first + e)).exists() for e in JS_EXTS))
            if spec.startswith(".") or any(spec.startswith(p) for p, _t in aliases) or spec.startswith(("@/", "~/")) or via_base_url:
                target, exists = self._resolve_js(sf, spec)
                if not exists:
                    self.add(sf, "QA006", line, f"Import `{spec}` does not resolve to a file in the project.")
                elif target and m.group(2) and not m.group(1):
                    self._check_js_names(sf, line, spec, target, m.group(2))
                continue
            if declared is None or spec.startswith(("#", "$", "virtual:", "~")):
                continue
            pkg = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
            if pkg in NODE_BUILTINS or pkg.startswith("node:") or pkg in declared or pkg in reported or m.group(1) or NOT_DEPLOYED.search(rel):
                continue
            if pkg.startswith("@types/") or ("@types/" + pkg) in declared:
                continue
            if pkg.startswith("@") and any(d.startswith(pkg.split("/")[0] + "/") for d in declared):
                continue  # a sibling of a declared package from the same scope (installed together)
            reported.add(pkg)
            self.add(sf, "QA007", line, f"`{pkg}` is imported but not listed in package.json.")

    def _package_dir(self, rel: str) -> str:
        """Folder of the nearest package.json above `rel` ("" when there is none)."""
        parts = rel.split("/")[:-1]
        while parts and self.p.package_json("/".join(parts)) is None:
            parts.pop()
        return "/".join(parts)

    def _near(self, rel: str, names: Tuple[str, ...]) -> bool:
        parts = rel.split("/")[:-1]
        while True:
            for n in names:
                if self.p.get("/".join(parts + [n]).lstrip("/")):
                    return True
            if not parts:
                return False
            parts.pop()

    def _js_declared(self, rel: str) -> Optional[Set[str]]:
        found = False
        out: Set[str] = set()
        parts = rel.split("/")[:-1]
        while True:
            pkg = self.p.package_json("/".join(parts))
            if pkg is not None:
                found = True
                for key in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                    if isinstance(pkg.get(key), dict):
                        out.update(pkg[key])
                if isinstance(pkg.get("name"), str):
                    out.add(pkg["name"])
                if pkg.get("workspaces"):
                    out.update(self._workspace_names())
            if not parts:
                break
            parts.pop()
        return out if found else None

    def _workspace_names(self) -> Set[str]:
        names = set()
        for f in self.p.files:
            if f.rel.endswith("package.json"):
                d = f.rel.rsplit("/", 1)[0] if "/" in f.rel else ""
                pkg = self.p.package_json(d) or {}
                if isinstance(pkg.get("name"), str):
                    names.add(pkg["name"])
        return names

    def _check_js_names(self, sf: SourceFile, line: int, spec: str, target: str, clause: str) -> None:
        tf = self.p.get(target)
        if tf is None or not tf.text or target.endswith((".vue", ".svelte", ".astro", ".json")):
            return
        views = tf.cache.get("views")
        if views is None:
            from .lexer import js_views

            views = js_views(tf.text)
        text = views.code  # type: ignore[attr-defined]  # comments blanked: a commented-out export is not an export
        if re.search(r"\bexport\s*\*\s*from|module\.exports|\bexports\.\w+\s*=", text):
            return  # re-exports or CommonJS: too dynamic to check by name
        m = re.search(r"\{([^}]*)\}", clause)
        if not m:
            return
        # `export { a as b, c }` exports b and c (not a); `export { x as default }` exports only default
        listed = {item.strip().split(" as ")[-1].strip() for lst in re.findall(r"\bexport\s*(?:type\s*)?\{([^}]{0,5000})\}", text)
                  for item in lst.split(",")}
        listed = {re.sub(r"^type\s+", "", n) for n in listed}
        for part in m.group(1).split(","):
            name = part.strip().split(" as ")[0].strip()
            if not name or name.startswith("type ") or name == "default":
                continue
            exported = name in listed or re.search(
                r"\bexport\s+(?:declare\s+)?(?:default\s+)?(?:async\s+)?(?:function\*?|class|const|let|var|type|interface|enum|abstract\s+class|namespace)\s+"
                + re.escape(name) + r"\b", text) \
                or re.search(r"\bexport\s+(?:const|let|var)\s*[{\[](?:[^{}\[\]]|[{\[][^{}\[\]]*[}\]])*?\b" + re.escape(name) + r"\b", text)
            if not exported:
                self.add(sf, "QA006", line, f"`{name}` is imported from `{spec}` but that file does not export it.")
