"""Reliability checks: requests without timeouts, blocking calls in async handlers, webhooks that are not
idempotent, unbounded uploads, in-memory state on serverless hosts and services without a health check."""
from __future__ import annotations

import ast
import re
from typing import Callable, List

from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Finding, Route

Emit = Callable[[Finding], None]

BLOCKING = ("time.sleep", "requests.get", "requests.post", "requests.put", "requests.patch", "requests.delete",
            "requests.request", "requests.head", "urllib.request.urlopen", "subprocess.run", "subprocess.call",
            "subprocess.check_output", "subprocess.check_call")
IDEMPOTENCY = re.compile(
    r"(?i)idempoten|event\s*\.\s*id\b|event\[\s*['\"]id['\"]\s*\]|event_id|\bupsert\b|on\s+conflict|already\s+processed"
    r"|processed_events|webhook_events|stripeEventId|stripe_event_id|\.exists\s*\(|findUnique\s*\(\s*\{\s*where:\s*\{\s*(?:event|stripe)")
WRITE = re.compile(r"(?i)\.\s*(?:create|insert|update|upsert|save|add|increment|execute)\s*\(|\bINSERT\s+INTO\b|\bUPDATE\s+\w+\s+SET\b")
HEALTH = re.compile(r"(?i)(?:^|/)(?:health|healthz|healthcheck|health-check|ready|readyz|live|livez|ping|status)(?:/|$)")
DEPLOY_FILES = re.compile(r"(?:^|/)(?:Dockerfile[\w.-]*|Containerfile[\w.-]*|docker-compose[\w.-]*\.ya?ml|compose[\w.-]*\.ya?ml|fly\.toml|render\.ya?ml|"
                          r"railway\.(?:json|toml)|app\.ya?ml|Procfile|k8s/[^/]+\.ya?ml|kubernetes/[^/]+\.ya?ml|helm/.+)$")
STATE_NAME = r"[A-Za-z_$]*(?:rate|limit|attempt|session|cache|store|counter|visits|requests|tokens|users|memory|queue|jobs)[A-Za-z_$]*"


class ReliabilityScanner:
    def __init__(self, project: Project, emit: Emit, routes: List[Route]):
        self.p = project
        self.emit = emit
        self.routes = routes

    def add(self, sf: SourceFile, rule: str, line: int, msg: str, sev: str = "") -> None:
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> None:
        self.flask_limit = any(re.search(r"MAX_CONTENT_LENGTH", f.text or "") for f in self.p.files if f.kind == "py")
        for sf in self.p.files:
            if sf.text is None or sf.is_test:
                continue
            if sf.kind == "py":
                GUARD.run(sf.rel, "reliability checks", self._python, sf)
            elif sf.kind == "js":
                GUARD.run(sf.rel, "reliability checks", self._javascript, sf)
        GUARD.run("<project>", "webhook idempotency", self._webhooks)
        GUARD.run("<project>", "health check", self._health)

    # ------------------------------------------------------------- python
    def _python(self, sf: SourceFile) -> None:
        tree = sf.cache.get("ast")
        if tree is None:
            try:
                tree = ast.parse(sf.text or "")
            except (SyntaxError, ValueError, RecursionError):
                return
        from .pyscan import dotted, walk_shallow

        for node in ast.walk(tree):
            GUARD.tick()
            if isinstance(node, ast.Call):
                d = dotted(node.func)
                kws = {k.arg for k in node.keywords}
                if (d.startswith("requests.") and d.split(".")[-1] in ("get", "post", "put", "patch", "delete", "head", "request", "options")
                        or d in ("urllib.request.urlopen", "urlopen")) and "timeout" not in kws and None not in kws:
                    self.add(sf, "REL001", node.lineno, f"`{d}()` has no timeout; one slow upstream server can hang this worker forever.")
            elif isinstance(node, ast.AsyncFunctionDef):
                # `if driven_synchronously: time.sleep() else: await asyncio.sleep()` is a deliberate dual path
                dual = {id(n) for branch in walk_shallow(node) if isinstance(branch, ast.If)
                        for mine, other in ((branch.body, branch.orelse), (branch.orelse, branch.body))
                        if any(isinstance(a, ast.Await) for s in other for a in ast.walk(s))
                        for s in mine for n in ast.walk(s)}
                for inner in walk_shallow(node):
                    if inner is node or not isinstance(inner, ast.Call) or id(inner) in dual:
                        continue
                    d = dotted(inner.func)
                    if d in BLOCKING:
                        self.add(sf, "REL002", inner.lineno, f"Blocking `{d}()` inside `async def {node.name}` stalls every other request.")
                upload_params = [a.arg for a in node.args.args if a.annotation is not None and "UploadFile" in ast.unparse(a.annotation)]
                if upload_params:
                    src = ast.unparse(node)
                    reads = re.search(r"\b(?:" + "|".join(map(re.escape, upload_params)) + r")\s*\.\s*read\s*\(\s*\)", src)
                    if reads and not re.search(r"(?i)\bsize\b|\blen\s*\(|max_?(?:file_?)?size|MAX_|limit|content.length|spool", src):
                        self.add(sf, "REL004", node.lineno, "The whole upload is read into memory with no size limit.")
            elif isinstance(node, ast.Subscript) and not self.flask_limit and ast.unparse(node.value) in ("request.files",):
                self.add(sf, "REL004", node.lineno, "File uploads are accepted but MAX_CONTENT_LENGTH is never set.")
                self.flask_limit = True  # report once per project

    # --------------------------------------------------------- javascript
    def _javascript(self, sf: SourceFile) -> None:
        v = sf.cache.get("views")
        if v is None:
            return
        code, bare = v.code, v.bare  # type: ignore[attr-defined]
        for m in finditer(r"\bmulter\s*\(", bare):
            args = code[m.end():self._close(bare, m.end() - 1)]
            if "limits" not in args:
                self.add(sf, "REL004", sf.line_at(m.start()), "multer accepts uploads without a file size limit.")
        serverless_route = bool(re.search(r"(?:^|/)app/(?:.*/)?route\.[cm]?[jt]s$|(?:^|/)pages/api/|(?:^|/)netlify/functions/|"
                                          r"(?:^|/)api/[^/]+\.[cm]?[jt]s$|\+server\.[jt]s$", sf.rel)) or bool(
            re.search(r"^\s*['\"]use server['\"]", code[:600], re.M))
        if serverless_route and (self.p.js_deps(sf.rel) & {"next", "@sveltejs/kit", "@netlify/functions", "@vercel/node"}
                                 or self._has(("vercel.json", "netlify.toml"))):
            for m in finditer(r"(?m)^(?:export\s+)?(?:const|let|var)\s+(" + STATE_NAME + r")\s*(?::[^=\n]+)?=\s*(?:new\s+(?:Map|Set|WeakMap)\s*(?:<[^>\n]{0,200}>)?\s*\(|\{\s*\}|\[\s*\])", code):
                self.add(sf, "REL005", sf.line_at(m.start()),
                         f"`{m.group(1)}` keeps state in memory, but serverless instances do not share or keep memory.")

    @staticmethod
    def _close(bare: str, open_paren: int) -> int:
        from .lexer import match_close

        end = match_close(bare, open_paren)
        return end if end > 0 else open_paren + 1

    def _has(self, names) -> bool:
        return any(f.rel.rsplit("/", 1)[-1] in names for f in self.p.files)

    # ------------------------------------------------------------ project
    def _webhooks(self) -> None:
        for r in self.routes:
            if re.search(r"(?i)webhook", r.path) and WRITE.search(r.body) and not IDEMPOTENCY.search(r.body):
                sf = self.p.get(r.file)
                if sf is not None:
                    self.add(sf, "REL003", r.line, f"Webhook {r.path} writes data without checking whether the event was already processed.")

    def _health(self) -> None:
        # development containers and test setups are not deployments
        deploy = [f for f in self.p.files if DEPLOY_FILES.search(f.rel) and not re.search(r"(?:^|/)\.devcontainer/|(?:^|/)tests?/|\.test\.|\.dev\.", f.rel)]
        servers = [r for r in self.routes if r.framework in ("python", "express", "drf")]
        if not deploy or len(servers) < 5 or any(HEALTH.search(r.path) for r in self.routes):
            return
        sf = deploy[0]
        self.add(sf, "REL006", 1, f"The service is deployed ({sf.rel}) and has {len(servers)} routes but no health-check endpoint.")
