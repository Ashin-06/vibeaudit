"""Routes for RPC-style APIs, so the route checks (AUTH001-003) apply to them: tRPC procedures, GraphQL resolvers
(Apollo-style resolver maps, Strawberry, graphene) and gRPC service handlers (Go, Python, Node, Java).

Each procedure, resolver or handler becomes a Route named `/trpc/NAME`, `/graphql/NAME` or `/grpc/NAME`. Its method
comes from what it is (a tRPC query or a GraphQL Query field is a GET) or from its name (`deleteUser` is a DELETE,
`updateUser` a PUT), and a create still needs a write in its body before AUTH001 calls it state-changing."""
from __future__ import annotations

import ast
import re
from typing import Dict, List, Optional, Tuple

from . import heuristics as H
from .files import Project, SourceFile
from .guard import GUARD, finditer
from .lexer import js_views, match_close
from .model import Route

VERB = [(re.compile(r"(?i)^(?:delete|remove|destroy|purge|drop|archive|revoke|ban)"), "DELETE"),
        (re.compile(r"(?i)^(?:update|edit|set|patch|modify|change|rename|toggle|move|assign|replace|reset)"), "PUT"),
        (re.compile(r"(?i)^(?:get|list|find|search|fetch|read|query|watch|stream|count|check|lookup|describe|me$|health)"), "GET")]
ID_FIELD = re.compile(r"\b(?:input|args|request|req|in|data)\s*(?:\??\.\s*|\[\s*['\"])(?:Get)?(\w*?(?:[iI]d|ID))\b")
# a GraphQL server that rejects anonymous requests before any resolver runs, or a shield / auth directive
GQL_GLOBAL_AUTH = re.compile(r"\bshield\s*\(|@(?:auth|authenticated|requiresAuth|isAuthenticated|hasRole)\b")
GQL_CONTEXT_THROW = re.compile(r"(?s)\bcontext\s*[:=(][^;]{0,1500}?\bthrow\b[^;]{0,200}?(?:AuthenticationError|UNAUTHENTICATED|Unauthorized)")
PROTECTED_NAME = re.compile(r"(?i)protected|authed|authenticated|auth|private|admin|logged|member|user|session|owner|org|team|staff")
INTERCEPTOR = re.compile(r"(?i)(?:UnaryInterceptor|StreamInterceptor|interceptors\s*=|ServerInterceptors\s*\.\s*intercept"
                         r"|@GrpcService\s*\([^)]*interceptors|@GrpcGlobalServerInterceptor)[^;]{0,400}?"
                         r"(?:auth|jwt|token|guard|verify|secur|session|apikey|api_key)")


JAVA_HANDLER = re.compile(r"(?:\bpublic\s+void|\boverride\s+fun)\s+(\w+)\s*\([^)]*StreamObserver[^)]*\)[^{]*\{"
                          r"|\boverride\s+suspend\s+fun\s+(\w+)\s*\([^)]*\)[^{]*\{")


def verb(name: str, default: str = "POST") -> str:
    return next((v for rx, v in VERB if rx.search(name)), default)


class RpcScanner:
    def __init__(self, project: Project):
        self.p = project
        self.routes: List[Route] = []
        self.procedures: Dict[str, str] = {}

    def add(self, sf: SourceFile, off_line: int, path: str, method: str, body: str, framework: str, lang: str,
            auth: bool = False) -> None:
        has_auth = auth or bool(H.AUTH_EVIDENCE.search(body) or H.CUSTOM.is_auth(body))
        params = sorted(set(ID_FIELD.findall(body)))
        self.routes.append(Route(sf.rel, off_line, path, [method], body, framework, lang, has_auth=has_auth,
                                 params=params))  # inputs are schema-typed (zod, GraphQL, protobuf): not BE018

    def run(self) -> List[Route]:
        files = [f for f in self.p.files if f.text and not f.is_test]
        js = [f for f in files if f.kind == "js"]
        trpc = [f for f in js if re.search(r"(?i)trpc|procedure\b", f.text or "")]
        for f in trpc:  # custom procedures: `export const adminProcedure = protectedProcedure.use(...)`
            for m in finditer(r"(?:const|let|var)\s+([\w$]*[pP]rocedure)\s*=\s*([^;]{0,2000})", f.text or ""):
                self.procedures[m.group(1)] = m.group(2)
        gql_auth = any(GQL_GLOBAL_AUTH.search(f.text or "") or GQL_CONTEXT_THROW.search(f.text or "") for f in files
                       if f.kind in ("js", "py") or f.rel.endswith((".graphql", ".gql")))
        # an auth interceptor covers the handlers of its own language only
        grpc_auth = {lang: any(INTERCEPTOR.search(f.text or "") for f in files if f.rel.endswith(exts))
                     for lang, exts in (("go", (".go",)), ("py", (".py",)), ("js", (".js", ".ts", ".mjs", ".cjs")),
                                        ("jvm", (".java", ".kt")))}
        go_services = set()
        for f in files:
            if f.rel.endswith(".go"):
                go_services.update(re.findall(r"type\s+(\w+)\s+struct\s*\{[^}]{0,2000}?\bUnimplemented\w*Server\b", f.text or ""))
        for f in files:
            text = f.text or ""
            if f in trpc and re.search(r"\.\s*(?:mutation|query)\s*\(", text):
                GUARD.run(f.rel, "rpc routes", self.trpc, f)
            if f.kind == "js" and re.search(r"\bMutation\s*:\s*\{", text):
                GUARD.run(f.rel, "rpc routes", self.gql_js, f, gql_auth)
            if f.kind == "js" and ".addService" in text:
                GUARD.run(f.rel, "rpc routes", self.grpc_node, f, grpc_auth["js"])
            if f.kind == "py" and re.search(r"strawberry|graphene|Servicer\b", text):
                GUARD.run(f.rel, "rpc routes", self.python, f, gql_auth, grpc_auth["py"])
            if f.rel.endswith(".go") and go_services:
                GUARD.run(f.rel, "rpc routes", self.grpc_go, f, go_services, grpc_auth["go"])
            if f.rel.endswith((".java", ".kt")) and "ImplBase" in text:
                GUARD.run(f.rel, "rpc routes", self.grpc_java, f, grpc_auth["jvm"])
        return self.routes

    # ------------------------------------------------------------------ tRPC
    def procedure_text(self, name: str, depth: int = 0) -> Tuple[bool, str]:
        """Whether a procedure requires a login, and the text that defines it (for the admin-role check)."""
        if name in ("publicProcedure", "procedure") or depth > 3:
            return False, ""
        text = self.procedures.get(name, "")
        if not text:
            return bool(PROTECTED_NAME.search(name)), name
        base = re.match(r"\s*([\w$]+)", text)
        auth, inner = self.procedure_text(base.group(1), depth + 1) if base else (False, "")
        auth = auth or bool(PROTECTED_NAME.search(name) and not re.search(r"(?i)public", name)) \
            or bool(re.search(r"UNAUTHORIZED|FORBIDDEN", text) or H.AUTH_EVIDENCE.search(text))
        return auth, inner + "\n" + text

    def trpc(self, sf: SourceFile) -> None:
        v = js_views(sf.text or "")
        code, bare = v.code, v.bare
        for m in finditer(r"(?<![\w$.])([\w$]+)\s*:\s*((?:[\w$]+\s*\.\s*)?[\w$]*[pP]rocedure)\b", code):
            pos, chain, kind, handler = m.end(), "", "", ""
            for _ in range(20):
                step = re.match(r"\s*\.\s*([\w$]+)\s*(?:<[^()]{0,200}>)?\s*\(", bare[pos:pos + 300])
                if not step:
                    break
                paren = pos + step.end() - 1
                close = match_close(bare, paren)
                if close < 0:
                    break
                if step.group(1) in ("mutation", "query", "subscription"):
                    kind, handler = step.group(1), code[paren + 1:close]
                    break
                chain += code[pos:close + 1]
                pos = close + 1
            if kind not in ("mutation", "query"):
                continue
            base = re.sub(r"\s", "", m.group(2))
            auth, definition = self.procedure_text(base.rsplit(".", 1)[-1] if base.endswith("Procedure") else
                                                   ("procedure" if base.endswith("procedure") else base))
            auth = auth or bool(re.search(r"\.\s*use\s*\(\s*[\w$]*(?:auth|Auth|protect|session|user|User)", chain))
            method = "GET" if kind == "query" else verb(m.group(1))
            self.add(sf, sf.line_at(m.start()), "/trpc/" + m.group(1), method,
                     definition + "\n" + base + chain + "\n" + handler, "trpc", "js", auth)

    # --------------------------------------------------------------- GraphQL
    def object_members(self, code: str, bare: str, brace: int):
        """(name, start, text) for each member of the object literal opening at `brace`."""
        end = match_close(bare, brace)
        if end < 0:
            return
        i = brace + 1
        while i < end:
            m = re.compile(r"\s*(?:async\s+)?([\w$]+)\s*(?=[:(,}])").match(bare, i, end)
            j = i
            depth = 0
            while j < end:  # the member ends at the next top-level comma
                ch = bare[j]
                if ch in "([{":
                    depth += 1
                elif ch in ")]}":
                    depth -= 1
                elif ch == "," and depth == 0:
                    break
                j += 1
            if m:
                yield m.group(1), m.start(1), code[m.end(1):j]
            i = j + 1

    def gql_js(self, sf: SourceFile, global_auth: bool) -> None:
        v = js_views(sf.text or "")
        code, bare = v.code, v.bare
        for m in finditer(r"\b(Mutation|Query)\s*:\s*\{", code):
            for name, start, text in self.object_members(code, bare, m.end() - 1):
                if not re.search(r"=>|\bfunction\b|^\s*\(", text):
                    continue  # a reference to a function elsewhere: its body is not here
                method = "GET" if m.group(1) == "Query" else verb(name)
                self.add(sf, sf.line_at(start), "/graphql/" + name, method, text, "graphql", "js", global_auth)

    # ---------------------------------------------------------------- Python
    def python(self, sf: SourceFile, gql_auth: bool, grpc_auth: bool) -> None:
        text = sf.text or ""
        try:
            tree = ast.parse(text)
        except (SyntaxError, ValueError):
            return
        lines = text.split("\n")

        def source(node) -> str:
            first = min([d.lineno for d in getattr(node, "decorator_list", [])] + [node.lineno])
            return "\n".join(lines[first - 1:node.end_lineno or node.lineno])

        for cls in ast.walk(tree):
            if not isinstance(cls, ast.ClassDef):
                continue
            bases = " ".join(ast.unparse(b) for b in cls.bases)
            methods = [n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
            if re.search(r"\b(?:graphene\.)?Mutation$|ClientIDMutation\b|\bDjango\w*Mutation\b", bases):
                for fn in methods:
                    if fn.name in ("mutate", "mutate_and_get_payload", "perform_mutate"):
                        self.add(sf, cls.lineno, "/graphql/" + cls.name, verb(cls.name), source(cls), "graphene", "py",
                                 gql_auth)
            elif re.search(r"Servicer\b", bases):
                for fn in methods:
                    if not fn.name.startswith("_") and len(fn.args.args) >= 3:
                        self.add(sf, fn.lineno, "/grpc/" + fn.name, verb(fn.name), source(fn), "grpc", "py", grpc_auth)
            for fn in methods:  # Strawberry: @strawberry.mutation / @strawberry_django.mutation
                for d in fn.decorator_list:
                    text = ast.unparse(d)
                    if re.match(r"strawberry(?:_django)?\.(mutation|field)\b", text):
                        kind = "GET" if ".field" in text.split("(", 1)[0] else verb(fn.name)
                        if kind == "GET" and cls.name != "Query":
                            continue  # a field of an ordinary type, not an entry point
                        self.add(sf, fn.lineno, "/graphql/" + fn.name, kind, source(fn), "strawberry", "py", gql_auth)

    # ------------------------------------------------------------------ gRPC
    def grpc_go(self, sf: SourceFile, services: set, global_auth: bool) -> None:
        from .goscan import go_views

        v = go_views(sf.text or "")
        rx = r"\bfunc\s*\(\s*\w+\s+\*?(\w+)\s*\)\s*([A-Z]\w*)\s*\(\s*\w+\s+context\.Context\s*,[^)]*\)\s*\([^)]*error\s*\)\s*\{"
        for m in finditer(rx, v.code):
            if m.group(1) not in services:
                continue
            close = match_close(v.bare, m.end() - 1)
            body = v.code[m.start():close + 1 if close > 0 else len(v.code)]
            self.add(sf, sf.line_at(m.start()), "/grpc/" + m.group(2), verb(m.group(2)), body, "grpc", "go",
                     global_auth)

    def grpc_java(self, sf: SourceFile, global_auth: bool) -> None:
        from .jvm import jvm_views

        v = jvm_views(sf.text or "")
        for cls in finditer(r"\bclass\s+\w+[^{]*?(?:extends\s+|:\s*)[\w.]*Grpc\w*\s*\.\s*\w+ImplBase\b[^{]*\{", v.code):
            end = match_close(v.bare, cls.end() - 1)
            end = len(v.code) if end < 0 else end
            for m in JAVA_HANDLER.finditer(v.code, cls.end(), end):
                name = m.group(1) or m.group(2)
                close = match_close(v.bare, m.end() - 1)
                body = v.code[max(cls.end(), m.start() - 300):close + 1 if close > 0 else end]
                self.add(sf, sf.line_at(m.start()), "/grpc/" + name, verb(name), body, "grpc", "jvm", global_auth)

    def grpc_node(self, sf: SourceFile, global_auth: bool) -> None:
        v = js_views(sf.text or "")
        code, bare = v.code, v.bare
        for m in finditer(r"\.\s*addService\s*\(", code):
            close = match_close(bare, m.end() - 1)
            brace = bare.find("{", m.end(), close)
            if close < 0 or brace < 0:
                continue
            for name, start, text in self.object_members(code, bare, brace):
                if not re.search(r"=>|\bfunction\b|^\s*\(", text):
                    ref = re.match(r"\s*:?\s*([\w$]+)\s*$", text)
                    fn = self.js_function(code, bare, ref.group(1) if ref and ref.group(1) else name)
                    if fn is None:
                        continue
                    text = fn
                self.add(sf, sf.line_at(start), "/grpc/" + name, verb(name), text, "grpc", "js", global_auth)

    @staticmethod
    def js_function(code: str, bare: str, name: str) -> Optional[str]:
        m = re.search(r"(?:\bfunction\s+" + re.escape(name) + r"\s*\(|\b(?:const|let|var)\s+" + re.escape(name)
                      + r"\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[\w$]+\s*=>))", code)
        if not m:
            return None
        brace = bare.find("{", m.end())
        close = match_close(bare, brace) if brace >= 0 else -1
        return code[m.start():close + 1] if close > 0 else None


def routes(project: Project) -> List[Route]:
    return RpcScanner(project).run()
