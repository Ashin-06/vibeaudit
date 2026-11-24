"""Ruby on Rails: routes from config/routes.rb with `before_action` authentication (inherited, `only:` / `except:`,
`skip_before_action`), and Brakeman-style sinks: SQL injection (BE001), command injection (BE002), dynamic code
(BE003), unsafe deserialization (BE004), path traversal (BE006), open redirect (BE008), mass assignment (BE009) and
raw output in ERB views (FE001).

Taint is per method: request data (`params`, `request.*`, `cookies`) and the local variables assigned from it. Rails
findings are preview like the other added languages (see STABILITY.md); injection and XSS still gate."""
from __future__ import annotations

import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import heuristics as H
from .files import Project, SourceFile
from .guard import GUARD, finditer
from .model import Finding, Route

Emit = Callable[[Finding], None]

_NOT_NL = re.compile(r"[^\n]")
# comments outside strings: a `#` that does not start an interpolation, plus =begin/=end blocks
_TOKEN = re.compile(r"""^=begin\b[\s\S]{0,20000}?^=end\b|#\{|#[^\n]*|'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*\"""", re.M)

SOURCE = re.compile(r"\bparams\b(?!\s*\.\s*require\s*\([^)]*\)\s*\.\s*permit\b)|\brequest\s*\.\s*(?:params|query_parameters|"
                    r"request_parameters|body|raw_post|headers|referr?er|path|url|query_string)\b|\bcookies\s*\[")
SAFE_VALUE = re.compile(r"\.to_i\b|\.to_f\b|Integer\s*\(|Float\s*\(|\bsanitize_sql\w*|\bquote\b|\bconnection\s*\.\s*quote\b"
                        r"|\bFile\s*\.\s*basename\b|\bShellwords\b|\.shellescape\b|\bCGI\s*\.\s*escape\w*|\bERB::Util|\bh\s*\(")
ASSIGN = re.compile(r"(?m)^[ \t]*([a-z_]\w*)\s*(?:\|\|)?=(?![=~>])\s*([^\n]{1,500})")
DEF = re.compile(r"(?m)^([ \t]*)def\s+(?:self\.)?([\w?!=]+)")
CLASS = re.compile(r"(?m)^[ \t]*class\s+([\w:]+)(?:\s*<\s*([\w:]+))?")

SQL_STRING_CALL = re.compile(r"\.\s*(?:where|having|order|reorder|group|joins|select|from|pluck|exists\?|find_by_sql|"
                             r"count_by_sql|delete_all|update_all|calculate|lock)\s*\(|\b(?:find_by_sql|execute|exec_query|"
                             r"select_all|select_one|select_value|select_values|select_rows)\s*\(")
SINKS: List[Tuple[re.Pattern, str, str, str]] = [
    (re.compile(r"\b(?:system|exec|spawn)\s*\(|`[^`\n]*#\{|%x[({\[]|\bOpen3\s*\.\s*\w+\s*\(|\bIO\s*\.\s*popen\s*\("),
     "BE002", "a shell command", "critical"),
    (re.compile(r"\b(?:eval|instance_eval|class_eval|module_eval)\s*\(|\.\s*(?:safe_)?constantize\b|"
                r"\.\s*(?:send|public_send|__send__)\s*\("), "BE003", "code that runs", "critical"),
    (re.compile(r"\bMarshal\s*\.\s*load\s*\(|\bYAML\s*\.\s*(?:unsafe_)?load\s*\(|\bOj\s*\.\s*load\s*\("),
     "BE004", "deserialization", "high"),
    (re.compile(r"\bsend_file\s*\(?|\b(?:File|IO)\s*\.\s*(?:read|open|write|readlines|binread|delete|unlink)\s*\(|"
                r"\bFileUtils\s*\.\s*\w+\s*\("), "BE006", "a file path", "high"),
    (re.compile(r"\bredirect_to\s*\(?"), "BE008", "a redirect target", "medium"),
]
MASS_ASSIGN = re.compile(r"\.\s*(?:new|create!?|update!?|update_attributes!?|assign_attributes|insert|upsert|"
                         r"first_or_create!?|find_or_create_by!?)\s*\(\s*([^()\n]{0,300}(?:\([^()\n]{0,200}\))?[^()\n]{0,100})\)")
PERMIT_PRIVILEGED = re.compile(r"\.\s*permit\s*\([^)]{0,600}?:(?:admin|is_admin|role|roles|role_id|superuser|"
                               r"is_superuser|staff|is_staff|permissions?)\b")
ERB_RAW = re.compile(r"<%==\s*(.{1,300}?)\s*-?%>|<%=\s*raw\s*\(?\s*(.{1,300}?)\s*\)?\s*-?%>|<%=\s*(.{1,300}?)\.html_safe\s*-?%>")
ERB_SAFE = re.compile(r"""\A\s*(?:["'][^"'#]*["']|t\s*\(|I18n\b|render\b|yield\b|content_for\b|sanitize\s*\(|strip_tags\s*\(|"""
                      r"""json_escape\s*\(|j\s*\(|escape_javascript\s*\(|\w+_path\b|\w+_url\b|link_to\b|image_tag\b|"""
                      r"""javascript_include_tag\b|stylesheet_link_tag\b|csrf_meta_tags\b|simple_format\s*\(|markdown\w*\s*\()"""
                      r"""|\.to_json\b|\bjson\b""")

RAILS_AUTH = re.compile(r"(?i)authenticat|authori[sz]|require_(?:login|user|admin|signed_in|sign_in|session|current_user)"
                        r"|logged_in|signed_in|login_required|ensure_\w*(?:user|login|auth|admin)|check_\w*(?:user|admin|"
                        r"login|auth)|verify_\w*(?:user|token|session)|doorkeeper|current_user|protect")
# filters that look up a session when there is one but let anonymous requests through
OPTIONAL_AUTH = re.compile(r"(?i)(?:resume|optional|try|maybe|set|load|find|restore)_")
ADMIN_FILTER =re.compile(r"(?i)admin|role|staff|superuser|permission")
VERBS = ("get", "post", "put", "patch", "delete", "match")
RESOURCE_ACTIONS = [("index", "GET", ""), ("create", "POST", ""), ("new", "GET", "/new"), ("show", "GET", "/:id"),
                    ("edit", "GET", "/:id/edit"), ("update", "PATCH", "/:id"), ("destroy", "DELETE", "/:id")]
SINGULAR_ACTIONS = [("create", "POST", ""), ("new", "GET", "/new"), ("show", "GET", ""), ("edit", "GET", "/edit"),
                    ("update", "PATCH", ""), ("destroy", "DELETE", "")]


def ruby_code(src: str) -> str:
    """`src` with comments blanked (offsets and line breaks kept); strings stay, since interpolation matters."""
    def blank(m: "re.Match[str]") -> str:
        t = m.group(0)
        return _NOT_NL.sub(" ", t) if t.startswith(("#", "=begin")) and not t.startswith("#{") else t
    return _TOKEN.sub(blank, src)


def _symbols(text: str) -> List[str]:
    return [a or b for a, b in re.findall(r""":(\w+[?!]?)|["'](\w+[?!]?)["']""", text)]


def _option(args: str, key: str) -> Optional[List[str]]:
    m = re.search(r"\b" + key + r"\s*:\s*(\[[^\]]{0,500}\]|%i\[[^\]]{0,500}\]|:\w+[?!]?|['\"]\w+['\"])", args)
    if not m:
        return None
    v = m.group(1)
    return v[3:-1].split() if v.startswith("%i[") else _symbols(v)


class RubyScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit
        self.routes: List[Route] = []
        self.controllers: Dict[str, Tuple[SourceFile, str, Optional[str]]] = {}  # Class name -> (file, code, parent)
        self.reported: Set[Tuple[str, int, str]] = set()

    def add(self, sf: SourceFile, off: int, rule: str, msg: str, sev: str = "") -> None:
        line = sf.line_at(off)
        if (sf.rel, line, rule) in self.reported:
            return
        self.reported.add((sf.rel, line, rule))
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> List[Route]:
        files = [f for f in self.p.files if f.text and not f.is_test]
        rb = [f for f in files if f.rel.endswith(".rb")]
        if not rb:
            return []
        self.redirects_checked = self._raises_on_open_redirects(rb)
        self.included: Dict[str, str] = {}
        self.macros: Dict[str, Tuple[List[str], str, List[str]]] = {}
        for f in rb:
            code = f.cache["ruby_code"] = ruby_code(f.text)
            if "ActiveSupport::Concern" in code:
                self._concern(code)
            if "/controllers/" in "/" + f.rel:
                for m in finditer(CLASS, code):
                    self.controllers[m.group(1).split("::")[-1]] = (f, code, m.group(2) and m.group(2).split("::")[-1])
        for f in rb:
            if f.rel.endswith("config/routes.rb") or "/config/routes/" in "/" + f.rel:
                GUARD.run(f.rel, "rails routes", self._routes, f)
            if re.search(r"(?:^|/)(?:app|lib)/", f.rel):
                GUARD.run(f.rel, "rails sinks", self._sinks, f)
        for f in files:
            if f.rel.endswith((".erb", ".haml", ".slim")):
                GUARD.run(f.rel, "rails views", self._views, f)
        return self.routes

    # ---------------------------------------------------------------- config
    @staticmethod
    def _raises_on_open_redirects(rb: List[SourceFile]) -> bool:
        """Rails 7 apps (load_defaults 7.0 or later) raise on a redirect to another host unless it is allowed."""
        text = "\n".join(f.text for f in rb if f.rel.startswith("config/"))
        if re.search(r"raise_on_open_redirects\s*=\s*false", text):
            return False
        m = re.search(r"\bload_defaults\s+['\"]?(\d+)(?:\.(\d+))?", text)
        return bool(re.search(r"raise_on_open_redirects\s*=\s*true", text)) or bool(m and int(m.group(1)) >= 7)

    # ---------------------------------------------------------------- routes
    def _routes(self, sf: SourceFile) -> None:
        code = sf.cache["ruby_code"]
        stack: List[Tuple[str, str, str]] = []  # (path prefix, controller module, resource member prefix) per open block
        depth_marks: List[int] = []
        depth = 0
        for line_m in re.finditer(r"(?m)^[^\n]*$", code):
            line, off = line_m.group(0), line_m.start()
            s = line.strip()
            prefix = "".join(p for p, _m, _r in stack)
            module = "".join(m for _p, m, _r in stack)
            opens = len(re.findall(r"\bdo\b(?:\s*\|[^|]*\|)?\s*$", s)) + \
                (1 if re.match(r"(?:if|unless|case|begin|while|until|def|class|module)\b", s) else 0)
            closes = len(re.findall(r"(?:^|;)\s*end\b", s))
            m = re.match(r"(namespace|scope)\b\s*\(?\s*(.*)", s)
            if m and opens:
                args = m.group(2)
                name = re.match(r""":(\w+)|['"]/?([\w/:-]*)['"]""", args)
                seg = (name.group(1) or name.group(2)) if name else ""
                path_opt = re.search(r"""\bpath\s*:\s*['"]/?([\w/:-]*)['"]""", args)
                mod_opt = re.search(r"""\bmodule\s*:\s*[:'"]?(\w+)""", args)
                if m.group(1) == "namespace":
                    stack.append(("/" + (path_opt.group(1) if path_opt else seg), (mod_opt.group(1) if mod_opt else seg) + "/", ""))
                else:
                    p = path_opt.group(1) if path_opt else (seg if name and name.group(2) is not None else "")
                    stack.append(("/" + p if p else "", mod_opt.group(1) + "/" if mod_opt else "", ""))
                depth += opens
                depth_marks.append(depth)
            else:
                r = re.match(r"(resources|resource)\s*\(?\s*:(\w+)(.*)", s)
                if r:
                    self._resources(sf, off, prefix, module, r.group(1) == "resource", r.group(2), r.group(3))
                    if opens:
                        nested = ("/" + r.group(2) + ("" if r.group(1) == "resource" else "/:" + _singular(r.group(2)) + "_id"))
                        stack.append((nested, "", ""))
                        depth += opens
                        depth_marks.append(depth)
                        opens = 0
                v = re.match(r"(get|post|put|patch|delete|match)\s*\(?\s*['\"]([^'\"]*)['\"](.*)", s)
                if v:
                    self._verb(sf, off, prefix, module, v.group(1), v.group(2), v.group(3))
                elif opens:
                    depth += opens
            for _ in range(closes):
                if depth_marks and depth == depth_marks[-1]:
                    depth_marks.pop()
                    stack.pop()
                depth = max(0, depth - 1)

    def _resources(self, sf: SourceFile, off: int, prefix: str, module: str, single: bool, name: str, args: str) -> None:
        actions = SINGULAR_ACTIONS if single else RESOURCE_ACTIONS
        only, except_ = _option(args, "only"), _option(args, "except")
        ctrl = _option(args, "controller")
        controller = module + (ctrl[0] if ctrl else (name if not single else name + "s"))
        base = prefix + "/" + (_option(args, "path") or [name])[0]
        for action, verb, suffix in actions:
            if (only is not None and action not in only) or (except_ is not None and action in except_):
                continue
            self._route(sf, off, base + suffix, verb, controller, action)

    def _verb(self, sf: SourceFile, off: int, prefix: str, module: str, verb: str, path: str, rest: str) -> None:
        to = re.search(r"""\bto\s*:\s*['"]([\w/]+)#(\w+)['"]|=>\s*['"]([\w/]+)#(\w+)['"]""", rest)
        if to:
            controller, action = (to.group(1), to.group(2)) if to.group(1) else (to.group(3), to.group(4))
            controller = module + controller
        else:
            ctrl, act = _option(rest, "controller"), _option(rest, "action")
            if not ctrl and not act:
                return  # a redirect, a Rack app or `get 'x'` inside a resource block: no controller action to read
            controller, action = module + (ctrl[0] if ctrl else ""), (act[0] if act else path.strip("/").split("/")[-1])
        verbs = ["GET"] if verb == "get" else ["POST", "PUT", "PATCH", "DELETE"] if verb == "match" else [verb.upper()]
        for v in verbs[:1] if verb != "match" else ["GET"]:
            self._route(sf, off, prefix + "/" + path.lstrip("/"), v, controller, action)

    def _route(self, sf: SourceFile, off: int, path: str, verb: str, controller: str, action: str) -> None:
        cls = "".join(w.capitalize() for w in re.split(r"[_/]", controller.split("/")[-1])) + "Controller"
        info = self.controllers.get(cls)
        if info is None:
            return
        csf, code, _parent = info
        body, at = self._action(code, action)
        if body is None:
            return  # an inherited or implicit action: nothing to read
        filters, auth = self._filters(cls, action)
        has_auth = auth or bool(H.AUTH_EVIDENCE.search(body) or RAILS_AUTH.search(body) and "current_user" in body)
        path = re.sub(r"\(\.:format\)|\(([^()]*)\)", "", path) or "/"
        params = re.findall(r":(\w+)", path)
        self.routes.append(Route(csf.rel, csf.line_at(at), path, [verb], filters + "\n" + body, "rails", "ruby",
                                 has_auth=has_auth, reads_body=bool(SOURCE.search(body)), params=params))

    @staticmethod
    def _action(code: str, action: str) -> Tuple[Optional[str], int]:
        for m in DEF.finditer(code):
            if m.group(2) == action:
                nxt = re.compile(r"(?m)^" + re.escape(m.group(1)) + r"(?:def\b|end\b|private\b|protected\b)").search(code, m.end())
                return code[m.start():nxt.start() if nxt else len(code)], m.start()
        return None, 0

    def _filters(self, cls: str, action: str, seen: Optional[Set[str]] = None) -> Tuple[str, bool]:
        """The before_action lines that apply to `action` (this class and its parents), and whether one authenticates."""
        seen = seen or set()
        info = self.controllers.get(cls)
        if info is None or cls in seen:
            return "", False
        seen.add(cls)
        _sf, code, parent = info
        code = self._expand(code)
        text, auth = self._filters(parent, action, seen) if parent else ("", False)
        for m in finditer(r"(?m)^[ \t]*(skip_before_action|before_action|before_filter|prepend_before_action|"
                          r"load_and_authorize_resource|authorize_resource|http_basic_authenticate_with|"
                          r"skip_authorization_check)\b([^\n]*)", code):
            kind, args = m.group(1), m.group(2)
            only, except_ = _option(args, "only"), _option(args, "except")
            if (only is not None and action not in only) or (except_ is not None and action in except_):
                continue
            names = re.findall(r":(\w+[?!]?)", args.split(",")[0] + "," + args) if kind.endswith("before_action") or \
                kind == "before_filter" else [kind]
            if kind == "skip_before_action":
                if any(RAILS_AUTH.search(n) for n in names[:1]):
                    auth = False
                continue
            text += "\n" + m.group(0).strip()
            if kind in ("load_and_authorize_resource", "authorize_resource", "http_basic_authenticate_with") \
                    or any(RAILS_AUTH.search(n) and not OPTIONAL_AUTH.match(n) for n in names):
                auth = True
        return text, auth

    def _concern(self, code: str) -> None:
        """A concern's `included do ... end` filters, and its class macros that add or skip filters
        (`allow_unauthenticated_access only: :show` runs `skip_before_action :require_authentication, **options`)."""
        mod = re.search(r"(?m)^[ \t]*module\s+([\w:]+)", code)
        if not mod or "ActiveSupport::Concern" not in code:
            return
        name = mod.group(1).split("::")[-1]
        for m in finditer(r"(?m)^([ \t]*)included\s+do\b", code):
            end = re.compile(r"(?m)^" + re.escape(m.group(1)) + r"end\b").search(code, m.end())
            self.included[name] = code[m.end():end.start() if end else len(code)]
        for m in finditer(r"(?m)^([ \t]*)def\s+(\w+[?!]?)\s*\(\s*\*\*(\w+)\s*\)", code):
            end = re.compile(r"(?m)^" + re.escape(m.group(1)) + r"end\b").search(code, m.end())
            body = code[m.end():end.start() if end else len(code)]
            lines = re.findall(r"(?m)^[ \t]*((?:skip_)?before_action\b[^\n]*\*\*" + m.group(3) + r")\b", body)
            calls = re.findall(r"(?m)^[ \t]*(\w+[?!]?)\s+\*\*" + m.group(3) + r"\b", body)  # one macro calling another
            if lines or calls:
                self.macros[m.group(2)] = (lines, m.group(3), calls)

    def _expand(self, code: str, depth: int = 0) -> str:
        """Controller code with `include Concern` replaced by the concern's included filters and macro calls replaced
        by the filter lines they run, with the call's options."""
        if not self.included and not self.macros:
            return code

        def include(m: "re.Match[str]") -> str:
            return "\n".join(self.included.get(n.strip().split("::")[-1], "") for n in m.group(1).split(","))

        def macro(m: "re.Match[str]", depth: int = 0) -> str:
            lines, var, calls = self.macros[m.group(1)]
            out = [ln.replace("**" + var, m.group(2).strip()) for ln in lines]
            for c in calls if depth < 3 else []:
                if c in self.macros:
                    out.append(macro(re.match(r"(\w+[?!]?)(.*)", c + " " + m.group(2)), depth + 1))
            return "\n".join(out)

        # a list may continue on the next lines after a trailing comma: `include A, B,\n  C`
        code = re.sub(r"(?m)^[ \t]{0,20}include[ \t]+([\w:]{1,80}(?:[ \t]{0,5},[ \t]{0,5}\n?[ \t]{0,40}[\w:]{1,80}){0,30})[ \t]*$",
                      include, code)
        if self.macros:
            names = "|".join(re.escape(n) for n in self.macros)
            code = re.sub(r"(?m)^[ \t]*(" + names + r")\b([^\n]*)$", macro, code)
        return code

    # ----------------------------------------------------------------- sinks
    def _sinks(self, sf: SourceFile) -> None:
        code = sf.cache["ruby_code"]
        for m in finditer(PERMIT_PRIVILEGED, code):
            self.add(sf, m.start(), "BE009", "Strong parameters permit a privileged attribute (admin or role) from the request.")
        for m in finditer(r"\bparams\s*\.\s*permit!|\.to_unsafe_h(?:ash)?\b", code):
            self.add(sf, m.start(), "BE009", "Every request parameter is permitted (mass assignment).")
        defs = list(DEF.finditer(code))
        for i, d in enumerate(defs):
            end = defs[i + 1].start() if i + 1 < len(defs) else len(code)
            self._method(sf, code, d.start(), end)

    def _method(self, sf: SourceFile, code: str, a: int, b: int) -> None:
        body = code[a:b]
        tainted: Set[str] = set()
        for _ in range(3):
            for m in ASSIGN.finditer(body):
                rhs = m.group(2)
                if LAUNDERS.match(rhs):
                    continue  # a record found by the value, a new object, or a helper's result: not the request's text
                if (SOURCE.search(rhs) or _mentions(_unstring(rhs), tainted)) and not SAFE_VALUE.search(rhs):
                    tainted.add(m.group(1))

        def dirty(expr: str) -> bool:
            return bool((SOURCE.search(expr) or _mentions(_unstring(expr), tainted)) and not SAFE_VALUE.search(expr))

        for m in finditer(SQL_STRING_CALL, body):
            arg = _call_arg(body, m.end() - 1)
            first = _first(arg)
            interp = re.findall(r"#\{([^}]{1,200})\}", first) if first.lstrip().startswith(('"', "%(", "%Q", "<<")) else []
            concat = re.search(r"""["']\s*\+\s*(.+)|(.+?)\s*\+\s*["']""", first)
            raw = not first.lstrip().startswith(('"', "'", ":", "[", "{", "%")) and re.search(r"\.\s*(?:order|reorder|group|pluck|select|from)\s*\($", body[m.start():m.end()])
            if any(dirty(x) for x in interp) or (concat and dirty(concat.group(0))) or (raw and dirty(first)):
                self.add(sf, a + m.start(), "BE001", "Request data is built into SQL (SQL injection).")
        for rx, rule, what, sev in SINKS:
            for m in finditer(rx, body):
                seg = body[m.start():m.start() + 400].split("\n", 1)[0]
                if rule == "BE002" and m.group(0).startswith(("system", "exec", "spawn")):
                    arg = _call_arg(body, m.end() - 1)
                    if "," in _top_commas(arg) or not (re.search(r"#\{", _first(arg)) or not _first(arg).lstrip().startswith(('"', "'"))):
                        continue  # the array form `system("convert", path)` runs no shell
                    seg = arg
                elif rule == "BE003" and re.search(r"send\s*\($", m.group(0)):
                    seg = _first(_call_arg(body, m.end() - 1))
                elif rule == "BE003" and "constantize" in m.group(0):
                    seg = body[max(0, m.start() - 200):m.start()].rsplit("\n", 1)[-1]
                elif rule == "BE008":
                    seg = body[m.end():m.end() + 300].split("\n", 1)[0]
                    if self.redirects_checked and "allow_other_host" not in seg:
                        continue  # Rails 7 raises on a redirect to another host
                    if re.search(r"\bonly_path\s*:\s*true|allow_other_host\s*:\s*false", seg) or \
                            re.match(r"""\s*\(?\s*(?:['"]/|\w+_path\b|root_url\b|:back\b|request\.referr?er\s*\|\|)""", seg):
                        continue
                elif rule == "BE006" and re.search(r"File\s*\.\s*basename|Rails\.root\.join\(\s*['\"][^'\"]+['\"]\s*\)\s*$", seg):
                    continue
                if rule == "BE008" and re.match(r"\s*\(?\s*(?:params\s*\[\s*:(?:id|\w+_id)\s*\]|@\w+)", seg):
                    continue  # redirect_to @post builds a local URL from the record
                if dirty(seg):
                    msg = "Request data is used as a redirect target (open redirect)." if rule == "BE008" else \
                        f"Request data reaches {what}."
                    self.add(sf, a + m.start(), rule, msg, sev)

    # ----------------------------------------------------------------- views
    def _views(self, sf: SourceFile) -> None:
        text = sf.text
        for m in finditer(ERB_RAW, text):
            expr = next(g for g in m.groups() if g is not None)
            if ERB_SAFE.match(expr) or re.search(r"\bsanitize\b|\bstrip_tags\b|\bh\s*\(|\bjson_escape\b|\.to_json\b", expr):
                continue
            if SOURCE.search(expr) or re.search(r"@\w+\s*\.\s*(?:body|content|description|bio|title|name|text|comment|message|"
                                                r"about|summary|html|notes?|signature)\b", expr):
                self.add(sf, m.start(), "FE001", "Request data or a stored user field is rendered without escaping (raw / html_safe) (XSS).",
                         "high")


# \A and bounded, non-overlapping repeats: only ever .match()ed against one assignment's right-hand side
LAUNDERS = re.compile(r"\A[ \t]{0,10}(?:[A-Z][\w:]{0,80}(?:\.\w{1,60}[?!]?){0,6}\.(?:find\w{0,40}|where|first!?|last!?|"
                      r"take!?|new|exists\?|includes|joins)\b|[a-z_]\w{0,60}[?!]?[ \t]{0,5}\((?![ \t]{0,5}\))"
                      r"|[a-z_]\w{0,60}[?!]?[ \t]{1,5}(?![-+*/%<>=!&|?: \t]))")


def _unstring(expr: str) -> str:
    """String literals blanked except their interpolations, so `"image/png"` does not mention a variable `image`."""
    def keep(m: "re.Match[str]") -> str:
        return " ".join(re.findall(r"#\{([^}]{0,200})\}", m.group(0))) if m.group(0)[0] == '"' else " "
    return re.sub(r""""(?:\\.|[^"\\]){0,2000}"|'(?:\\.|[^'\\]){0,2000}'""", keep, expr)


def _singular(name: str) -> str:
    return name[:-3] + "y" if name.endswith("ies") else name[:-1] if name.endswith("s") else name


def _mentions(text: str, names: Set[str]) -> bool:
    return bool(names) and bool(re.search(r"(?<![\w@.:])(?:" + "|".join(map(re.escape, names)) + r")\b(?!\s*[:(])", text))


def _call_arg(text: str, i: int) -> str:
    """The argument text of the call whose name ends at `i` (parenthesised, or the rest of the line)."""
    j = i + 1
    while j < len(text) and text[j] in " \t":
        j += 1
    if j < len(text) and text[j] == "(" or (i < len(text) and text[i] == "("):
        start = i if text[i] == "(" else j
        depth = 0
        for k in range(start, min(len(text), start + 2000)):
            if text[k] in "([{":
                depth += 1
            elif text[k] in ")]}":
                depth -= 1
                if depth == 0:
                    return text[start + 1:k]
        return text[start + 1:start + 500]
    return text[j:j + 500].split("\n", 1)[0]


def _top_commas(arg: str) -> str:
    depth, out = 0, []
    in_str = None
    for ch in arg:
        if in_str:
            if ch == in_str:
                in_str = None
            continue
        if ch in "\"'":
            in_str = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            out.append(ch)
    return "".join(out)


def _first(arg: str) -> str:
    depth, in_str = 0, None
    for k, ch in enumerate(arg):
        if in_str:
            if ch == in_str and arg[k - 1] != "\\":
                in_str = None
            continue
        if ch in "\"'":
            in_str = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            return arg[:k]
    return arg
