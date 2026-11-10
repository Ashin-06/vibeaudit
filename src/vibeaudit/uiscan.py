"""UI, UX and accessibility checks for React/Next components and HTML pages: missing alt text and labels,
mouse-only click targets, dead controls, unconfirmed destructive actions, hydration traps, effects without
cleanup, missing loading or error states, placeholder content, missing metadata or error pages, and internal
links to pages that do not exist."""
from __future__ import annotations

import posixpath
import re
from typing import Callable, List, Set

from .files import Project, SourceFile
from .guard import GUARD, finditer
from .lexer import match_close
from .model import Finding

Emit = Callable[[Finding], None]

SKIP_PATH = re.compile(r"(?i)(?:^|/)(?:tests?|__tests__|stories|storybook|mocks?|__mocks__|fixtures?|examples?|demos?|docs?)/|\.stories\.|\.test\.|\.spec\.")
JSX_EXT = re.compile(r"\.(?:jsx|tsx)$")
MARKUP_EXT = re.compile(r"\.(?:html?|vue|svelte|astro|jinja2?|j2|hbs|ejs)$")
TAG = re.compile(r"<(img|Image|input|select|textarea|div|span|li|td|tr|p|section|article|a|button)\b")
NON_INTERACTIVE = {"div", "span", "li", "td", "tr", "p", "section", "article", "img"}
EMPTY_HANDLER = re.compile(r"""\bonClick\s*=\s*\{\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*(?:\{\s*\}|\{\s*console\.log\([^()]{0,200}\)\s*;?\s*\}|console\.log\([^()]{0,200}\))\s*\}""")
DESTRUCTIVE = re.compile(r"""\bon(?:Click|Select|Press)\s*=\s*\{\s*(?:\(\s*\w*\s*\)\s*=>\s*)?(?:void\s+)?(?:await\s+)?((?:handle|on)?(?:[Dd]elete|[Dd]estroy|[Pp]urge|[Ww]ipe)\w*)\b""")
# a handler that only stops the event from reaching a parent is not a control
SWALLOW_ONLY = re.compile(r"""\bonClick\s*=\s*\{\s*\(?\s*(\w+)\s*\)?\s*=>\s*\{?\s*(?:\1\s*\.\s*(?:stopPropagation|preventDefault)\s*\(\s*\)\s*;?\s*){1,2}\}?\s*\}""")
# a full-screen overlay behind a modal or drawer that closes it on click: the dialog has its own close control
BACKDROP = re.compile(r"\binset-0\b|\b(?:fixed|absolute)\b[^\"'`]{0,300}?\bh-full\s+w-full\b"
                      r"|\bh-full\s+w-full\b[^\"'`]{0,300}?\b(?:fixed|absolute)\b")  # bounded: linear on long class lists
CLOSE_HANDLER = re.compile(r"(?i)\bonClick\s*=\s*\{\s*(?:\(\s*\w*\s*\)\s*=>\s*\{?\s*)?(?:set\w*\(\s*(?:false|null)\s*\)|\w*(?:close|toggle|dismiss|hide)\w*)")
CONFIRMATION = re.compile(r"(?i)\bconfirm\s*\(|AlertDialog|Dialog|Modal|Popconfirm|useConfirm|Confirm\w*|\bundo\b|DropdownMenu|ContextMenu")
INDEX_KEY = re.compile(r"\.map\(\s*\(\s*\w+\s*,\s*(\w+)\s*\)\s*=>")
CLOCK_IN_JSX = re.compile(r"<[A-Za-z][^<>]{0,300}>[^<>{}]{0,200}\{[^{}]{0,200}\b(Math\.random\(\)|Date\.now\(\)|new Date\(\)\.(?:toLocale\w*|get(?!FullYear)\w+)\()")
SUBSCRIBE = re.compile(r"\bsetInterval\s*\(|\.addEventListener\s*\(|\.subscribe\s*\(|\bnew\s+(?:WebSocket|EventSource)\s*\(|\bonSnapshot\s*\(|\.onAuthStateChange\s*\(|\.channel\s*\(")
FETCH = re.compile(r"\bfetch\s*\(|\baxios(?:\.\w+)?\s*\(|\.from\s*\(\s*['\"]\w+['\"]\s*\)\s*\.\s*select\s*\(")
LOADING = re.compile(r"(?i)loading|pending|isFetching|skeleton|spinner|suspense|status\s*===?\s*['\"]")
ERROR_STATE = re.compile(r"\bcatch\b|\.catch\s*\(|\berror\b|isError|onError|setError|ErrorBoundary")
LOREM = re.compile(r"(?i)\blorem ipsum\b|\bdolor sit amet\b")
HREF = re.compile(r"""(?:\bhref\s*=\s*\{?\s*|\brouter\s*\.\s*(?:push|replace)\s*\(\s*|\bredirect\s*\(\s*|\bnavigate\s*\(\s*)(["'`])(/[^"'`\s?#]*)(?:[?#][^"'`\s]*)?\1""")
PAGE_FILE = re.compile(r"(?:^|/)(?:src/)?app/(.*?)/?(?:page|route)\.(?:jsx?|tsx?|mdx?)$")
PAGES_FILE = re.compile(r"(?:^|/)(?:src/)?pages/(.+)\.(?:jsx?|tsx?|mdx?)$")


def tag_end(bare: str, start: int) -> int:
    """Offset just past the `>` that closes the JSX/HTML tag opened at `start`, or -1."""
    depth = 0
    for j in range(start + 1, min(len(bare), start + 4000)):
        c = bare[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        elif c == ">" and depth <= 0 and bare[j - 1] != "=":
            return j + 1
        elif c == "<" and depth <= 0:
            return -1
    return -1


class UiScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit

    def add(self, sf: SourceFile, rule: str, line: int, msg: str, sev: str = "") -> None:
        self.emit(Finding(rule, sf.rel, line, msg, sev, sf.line(line).strip()[:200]))

    def run(self) -> None:
        for sf in self.p.files:
            if sf.text is None or sf.is_test or SKIP_PATH.search(sf.rel):
                continue
            if JSX_EXT.search(sf.rel) or (sf.kind == "js" and re.search(r"""from\s+['"]react['"]""", sf.text)):
                GUARD.run(sf.rel, "UI checks", self._jsx, sf)
            elif MARKUP_EXT.search(sf.rel):
                GUARD.run(sf.rel, "UI checks", self._markup, sf)
        GUARD.run("<project>", "Next.js pages", self._next)

    # ----------------------------------------------------------------- JSX
    def _jsx(self, sf: SourceFile) -> None:
        v = sf.cache.get("views")
        if v is None:
            return
        code, bare = v.code, v.bare  # type: ignore[attr-defined]
        next_image = bool(re.search(r"""from\s+['"]next/image['"]""", code))
        for m in finditer(TAG, bare):
            end = tag_end(bare, m.start())
            if end < 0:
                continue
            name, attrs, battrs = m.group(1), code[m.start():end], bare[m.start():end]
            if "{..." in battrs:
                continue  # spread props: the attributes come from elsewhere
            line = sf.line_at(m.start())
            if (name == "img" or (name == "Image" and next_image)) and not re.search(r"\balt\s*=", battrs):
                self.add(sf, "UI001", line, f"<{name}> has no alt text; screen readers announce the file name or nothing.")
            if (name in NON_INTERACTIVE and re.search(r"\bonClick\s*=", battrs) and not SWALLOW_ONLY.search(attrs)
                    and not (BACKDROP.search(attrs) and CLOSE_HANDLER.search(attrs))
                    and not re.search(r"\brole\s*=|\bonKey(?:Down|Up|Press)\s*=", battrs)):
                self.add(sf, "UI002", line, f"<{name} onClick> cannot be reached or used with the keyboard.")
            if name in ("input", "select", "textarea") and self._unlabeled(attrs, battrs, bare, m.start()):
                self.add(sf, "UI003", line, f"<{name}> has no label, aria-label or id that a <label> could point to.")
            if name == "a" and re.search(r"""\bhref\s*=\s*["']#["']""", attrs) and not re.search(r"\bonClick\s*=", battrs):
                self.add(sf, "UI004", line, "Link with href=\"#\" and no click handler does nothing.")
        for m in finditer(EMPTY_HANDLER, code):
            self.add(sf, "UI004", sf.line_at(m.start()), "This control's click handler does nothing (empty or only logs).")
        if not CONFIRMATION.search(code):
            m = DESTRUCTIVE.search(code)
            if m:
                self.add(sf, "UI006", sf.line_at(m.start()), f"`{m.group(1)}` runs straight from a click, with no confirmation or undo.")
        self._index_keys(sf, code, bare)
        if self.p.js_deps(sf.rel) & {"next", "@remix-run/react", "gatsby"}:
            for m in finditer(CLOCK_IN_JSX, code):
                self.add(sf, "UI007", sf.line_at(m.start(1)),
                         f"`{m.group(1)}` in server-rendered markup gives a different value on the client: hydration mismatch.")
        self._effects(sf, code, bare)
        self._lorem(sf, code)

    @staticmethod
    def _unlabeled(attrs: str, battrs: str, bare: str, at: int) -> bool:
        if re.search(r"""\btype\s*=\s*["'](?:hidden|submit|button|reset|image|file)["']""", attrs):
            return False  # file inputs are almost always hidden behind a labelled button
        if re.search(r"""\btabIndex\s*=\s*\{\s*-1\s*\}|\baria-hidden\b|\shidden(?:\s|=|/|>)""", attrs):
            return False
        if re.search(r"\b(?:aria-label|aria-labelledby|id|title|label)\s*=", battrs):
            return False
        before = bare[max(0, at - 600):at]
        opened, closed = before.rfind("<label"), before.rfind("</label")
        return not (opened >= 0 and opened > closed)

    def _index_keys(self, sf: SourceFile, code: str, bare: str) -> None:
        # The bug needs both: items that keep their own state (fields) and a list that loses or reorders items.
        state = dict(re.findall(r"\[\s*(\w+)\s*,\s*(set\w+)\s*\]\s*=\s*(?:React\.)?useState", code))
        for m in finditer(INDEX_KEY, code):
            owner = re.search(r"(\w+)\s*\??$", code[max(0, m.start() - 60):m.start()])
            setter = state.get(owner.group(1)) if owner else None
            close = match_close(bare, code.index("(", m.start()))
            body = code[m.end():close if close > 0 else m.end() + 600]
            if (setter and re.search(r"\bkey\s*=\s*\{\s*" + re.escape(m.group(1)) + r"\s*\}", body)
                    and re.search(r"<(?:input|textarea|select)\b|defaultValue|defaultChecked|contentEditable", body)
                    and re.search(re.escape(setter) + r"\s*\([^;]{0,200}\.(?:filter|splice|sort|toSorted|reverse|unshift)\s*\(", code)):
                self.add(sf, "UI005", sf.line_at(m.start()),
                         f"Items of `{owner.group(1)}` hold input state, are removed or reordered, and use the array index as key.")

    def _effects(self, sf: SourceFile, code: str, bare: str) -> None:
        fetch_effect = None
        for m in finditer(r"\buseEffect\s*\(", bare):
            close = match_close(bare, m.end() - 1)
            if close < 0:
                continue
            body = code[m.end():close]
            sub = SUBSCRIBE.search(body)
            if sub and not re.search(r"\breturn\b", bare[m.end():close]):
                self.add(sf, "UI008", sf.line_at(m.start()),
                         f"The effect starts `{sub.group(0).strip(' (.')}` but never cleans it up; it leaks and runs twice.")
            if fetch_effect is None and FETCH.search(body):
                fetch_effect = m.start()
        if fetch_effect is not None:
            # a hook can signal loading with an empty initial value; only components must render it
            checks = (("loading", LOADING), ("error", ERROR_STATE)) if JSX_EXT.search(sf.rel) else (("error", ERROR_STATE),)
            missing = [what for what, rx in checks if not rx.search(code)]
            if missing:
                self.add(sf, "UI009", sf.line_at(fetch_effect),
                         f"Data is fetched with no {' or '.join(missing)} state; users see a blank or stale screen.")

    def _lorem(self, sf: SourceFile, text: str) -> None:
        m = LOREM.search(text)
        if m:
            self.add(sf, "UI010", sf.line_at(m.start()), "Placeholder text (lorem ipsum) is still in the UI.")

    # -------------------------------------------------------------- markup
    def _markup(self, sf: SourceFile) -> None:
        # HTML and template comments are never rendered; blank them keeping offsets (and so line numbers)
        text = re.sub(r"(?s)<!--.*?-->|\{%-?\s*comment\b.*?\{%-?\s*endcomment\s*-?%\}|\{#.*?#\}",
                      lambda m: re.sub(r"[^\n]", " ", m.group(0)), sf.text or "")
        for m in finditer(r"<img\b[^<>]{0,2000}>", text):
            if not re.search(r"\balt\s*=|:alt\s*=|\{\.\.\.|v-bind", m.group(0)):
                self.add(sf, "UI001", sf.line_at(m.start()), "<img> has no alt text; screen readers announce the file name or nothing.")
        self._lorem(sf, text)
        html = re.search(r"(?i)<html\b", text)
        folder = sf.rel.rsplit("/", 1)[0] if "/" in sf.rel else ""
        app_root = re.sub(r"/?(?:public|src)$", "", folder)
        is_entry = re.search(r"(?:^|/)index\.html?$", sf.rel) and self.p.get(f"{app_root}/package.json".lstrip("/")) is not None
        if html and is_entry and not re.search(r"""(?i)<meta[^<>]{0,300}name\s*=\s*["']viewport""", text):
            self.add(sf, "UI012", sf.line_at(html.start()), "The page has no viewport meta tag, so phones render it as a zoomed-out desktop page.")

    # ------------------------------------------------------------- project
    def _next(self) -> None:
        # react-router and other SPA apps also have src/pages/, so only Next.js projects are mapped
        files = [f for f in self.p.files if not f.is_test and "next" in self.p.js_deps(f.rel)]
        app_pages = [f for f in files if PAGE_FILE.search(f.rel) and f.rel.rsplit("/", 1)[-1].startswith("page.")]
        layouts = [f for f in files if re.search(r"(?:^|/)(?:src/)?app/layout\.(?:jsx?|tsx?)$", f.rel)]
        for layout in layouts:
            base = layout.rel.rsplit("/", 1)[0]
            if len([f for f in app_pages if f.rel.startswith(base + "/")]) >= 3 and not any(
                    re.search(r"(?:^|/)(?:global-)?error\.(?:jsx?|tsx?)$", f.rel) and f.rel.startswith(base + "/") for f in files):
                self.add(layout, "UI011", 1, "The app has no error.tsx, so a thrown error shows Next.js's bare error screen.")
            text = layout.text or ""
            if not re.search(r"export\s+(?:const\s+metadata\b|(?:async\s+)?function\s+generateMetadata\b)|<title\b|<head\b", text):
                self.add(layout, "UI012", 1, "The root layout exports no metadata, so pages have no title or description.")
        self._links(files)

    def _links(self, files: List[SourceFile]) -> None:
        routes: List[List[str]] = []
        for f in files:
            m = PAGE_FILE.search(f.rel)
            if m:
                parts = [s for s in m.group(1).split("/") if s and not (s.startswith("(") and s.endswith(")")) and not s.startswith("@")]
                if any(s.startswith("_") for s in parts):
                    continue
                routes.append(parts)
                continue
            m = PAGES_FILE.search(f.rel)
            if m and not m.group(1).split("/")[-1].startswith("_"):
                parts = m.group(1).split("/")
                routes.append(parts[:-1] if parts[-1] == "index" else parts)
        if len(routes) < 2:
            return
        config = " ".join(f.text or "" for f in files if re.search(r"(?:^|/)next\.config\.\w+$", f.rel))
        if re.search(r"\b(?:rewrites|redirects|basePath|i18n)\b", config) or any(re.search(r"(?:^|/)(?:src/)?(?:middleware|proxy)\.[jt]s$", f.rel) for f in files):
            return  # paths can be rewritten outside the file tree
        public: Set[str] = {"/" + f.rel.split("public/", 1)[1] for f in self.p.files if "public/" in f.rel}
        for f in files:
            if f.kind != "js" or SKIP_PATH.search(f.rel):
                continue
            v = f.cache.get("views")
            code = v.code if v is not None else (f.text or "")  # type: ignore[attr-defined]
            for m in finditer(HREF, code):
                path = posixpath.normpath(m.group(2)) if m.group(2) != "/" else "/"
                if "${" in m.group(0) or path in public or "." in path.rsplit("/", 1)[-1]:
                    continue
                segs = [s for s in path.split("/") if s]
                if not any(self._match(r, segs) for r in routes):
                    self.add(f, "UI013", f.line_at(m.start()), f"Link to `{m.group(2)}`, but no page or route handles that path.")

    @staticmethod
    def _match(route: List[str], segs: List[str]) -> bool:
        i = 0
        for r in route:
            if r.startswith("[[...") or r.startswith("[..."):
                return r.startswith("[[") or i < len(segs)
            if i >= len(segs):
                return False
            if not (r.startswith("[") or r == segs[i]):
                return False
            i += 1
        return i == len(segs)
