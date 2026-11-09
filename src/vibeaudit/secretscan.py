"""Secret detection over raw file text (comments included: a key in a comment is still leaked)."""
from __future__ import annotations

import base64
import json
import re
from typing import Callable, List, Optional, Pattern, Tuple

from . import heuristics as H
from .files import ENV_EXAMPLE_RE, Project, SourceFile
from .lexer import js_views, py_views
from .model import Finding

Emit = Callable[[Finding], None]

PROVIDER_KEYS: List[Tuple[str, Pattern[str]]] = [
    ("OpenAI API key", re.compile(r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}")),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b")),
    ("OpenAI API key", re.compile(r"\bsk-[A-Za-z0-9]{48}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}")),
    ("OpenRouter API key", re.compile(r"\bsk-or-v1-[a-f0-9]{64}\b")),
    ("OpenAI-compatible API key (DeepSeek and others)", re.compile(r"\bsk-[a-f0-9]{32}\b")),
    ("Google API key (Gemini, Maps, Firebase)", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Groq API key", re.compile(r"\bgsk_[A-Za-z0-9]{48,}\b")),
    ("xAI API key", re.compile(r"\bxai-[A-Za-z0-9]{70,}\b")),
    ("Hugging Face token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b")),
    ("Replicate API token", re.compile(r"\br8_[A-Za-z0-9]{37,}\b")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS secret access key", re.compile(r"(?i)aws_?secret_?access_?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Stripe live secret key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("Slack webhook URL", re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}")),
    ("Discord webhook URL", re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{50,}")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")),
    ("npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("Telegram bot token", re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b")),
    ("Resend API key", re.compile(r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24}\b")),
    ("Twilio API key", re.compile(r"\bSK[0-9a-f]{32}\b")),
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b")),
    ("Pinecone API key", re.compile(r"\bpcsk_[A-Za-z0-9_]{50,}\b")),
    ("Supabase personal access token", re.compile(r"\bsbp_[a-f0-9]{40}\b")),
    ("Supabase secret key", re.compile(r"\bsb_secret_[A-Za-z0-9_-]{20,}\b")),
    ("Clerk secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{40,}\b")),
]
PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}")
DB_URL = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql)://([^:/\s'\"@]+):([^@\s'\"/]+)@([^/\s'\":?]+)"
)
GENERIC_ASSIGN = re.compile(
    r"""(?i)["']?([\w.-]*(?:api[_-]?key|apikey|secret|token|passwd|password|private[_-]?key|access[_-]?key|client[_-]?secret|auth[_-]?key|credentials?)[\w.-]*)["']?\s*(?:[:=]|:=|=>)\s*["'`]([^"'`\s]{12,})["'`]"""
)
ENV_LINE = re.compile(
    r"^\s*(?:export\s+)?([A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|CREDENTIALS?|PRIVATE)[A-Za-z0-9_]*)\s*=\s*['\"]?([^\s'\"#]{12,})", re.M
)
PASSWORD_ASSIGN = re.compile(
    r"""(?i)\b((?:[a-z_]*_)?(?:password|passwd|pwd|pass)|(?:admin|db|root|master|default)_?pass(?:word)?)["']?\s*(?:[:=]|=>)\s*["'`]([^"'`\n]{4,64})["'`]"""
)
SIGNING_LITERAL = [
    re.compile(r"""\b(?:app\s*\.\s*)?(?:secret_key|SECRET_KEY|JWT_SECRET(?:_KEY)?|jwt_secret(?:_key)?|SESSION_SECRET|session_secret|SIGNING_KEY|TOKEN_SECRET|COOKIE_SECRET|AUTH_SECRET|NEXTAUTH_SECRET)\s*=\s*["']([^"']+)["']"""),
    re.compile(r"""\bconfig\s*\[\s*["'](?:SECRET_KEY|JWT_SECRET_KEY|SESSION_SECRET)["']\s*\]\s*=\s*["']([^"']+)["']"""),
    re.compile(r"""\bjwt\s*\.\s*sign\s*\([^;]*?,\s*["'`]([^"'`$]+)["'`]"""),
    re.compile(r"""\b(?:session|expressSession|cookieSession|cookieParser)\s*\(\s*(?:\{[^}]*?\bsecret\s*:\s*)?["'`]([^"'`$]+)["'`]"""),
    re.compile(r"""\b(?:const|let|var)\s+(?:JWT_SECRET|jwtSecret|SECRET_KEY|secretKey|SESSION_SECRET|sessionSecret)\s*=\s*["'`]([^"'`$]+)["'`]"""),
]
SIGNING_FALLBACK = [
    re.compile(r"""(?:getenv|environ\s*\.\s*get)\s*\(\s*["']\w*(?:SECRET|SIGNING)\w*["']\s*,\s*["']([^"']+)["']"""),
    re.compile(r"""process\s*\.\s*env\s*\.\s*\w*(?:SECRET|SIGNING)\w*\s*(?:\|\||\?\?)\s*["'`]([^"'`]+)["'`]"""),
]
FIREBASE_CONTEXT = re.compile(r"authDomain|projectId|messagingSenderId|storageBucket|firebase|appId|measurementId|maps\.googleapis|google\.maps|GOOGLE_MAPS|MAPS_API|places", re.I)
DOC_EXTS = (".md", ".mdx", ".rst", ".txt", ".adoc", ".ipynb")


def _jwt_role(payload: str) -> Optional[str]:
    try:
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict) or data.get("iss") == "supabase-demo":
        return None  # the Supabase CLI's well-known local development keys
    return data.get("role")


class SecretScanner:
    def __init__(self, project: Project, emit: Emit):
        self.p = project
        self.emit = emit

    def add(self, sf: SourceFile, rule: str, off: int, msg: str, secret: str = "", sev: str = "") -> None:
        line = sf.line_at(off)
        snippet = sf.line(line).strip()
        if secret:
            snippet = snippet.replace(secret, H.mask(secret))
        self.emit(Finding(rule, sf.rel, line, msg, sev, snippet[:200]))

    def run(self) -> None:
        for sf in self.p.files:
            text = sf.text
            if text is None or sf.is_lockfile or sf.rel.endswith((".map", ".min.js", ".svg")):
                continue
            self.scan_file(sf, text)

    def scan_file(self, sf: SourceFile, text: str) -> None:
        seen_lines = set()

        def once(off: int) -> bool:
            line = sf.line_at(off)
            if line in seen_lines:
                return False
            seen_lines.add(line)
            return True

        for label, rx in PROVIDER_KEYS:
            for m in rx.finditer(text):
                secret = m.group(1) if m.groups() else m.group(0)
                if H.PLACEHOLDER.search(secret) or re.search(r"(?i)example|xxxx", secret):
                    continue
                if label.startswith("Google API key"):
                    window = text[max(0, m.start() - 600): m.end() + 600]
                    if FIREBASE_CONTEXT.search(window):
                        continue  # Firebase web config / Maps keys are public by design
                if label == "Twilio API key" and not re.search(r"(?i)twilio", text):
                    continue
                if label == "Mailgun API key" and not re.search(r"(?i)mailgun", text):
                    continue
                if once(m.start()):
                    self.add(sf, "SEC001", m.start(), f"{label} committed in source.", secret)
        for m in PRIVATE_KEY.finditer(text):
            window = text[m.end(): m.end() + 200]
            if re.search(r"(?i)\.\.\.|example|your|redacted", window[:60]) or len(window.strip()) < 40:
                continue
            if once(m.start()):
                self.add(sf, "SEC002", m.start(), "Private key committed in source.")
        for m in JWT.finditer(text):
            if _jwt_role(m.group(1)) == "service_role" and once(m.start()):
                self.add(sf, "SEC009", m.start(), "Supabase service_role JWT committed in source.", m.group(0))
        for m in DB_URL.finditer(text):
            user, pw, host = m.group(1), m.group(2), m.group(3)
            if "." not in host or host.startswith(("127.", "0.0.0.0")) or host == "localhost":
                continue
            if H.PLACEHOLDER.search(pw) or pw.lower() in ("password", "pass", "postgres", "secret", "root", "admin", "user", "changeme", "pw"):
                continue
            if once(m.start()):
                self.add(sf, "SEC005", m.start(), f"Connection string for {host} includes a password.", pw)
        is_doc = sf.rel.lower().endswith(DOC_EXTS)
        if sf.is_test or is_doc:
            return
        public_lines = set()
        for m in PUBLIC_ENV.finditer(text):
            if re.search(r"PUBLISHABLE|ANON|PUBLIC_KEY|SITE_KEY|MEASUREMENT|_PK_|PK_LIVE|PK_TEST", m.group(0)):
                continue
            line = sf.line_at(m.start())
            if line not in public_lines:
                public_lines.add(line)
                self.add(sf, "SEC008", m.start(), f"{m.group(0)} is a public (browser-exposed) variable but holds a secret.")
        code = self._code(sf, text)
        for rx in SIGNING_LITERAL:
            for m in rx.finditer(code):
                val = m.group(1)
                if H.PLACEHOLDER.search(val) and not re.search(r"(?i)changeme|change_me|secret|dev|insecure", val):
                    continue
                if once(m.start()):
                    self.add(sf, "SEC004", m.start(), "Session/JWT signing secret is hard-coded.", val if len(val) > 8 else "")
        for rx in SIGNING_FALLBACK:
            for m in rx.finditer(code):
                if once(m.start()):
                    self.add(sf, "SEC004", m.start(), "Signing secret falls back to a hard-coded default when the env var is missing.", "", "medium")
        if sf.kind == "env":
            for m in ENV_LINE.finditer(text):
                if re.search(r"PUBLISHABLE|ANON|PUBLIC_KEY|SITE_KEY|_PK\b|MEASUREMENT", m.group(1)):
                    continue  # keys that are designed to be public
                jwt = JWT.match(m.group(2))
                if jwt and _jwt_role(jwt.group(1)) in ("anon", None):
                    continue
                if H.looks_random(m.group(2)) and once(m.start()):
                    self.add(sf, "SEC003", m.start(), f"{m.group(1)} has a real-looking value.", m.group(2))
        elif sf.kind in ("py", "js", "html", "json", "yaml", "compose", "docker", "other", "workflow") and not ENV_EXAMPLE_RE.search(sf.rel):
            if sf.kind in ("py", "js"):
                for m in PASSWORD_ASSIGN.finditer(code):
                    name, val = m.group(1), m.group(2)
                    low = val.lower()
                    if (" " in val or low == name.lower() or low in ("password", "passwd", "pwd", "pass", "required", "text", "string", "hidden", "new-password", "current-password")
                            or H.PLACEHOLDER.search(val) or re.match(r"^[\w.]+\(|^\$|^%|^\{", val)):
                        continue
                    if once(m.start()):
                        self.add(sf, "SEC011", m.start(), f"`{name}` is a hard-coded password.", val)
            for m in GENERIC_ASSIGN.finditer(code if sf.kind in ("py", "js") else text):
                name, val = m.group(1), m.group(2)
                if re.search(r"(?i)tokens?_?(?:count|limit|url|endpoint|type|name|usage)|max_?tokens?|tokenizer|csrf|_url$|_path$|_file$|_id$|_ids$|placeholder|label|hint", name):
                    continue
                if val.startswith("AIza") and FIREBASE_CONTEXT.search(text[max(0, m.start() - 600): m.end() + 600]):
                    continue
                if H.looks_random(val) and once(m.start()):
                    self.add(sf, "SEC003", m.start(), f"`{name}` is assigned a real-looking secret.", val)

    @staticmethod
    def _code(sf: SourceFile, text: str) -> str:
        """Comment-free view for rules where commented-out examples are noise."""
        v = sf.cache.get("views")
        if v is None:
            if sf.kind == "py":
                v = py_views(text)
            elif sf.kind in ("js", "html"):
                v = js_views(text)
            else:
                return text
            sf.cache["views"] = v
        return v.code  # type: ignore[attr-defined]


PUBLIC_ENV = re.compile(
    r"\b(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|NUXT_PUBLIC_|GATSBY_|PUBLIC_)"
    r"[A-Z0-9_]*?(?:SECRET|PRIVATE_KEY|SERVICE_ROLE|SERVICE_KEY|PASSWORD|PASSWD|DATABASE_URL|DB_URL|DB_PASS"
    r"|POSTGRES_URL|MONGO(?:DB)?_URI|AWS_ACCESS_KEY"
    r"|(?:OPENAI|ANTHROPIC|CLAUDE|GEMINI|GOOGLE_AI|GENAI|GROQ|MISTRAL|COHERE|REPLICATE|HUGGING_?FACE|HF|DEEPSEEK|XAI"
    r"|PERPLEXITY|TOGETHER|OPENROUTER|ELEVENLABS|PINECONE|STRIPE|ADMIN|RESEND|SENDGRID|TWILIO|GITHUB|SLACK|LLM|AI)"
    r"_?(?:API_?)?(?:KEY|TOKEN))[A-Z0-9_]*\b"
)
