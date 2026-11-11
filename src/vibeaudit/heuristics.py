"""Patterns shared by the language scanners: what counts as auth, an LLM call, a public path, and so on.

These are deliberately conservative. When in doubt a pattern counts as *evidence of protection*,
because a scanner that cries wolf gets switched off.
"""
from __future__ import annotations

import math
import re

# Anything that suggests the handler checks who the caller is.
AUTH_EVIDENCE = re.compile(
    r"""
    \b(?:req|request|ctx|c|event|context)\s*\.\s*(?:user|auth|session\s*\.\s*user|locals\s*\.\s*user|state\s*\.\s*user)\b
    | \b(?:getServerSession|getSession|unstable_getServerSession|currentUser|getAuth|clerkClient|auth|getUser|getToken
        |verifyToken|verifyIdToken|verifyJwt|jwtVerify|requireAuth|requireUser|requireSession|requireAdmin|requireRole
        |withAuth|withApiAuthRequired|isAuthenticated|ensureAuthenticated|authenticate|authorize|validateRequest
        |validateSession|getCurrentUser|get_current_user|get_current_active_user|get_jwt_identity
        |verify_jwt_in_request|verify_token|decode_token|verify_id_token|authenticate_user|get_user_from_token
        |getKindeServerSession|getUserFromRequest|lucia\.validateSession)\s*\(
    | \bget_?(?:current_?|logged_?in_?|authenticated_?|authed_?)?(?:user|session|auth)(?:_?or_?\w+)?\s*\(
    | \b(?:require|ensure|check|verify|validate|assert|authenticate|authorize|with|has)_?\w*?(?:user|auth|session|admin|token|role|permission)\w*\s*\(
    | \bjwt\s*\.\s*(?:verify|decode)\s*\(
    | \bauth\s*\.\s*(?:getUser|getSession|uid|currentUser|verifyIdToken)\b
    | \bcurrent_user\b | \brequest\s*\.\s*user\b | \bg\s*\.\s*user\b
    | session\s*\[\s*['"]user | session\s*\.\s*get\s*\(\s*['"]user
    | \bstatus(?:_code)?\s*[=(:]\s*(?:status\.HTTP_)?401\b | \babort\s*\(\s*40[13] | \bUnauthorized\b
    | \bHTTP_40[13]
    | @\s*(?:\w+\s*\.\s*)?(?:login_required|jwt_required|auth_required|token_required|requires_auth|admin_required
        |roles_required|roles_accepted|permission_required|fresh_jwt_required|user_required|staff_member_required
        |permission_classes|authentication_classes|permission\s*\()
    | Depends\s*\(\s*[\w.]*(?:user|auth|token|verify|current|admin|security|session|api_key|apikey|scheme)
    | \bSecurity\s*\(
    | \bpassport\s*\.\s*authenticate\b
    | \bIsAuthenticated\b
    """,
    re.X | re.I,
)

# Middleware argument names that look like auth (Express style `app.post('/x', requireAuth, handler)`).
AUTH_MIDDLEWARE = re.compile(
    r"(?i)\b[\w$]*(?:auth|protect|requireuser|require_user|loggedin|logged_in|jwt|verify|ensure|guard|clerk|passport"
    r"|session|isadmin|requirerole|permission|token|secured?|private|apikey|api_key)[\w$]*\b"
)

ADMIN_ROLE_EVIDENCE = re.compile(
    r"(?i)(?:get_current_active_superuser|require_superuser)|\b(?:is_?admin|is_staff|is_superuser|superuser|roles?\b|permissions?|has_?role|require_?role|require_?admin"
    r"|admin_required|check_?role|authorize\s*\(|ability|can\s*\(|isStaff|staff_member_required|scopes?\b)"
)

OWNERSHIP_EVIDENCE = re.compile(
    r"(?i)(?:\buser_?id\b|\bowner(?:_?id)?\b|\bauthor(?:_?id)?\b|\bcreated_?by\b|current_user\s*(?:\(\s*\))?\s*\.\s*id"
    r"|\.user\s*[?!]?\s*\.\s*(?:id|_id|sub)\b|session\s*\.\s*user|auth\s*\.\s*uid|\buid\b|\btenant|\borg_?id\b"
    r"|\baccount_?id\b|\bsub\b)"
)
# a reset that needs a signed, emailed token, or a route that takes no credential: nothing to guess or rate-limit
TOKEN_RESET = re.compile(r"(?i)verify\w*token\w*\s*\(|[<{:]token\b")
CREDENTIAL_PATH = re.compile(r"(?i)(?:^|[/_.\-])(?:login|signin|sign-in|sign_in|password|forgot|otp|magic-link)(?:$|[/_.\-])")
CREDENTIAL_INPUT = re.compile(r"(?i)password|passwd|\botp\b|\bcode\b|e-?mail|username|credential|form_data|sign_?in")

PUBLIC_PATH = re.compile(
    r"(?i)(?:^|[/_.\-\s])(?:login|logout|signin|sign-in|sign_in|signup|sign-up|sign_up|register|auth|oauth|token|refresh"
    r"|sessions?|health|healthz|ready|readyz|live|livez|ping|status|version|webhooks?|callback|public|forgot|reset"
    r"|verify|confirm|csrf|contact|subscribe|unsubscribe|newsletter|waitlist|feedback|track|analytics|og|robots"
    r"|sitemap|metrics|nextauth)(?:$|[/_.\-\s\[{<:])"
)

LOGIN_PATH = re.compile(
    r"(?i)(?:^|[/_.\-])(?:login|signin|sign-in|sign_in|token|forgot|reset|otp|verify-otp|password|magic-link)(?:$|[/_.\-])"
)

WEBHOOK_PATH = re.compile(r"(?i)webhook")
WEBHOOK_VERIFY = re.compile(
    r"(?i)constructEvent|construct_event|webhooks\s*\.\s*verify|verifyWebhook|verify_webhook|validateWebhook"
    r"|Webhook\s*\(|svix|hmac|compare_digest|timingSafeEqual|verify_?signature|validate_?signature"
    r"|x-hub-signature|stripe-signature|x-signature|svix-signature|WebhookSignature|verify_header|verifyHeader"
    r"|constant_?time_?(?:equals?|compare)|safe_?compare|secure_?compare"
)

RATE_LIMIT_EVIDENCE = re.compile(
    r"(?i)rate.?limit|ratelimit|throttl|slowapi|flask_limiter|flask-limiter|\blimiter\b|express-slow-down"
    r"|rate-limiter-flexible|@upstash/ratelimit|django_ratelimit|@nestjs/throttler|arcjet|bottleneck|\bLimiter\b"
)

SERVER_VALIDATION_EVIDENCE = re.compile(
    r"""(?x)
    (?:from|require\s*\(|import)\s*['"](?:npm:|jsr:)?(?:zod|joi|yup|valibot|express-validator|class-validator|ajv|superstruct
        |@sinclair/typebox|@hapi/joi|arktype|io-ts|typia|@vinejs/vine|celebrate|fastest-validator)['"/@]
    | \bfrom\s+(?:pydantic|marshmallow|wtforms|flask_wtf|cerberus|voluptuous|jsonschema|rest_framework|django\s+import\s+forms|msgspec|attrs)\b
    | \bimport\s+(?:pydantic|marshmallow|cerberus|voluptuous|jsonschema)\b
    | \bforms\s*\.\s*(?:Form|ModelForm)\b | \bserializers\s*\.\s*\w*Serializer\b
    """
)
CLIENT_VALIDATION = re.compile(r"""(?:from|require\s*\()\s*['"](?:zod|yup|valibot|react-hook-form|joi|vee-validate)['"]""")

MUTATION_EVIDENCE = re.compile(
    r"(?i)\.\s*(?:insert|insertOne|insertMany|update|updateOne|updateMany|upsert|delete|deleteOne|deleteMany|remove"
    r"|create|createMany|destroy|save|rpc|bulkCreate|findOneAndUpdate|findByIdAndUpdate|findByIdAndDelete)\s*\("
    r"|\b(?:INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b"
)

LLM_CALL_JS = re.compile(
    r"\.\s*(?:chat\s*\.\s*completions\s*\.\s*(?:create|parse|stream)|completions\s*\.\s*create|responses\s*\.\s*(?:create|stream|parse)"
    r"|messages\s*\.\s*(?:create|stream)|generateContent(?:Stream)?|sendMessage(?:Stream)?)\s*\("
    r"|\b(?:generateText|streamText|generateObject|streamObject)\s*\("
    r"|\b(?:llm|chain|agent|chatModel|model|executor|graph|runnable)\w*\s*\.\s*(?:invoke|stream|batch)\s*\("
    r"|https?://(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com"
    r"|api\.mistral\.ai|openrouter\.ai/api|api\.deepseek\.com|api\.x\.ai|api\.together\.xyz|api\.cohere\.(?:ai|com)"
    r"|api\.replicate\.com|api\.elevenlabs\.io|api\.perplexity\.ai|api\.fireworks\.ai)"
)

LLM_HOSTS = re.compile(
    r"https?://(?:api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com"
    r"|api\.mistral\.ai|openrouter\.ai/api|api\.deepseek\.com|api\.x\.ai|api\.together\.xyz|api\.cohere\.(?:ai|com)"
    r"|api\.replicate\.com|api\.elevenlabs\.io|api\.perplexity\.ai|api\.fireworks\.ai)"
)

DANGEROUS_AGENT_OPTIONS = re.compile(
    r"\ballow_dangerous_code\s*=\s*True|\ballow_dangerous_requests\s*=\s*True|\ballowDangerousCode\s*:\s*true"
    r"|\b(?:PythonREPLTool|PythonAstREPLTool|PythonREPL|ShellTool|BashProcess|PALChain|create_python_agent)\b"
    r"|\bload_tools\s*\([^)]*['\"](?:terminal|python_repl|requests_all|requests_post)['\"]"
    r"|\bLocalCommandLineCodeExecutor\b|\bcode_execution_config\s*=\s*\{[^}]*['\"]use_docker['\"]\s*:\s*False"
)

USERISH_NAME = re.compile(
    r"(?i)^(?:user_?input|user_?message|user_?msg|message|msg|question|query|prompt|user_?prompt|text|input|content"
    r"|comment|body|instruction|instructions|user_?query|q|user_?text|user_?content|search|feedback)$"
)

SECRET_NAME = re.compile(
    r"(?i)(?:api_?key|apikey|secret|passw(?:or)?d|pwd|token|private_?key|access_?key|client_?secret|auth_?key"
    r"|credential|service_?role)"
)

# the model call asked for JSON mode or a schema, so the output parses (LLM011)
JSON_MODE = re.compile(
    r"response_format|json_object|json_schema|response_mime_type|responseMimeType|with_structured_output"
    r"|generateObject|streamObject|\bformat\s*[=:]\s*['\"]json['\"]"
)

PLACEHOLDER = re.compile(
    r"(?i)your|example|xxx|\*\*\*|placeholder|changeme|change_me|replace|dummy|fake|sample|redacted|insert|todo"
    r"|<[^<>]{0,100}>|\$\{|\{\{|%\(|^\$|process\.env|import\.meta|os\.environ|getenv|0000000000|1234567890|abcdef"
    r"|lorem|test_?key|mock|not.?real|my_?(?:api|secret)|_here\b|\.\.\.|^sk-\.+$|^none$|^null$|^env\(|^\$\(|^vault:|changethis"
)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def looks_random(value: str) -> bool:
    """A string that looks like a generated credential rather than a word, path or identifier."""
    if len(value) < 12 or PLACEHOLDER.search(value):
        return False
    if "://" in value or value.startswith(("/", "./", "../", "~")) or " " in value:
        return False
    if re.fullmatch(r"[A-Z0-9_]+", value) and "_" in value:
        return False  # an env var name, not a value
    if re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+){2,}", value) and \
            sum(1 for seg in re.split(r"[._-]", value) if seg.isalpha() and len(seg) >= 3) >= 2:
        return False  # support.constant.color.w3c-standard-name
    if re.fullmatch(r"[a-z]+(?:[._-][a-z]+)+", value):
        return False  # dotted.or-dashed words
    if re.fullmatch(r"\d+(?:\.\d+)*", value):
        return False
    has_alpha = bool(re.search(r"[A-Za-z]", value))
    has_digit = bool(re.search(r"\d", value))
    e = entropy(value)
    if has_alpha and has_digit and e >= 3.3:
        return True
    return len(value) >= 24 and e >= 4.0


def mask(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return secret[:4] + "*" * min(12, len(secret) - 6) + secret[-2:]


class Custom:
    """Project knowledge from the config file: the project's own auth helpers, sanitizers and public paths."""

    def __init__(self) -> None:
        self.reset()

    def reset(self, auth_helpers=(), sanitizers=(), public_paths=()) -> None:
        self.auth_rx = re.compile(r"(?<![\w$])(?:" + "|".join(map(re.escape, auth_helpers)) + r")(?![\w$])") if auth_helpers else None
        self.sanitizers = set(sanitizers)
        self.sanitizer_rx = re.compile(r"(?<![\w$])(?:" + "|".join(map(re.escape, sanitizers)) + r")\s*\(") if sanitizers else None
        self.public_paths = list(public_paths)

    def is_auth(self, text: str) -> bool:
        return bool(self.auth_rx and self.auth_rx.search(text))

    def is_sanitizer(self, text: str) -> bool:
        return bool(self.sanitizer_rx and self.sanitizer_rx.search(text))

    def is_public(self, path: str) -> bool:
        import fnmatch

        return any(fnmatch.fnmatchcase(path, p) for p in self.public_paths)


CUSTOM = Custom()
