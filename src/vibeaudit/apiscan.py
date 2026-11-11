"""API and auth checks added in 0.7.2: AUTH011-AUTH014, BE019, BE020 (all preview)."""
from __future__ import annotations

import re
from typing import Callable, List

from . import heuristics as H
from .files import Project, SourceFile
from .guard import finditer
from .lexer import match_close
from .model import Route

Add = Callable[..., None]  # ProjectScanner.add(sf_or_rel, line, rule, message, severity="")

MIXED_ALGS = re.compile(r"algorithms['\"]?\s*[:=]\s*\[(?=[^\]]{0,200}\bHS\d)(?=[^\]]{0,200}\b(?:RS|ES|PS)\d)[^\]]{0,200}\]")
PY_JWT_DECODE = re.compile(r"\bjwt\s*\.\s*decode\s*\(")
SET_COOKIE = re.compile(
    r"""(?:\bres(?:ponse)?\s*\.\s*cookie|\bcookies\s*\(\s*\)\s*\.\s*set|\b(?:cookies|cookieStore)\s*\.\s*set|\.\s*set_cookie)\s*\(""")
AUTH_COOKIE_NAME = re.compile(r"""^\s*(?:key\s*=\s*)?['"`][\w.-]*(?:session|token|auth|jwt|sid|access|refresh)[\w.-]*['"`]""", re.I)
CSRF_EVIDENCE = re.compile(r"(?i)csrf|xsrf|csurf|double.?submit")
MANUAL_HMAC = re.compile(r"createHmac|hmac\s*\.\s*new|compare_digest|timingSafeEqual|crypto\.subtle\.(?:sign|verify)")
REPLAY_GUARD = re.compile(
    r"(?i)timestamp|tolerance|replay|nonce|max_?age|constructEvent|construct_event|svix|webhooks\s*\.\s*(?:verify|unwrap)"
    r"|Date\.now|time\.time|\bt=|event_?id|idempoten|delivery")
FORWARDED_FOR = re.compile(r"""(?i)headers?\s*(?:\[|\.\s*get\s*\(|\.)\s*['"]?x-forwarded-for""")
LAST_HOP = re.compile(r"\.pop\(\)|\[\s*-\s*1\s*\]|\.at\(\s*-\s*1\s*\)|\.slice\(\s*-\s*1|trust.?proxy|ProxyFix|TRUSTED_PROXIES|forwarded_allow_ips")
PAYMENT = re.compile(r"(?i)stripe|paypal|razorpay|paymentIntent|payment_intent|checkout\.sessions|mollie|square|braintree|paddle")
REQUEST_SOURCE = r"(?:req\.body|request\.body|body|request\.(?:json|form|data|POST|get_json\(\))|data|payload|input|params)"
CLIENT_AMOUNT = re.compile(
    r"(?i)\b(?:unit_amount(?:_decimal)?|amount|price|total)['\"]?\s*[:=]\s*(?:(?:Math\.\w+|int|float|Number|parseInt|parseFloat|Decimal)\(\s*){0,2}"
    + REQUEST_SOURCE + r"\s*(?:\??\.|\[|\.get\()\s*['\"]?\w*(?:amount|price|total|cost)\w*")
DESTRUCTURED_AMOUNT = re.compile(
    r"\{[^{}]{0,200}\b(amount|price|total)\b[^{}]{0,200}\}\s*=\s*(?:await\s+)?(?:req\.body\b|req\.json\(\)|request\.json\(\)|body\b)")
RAW_MAIL_HEADER = re.compile(r"""["'`](?:Subject|To|From|Cc|Bcc|Reply-To):\s*(?:\{|\$\{|["'`]\s*\+|%s|["'`]\s*%)""")
MIME_HEADER_FROM_REQUEST = re.compile(
    r"""\[\s*['"](?:Subject|To|From|Cc|Bcc|Reply-To)['"]\s*\]\s*=\s*[^\n]{0,120}?\b(?:request\.(?:form|json|args|data|POST|GET)|req\.body)\b""")
RAW_MAIL = re.compile(r"\bsmtplib\b|\bsendmail\s*\(|\bSMTP(?:_SSL)?\s*\(|\bMIME(?:Text|Multipart)\b|\bnet\s*\.\s*createConnection|\bmail\s*\(")


def _args(bare: str, code: str, open_paren: int) -> str:
    """The text between a call's parentheses; a bounded slice when the call does not close nearby."""
    close = match_close(bare, open_paren)
    if close < 0 or close - open_paren > 4000:
        close = min(len(code), open_paren + 600)
    return code[open_paren + 1:close]


def run(project: Project, routes: List[Route], all_code: str, add: Add) -> None:
    csrf = bool(CSRF_EVIDENCE.search(all_code))
    for sf in project.files:
        v = sf.cache.get("views")
        if v is None or sf.is_test or sf.kind not in ("py", "js"):
            continue
        _file(sf, v.code, v.bare, csrf, add)  # type: ignore[attr-defined]
    for r in routes:
        _route(r, add)


def _file(sf: SourceFile, code: str, bare: str, csrf: bool, add: Add) -> None:
    for m in finditer(MIXED_ALGS, code):
        add(sf, sf.line_at(m.start()), "AUTH011", "The token is accepted with both HMAC and public-key algorithms (key confusion).")
    if sf.kind == "py":
        for m in finditer(PY_JWT_DECODE, bare):
            args = _args(bare, code, m.end() - 1)
            if "algorithms" not in args and "verify" not in args and "**" not in args:  # verify=False is BE016
                add(sf, sf.line_at(m.start()), "AUTH011", "jwt.decode() does not pin the accepted algorithms.")
    if not csrf:
        for m in finditer(SET_COOKIE, bare):
            args = _args(bare, code, m.end() - 1)
            auth_cookie = AUTH_COOKIE_NAME.search(args) or re.search(r"(?i)\bhttp_?only\b", args)
            none = re.search(r"""(?i)same_?site['"]?\s*[:=]\s*['"]none""", args)
            if auth_cookie and (none or not re.search(r"(?i)same_?site", args)) and "..." not in args and "**" not in args:
                add(sf, sf.line_at(m.start()), "AUTH012",
                    "The session cookie is set with SameSite=None and the project has no CSRF protection." if none else
                    "The session cookie sets no SameSite attribute and the project has no CSRF protection.")
    if H.RATE_LIMIT_EVIDENCE.search(code) and not LAST_HOP.search(code):
        m = FORWARDED_FOR.search(code)
        if m:
            add(sf, sf.line_at(m.start()), "AUTH014", "The rate limit key comes from X-Forwarded-For, which the client can set.")
    if RAW_MAIL.search(code):
        for m in finditer(RAW_MAIL_HEADER, code):
            add(sf, sf.line_at(m.start()), "BE020", "An email header is built by formatting a value into the header line.")
        for m in finditer(MIME_HEADER_FROM_REQUEST, code):
            add(sf, sf.line_at(m.start()), "BE020", "An email header is set straight from request data.")


def _route(r: Route, add: Add) -> None:
    body = r.body
    if H.WEBHOOK_PATH.search(r.path) and MANUAL_HMAC.search(body) and not REPLAY_GUARD.search(body):
        add(r.file, r.line, "AUTH013", f"Webhook {r.path} checks a signature but no timestamp, so a captured request can be replayed.")
    if PAYMENT.search(body):
        m = CLIENT_AMOUNT.search(body)
        if m is None:
            d = DESTRUCTURED_AMOUNT.search(body)
            if d and re.search(r"(?i)\b(?:unit_amount|amount)['\"]?\s*:\s*(?:Math\.\w+\(\s*)?%s\b|[{,]\s*amount\s*[,}]" % d.group(1), body[d.end():]):
                m = d
        if m is not None:
            add(r.file, r.line, "BE019", "The amount charged comes from the request, so the client can set its own price.")
