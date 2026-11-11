"""API and auth rules added in 0.7.2 (AUTH011-AUTH014, BE019, BE020)."""
import time

from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

NEW = ("AUTH011", "AUTH012", "AUTH013", "AUTH014", "BE019", "BE020")


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def found(root, *rules):
    res = scan(str(root), Options(offline=True, external="none", min_severity="low"))
    assert res.meta.get("internal_errors", []) == []
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id in (rules or NEW))


def test_new_rules_start_as_preview():
    assert all(RULES[r].preview and RULES[r].preview_reason for r in NEW)


def test_jwt_algorithms_must_be_pinned(tmp_path):
    write(tmp_path, "auth.py", "import jwt\n"
          "def a(t):\n    return jwt.decode(t, KEY)\n"                                   # 3
          "def b(t):\n    return jwt.decode(t, KEY, algorithms=['HS256'])\n"
          "def c(t):\n    return jwt.decode(t, PUB, algorithms=['HS256', 'RS256'])\n"     # 7
          "def d(t):\n    return jwt.decode(t, options={'verify_signature': False})\n")   # BE016, not this rule
    write(tmp_path, "auth.ts", "jwt.verify(token, key, { algorithms: ['RS256', 'HS256'] });\n"   # 1
          "jwt.verify(token, key, { algorithms: ['RS256'] });\njwt.verify(token, secret);\n")
    assert found(tmp_path, "AUTH011") == [("auth.py", 3, "AUTH011"), ("auth.py", 7, "AUTH011"), ("auth.ts", 1, "AUTH011")]


def test_session_cookie_without_samesite_and_csrf(tmp_path):
    write(tmp_path, "server.js",
          "res.cookie('session', token, { httpOnly: true, secure: true });\n"                    # 1
          "res.cookie('session', token, { httpOnly: true, sameSite: 'lax' });\n"
          "res.cookie('auth_token', token, { sameSite: 'none', secure: true });\n"               # 3
          "res.cookie('theme', 'dark');\n")
    write(tmp_path, "app.py", "def login(resp):\n    resp.set_cookie('access_token', t, httponly=True)\n"   # 2
          "    resp.set_cookie('access_token', t, httponly=True, samesite='Lax')\n")
    assert found(tmp_path, "AUTH012") == [("app.py", 2, "AUTH012"), ("server.js", 1, "AUTH012"), ("server.js", 3, "AUTH012")]
    write(tmp_path, "csrf.js", "app.use(csurf());\n")
    assert found(tmp_path, "AUTH012") == []  # a CSRF token covers cookies without SameSite


def test_webhook_signature_needs_a_replay_guard(tmp_path):
    write(tmp_path, "app.py",
          "@app.post('/webhooks/shop')\ndef shop():\n"                                              # 2
          "    sig = hmac.new(SECRET, request.data, 'sha256').hexdigest()\n"
          "    if not hmac.compare_digest(sig, request.headers['X-Signature']):\n        abort(401)\n"
          "    db.orders.update(paid=True)\n    return ''\n\n"
          "@app.post('/webhooks/safe')\ndef safe():\n"
          "    if abs(time.time() - int(request.headers['X-Timestamp'])) > 300:\n        abort(400)\n"
          "    sig = hmac.new(SECRET, request.data, 'sha256').hexdigest()\n"
          "    if not hmac.compare_digest(sig, request.headers['X-Signature']):\n        abort(401)\n    return ''\n\n"
          "@app.post('/webhooks/stripe')\ndef stripe_hook():\n"
          "    event = stripe.Webhook.construct_event(request.data, sig, secret)\n    return ''\n")
    assert found(tmp_path, "AUTH013") == [("app.py", 2, "AUTH013")]


def test_rate_limit_keyed_on_x_forwarded_for(tmp_path):
    write(tmp_path, "limit.ts", "const ip = req.headers['x-forwarded-for'] ?? 'unknown';\n"                 # 1
          "const { success } = await ratelimit.limit(ip);\n")
    write(tmp_path, "limit_ok.ts", "const ip = req.headers['x-forwarded-for'].split(',').pop();\nawait ratelimit.limit(ip);\n")
    write(tmp_path, "log.ts", "console.log(req.headers['x-forwarded-for']);\n")  # no rate limit here
    assert found(tmp_path, "AUTH014") == [("limit.ts", 1, "AUTH014")]


def test_payment_amount_from_the_client(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "15.0.0", "stripe": "17.0.0"}}')
    write(tmp_path, "app/api/pay/route.ts",
          "export async function POST(req) {\n  const body = await req.json();\n"
          "  const intent = await stripe.paymentIntents.create({ amount: body.amount, currency: 'usd' });\n"   # 3
          "  return Response.json(intent);\n}\n")
    write(tmp_path, "app/api/checkout/route.ts",
          "export async function POST(req) {\n  const { amount, plan } = await req.json();\n"                 # 2
          "  const s = await stripe.checkout.sessions.create({ line_items: [{ price_data: { unit_amount: amount } }] });\n"
          "  return Response.json(s);\n}\n")
    write(tmp_path, "app/api/safe/route.ts",
          "export async function POST(req) {\n  const { planId } = await req.json();\n"
          "  const s = await stripe.checkout.sessions.create({ line_items: [{ price: PRICES[planId], quantity: 1 }] });\n"
          "  return Response.json(s);\n}\n")
    assert found(tmp_path, "BE019") == [("app/api/checkout/route.ts", 1, "BE019"), ("app/api/pay/route.ts", 1, "BE019")]


def test_email_header_injection(tmp_path):
    write(tmp_path, "mailer.py", "import smtplib\nfrom email.mime.text import MIMEText\n"
          "def send(name, body):\n    raw = f'Subject: {name}\\r\\n\\r\\n{body}'\n"                 # 4
          "    smtplib.SMTP('localhost').sendmail(A, B, raw)\n"
          "def contact():\n    msg = MIMEText('x')\n    msg['Subject'] = request.form['subject']\n"  # 8
          "    msg['From'] = 'site@example.com'\n")
    write(tmp_path, "docs.py", "HELP = 'Subject: {topic}'\n")  # no mail is sent from this file
    assert found(tmp_path, "BE020") == [("mailer.py", 4, "BE020"), ("mailer.py", 8, "BE020")]


def test_new_api_patterns_are_linear_on_hostile_input(tmp_path):
    write(tmp_path, "a.py", "import smtplib\nx = jwt.decode(" + "(" * 3000 + "\n" + "msg['Subject'] = " + "a " * 40000 + "\n")
    write(tmp_path, "b.ts", "ratelimit;\nalgorithms: [" + "'HS256', " * 20000 + "\n" + "res.cookie(" * 5000 + "\n"
          + "const {" + " amount, " * 20000 + "\n")
    start = time.time()
    found(tmp_path)
    assert time.time() - start < 15
