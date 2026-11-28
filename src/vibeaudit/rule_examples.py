"""Curated unsafe and safe code examples per rule for `vibeaudit explain RULE` and MCP rule docs."""
from __future__ import annotations

from typing import Dict

# Each entry maps a rule ID to {"lang": str, "unsafe": str, "safe": str}. Plain ASCII only.
EXAMPLES: Dict[str, Dict[str, str]] = {
    "SEC001": {
        "lang": "python",
        "unsafe": 'OPENAI_API_KEY = "sk-proj-..."  # committed in source',
        "safe": 'OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]',
    },
    "SEC002": {
        "lang": "bash",
        "unsafe": "# committed keys/server.pem in git repository",
        "safe": "# mount private keys at runtime via secret volume and add *.pem to .gitignore",
    },
    "SEC004": {
        "lang": "python",
        "unsafe": 'app.secret_key = os.getenv("SECRET_KEY", "dev-fallback-secret")',  # vibeaudit: ignore[SEC004] -- rule documentation example
        "safe": 'app.secret_key = os.environ["SECRET_KEY"]  # fail fast if unset',
    },
    "SEC005": {
        "lang": "env",
        "unsafe": 'DATABASE_URL="postgres://admin:RealPass123@db.prod.example.com:5432/app"',  # vibeaudit: ignore[SEC005] -- rule documentation example
        "safe": "# store real credentials in host secrets / untracked .env; commit placeholders only",
    },
    "SEC008": {
        "lang": "javascript",
        "unsafe": "const apiKey = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;",  # vibeaudit: ignore[SEC008] -- rule documentation example
        "safe": "const apiKey = process.env.STRIPE_SECRET_KEY; // server route only",
    },
    "SEC009": {
        "lang": "typescript",
        "unsafe": 'createClient(url, process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!);',  # vibeaudit: ignore[SEC008] -- rule documentation example
        "safe": 'createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!); // keep service_role server-only',
    },
    "SEC010": {
        "lang": "python",
        "unsafe": 'print("Using API key:", api_key)',
        "safe": 'print("Using API key:", api_key[:4] + "***")',
    },
    "SEC011": {
        "lang": "python",
        "unsafe": 'ADMIN_PASSWORD = "hardcoded-admin-password"',  # vibeaudit: ignore[SEC011] -- rule documentation example
        "safe": 'ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]',
    },
    "DEP001": {
        "lang": "text",
        "unsafe": "flask-openai-chat-helper==1.0.0  # invented / missing on PyPI",
        "safe": "openai==1.50.0  # verified real package name",
    },
    "DEP002": {
        "lang": "text",
        "unsafe": "reqeusts==2.31.0  # typo of requests",
        "safe": "requests==2.32.3",
    },
    "DEP004": {
        "lang": "text",
        "unsafe": "pyyaml==5.3  # vulnerable pinned version",
        "safe": "pyyaml==6.0.2  # patched version",
    },
    "BE001": {
        "lang": "python",
        "unsafe": 'cursor.execute(f"SELECT * FROM users WHERE email = \'{email}\'")',
        "safe": 'cursor.execute("SELECT * FROM users WHERE email = %s", (email,))',
    },
    "BE002": {
        "lang": "python",
        "unsafe": 'subprocess.run(f"convert {filename} out.png", shell=True)',
        "safe": 'subprocess.run(["convert", validated_name, "out.png"], check=True)',
    },
    "BE003": {
        "lang": "javascript",
        "unsafe": "const result = eval(req.body.formula);",
        "safe": "const data = JSON.parse(req.body.formula); // or dispatch an explicit allow-list",
    },
    "BE004": {
        "lang": "python",
        "unsafe": "obj = pickle.loads(request.data)",
        "safe": "obj = json.loads(request.data)",
    },
    "BE005": {
        "lang": "javascript",
        "unsafe": "const resp = await fetch(req.query.url);",
        "safe": "const target = assertAllowedHost(req.query.url); const resp = await fetch(target);",
    },
    "BE006": {
        "lang": "python",
        "unsafe": 'return send_file(os.path.join(UPLOAD_DIR, request.args["file"]))',
        "safe": (
            'base = Path(UPLOAD_DIR).resolve()\n'
            'target = (base / request.args["file"]).resolve()\n'
            'if not target.is_relative_to(base): abort(403)'
        ),
    },
    "BE007": {
        "lang": "python",
        "unsafe": 'return render_template_string("Hello " + request.args["name"])',
        "safe": 'return render_template("hello.html", name=request.args["name"])',
    },
    "BE008": {
        "lang": "javascript",
        "unsafe": "res.redirect(req.query.next);",
        "safe": 'const next = safeRelativePath(req.query.next) || "/"; res.redirect(next);',
    },
    "BE009": {
        "lang": "javascript",
        "unsafe": "await User.create(req.body);",
        "safe": "const { name, email } = UserSchema.parse(req.body); await User.create({ name, email });",
    },
    "BE010": {
        "lang": "javascript",
        "unsafe": "await users.findOne({ $where: `this.name == '${req.query.name}'` });",
        "safe": "await users.findOne({ name: String(req.query.name) });",
    },
    "BE011": {
        "lang": "python",
        "unsafe": "app.run(debug=True)",
        "safe": 'app.run(debug=os.getenv("FLASK_DEBUG") == "1")',
    },
    "BE012": {
        "lang": "javascript",
        "unsafe": 'app.use(cors({ origin: "*", credentials: true }));',
        "safe": 'app.use(cors({ origin: ["https://app.example.com"], credentials: true }));',
    },
    "BE013": {
        "lang": "python",
        "unsafe": "requests.get(url, verify=False, timeout=10)",
        "safe": "requests.get(url, verify=True, timeout=10)",
    },
    "BE014": {
        "lang": "python",
        "unsafe": 'digest = hashlib.md5(password.encode()).hexdigest()',
        "safe": 'hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
    },
    "BE015": {
        "lang": "python",
        "unsafe": 'reset_token = "".join(random.choices(string.hexdigits, k=32))',
        "safe": "reset_token = secrets.token_urlsafe(32)",
    },
    "BE016": {
        "lang": "python",
        "unsafe": 'payload = jwt.decode(token, options={"verify_signature": False})',
        "safe": 'payload = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])',
    },
    "BE017": {
        "lang": "python",
        "unsafe": "except Exception as err:\n    return jsonify({'error': str(err)}), 500",
        "safe": "except Exception:\n    logger.exception('request failed')\n    return jsonify({'error': 'internal error'}), 500",
    },
    "BE021": {
        "lang": "python",
        "unsafe": "tree = lxml.etree.fromstring(xml_bytes)",
        "safe": "import defusedxml.ElementTree as ET\ntree = ET.fromstring(xml_bytes)",
    },
    "BE023": {
        "lang": "javascript",
        "unsafe": "const re = /([0-9]+)+#/;",
        "safe": "const re = /[0-9]+#/;",
    },
    "FE001": {
        "lang": "javascript",
        "unsafe": "el.innerHTML = userComment;",
        "safe": "el.textContent = userComment; // or DOMPurify.sanitize(userComment)",
    },
    "FE002": {
        "lang": "javascript",
        "unsafe": 'fetch("https://api.openai.com/v1/chat/completions", { headers: { Authorization: `Bearer ${key}` } });',
        "safe": 'fetch("/api/chat", { method: "POST", body: JSON.stringify({ prompt }) });',
    },
    "FE003": {
        "lang": "javascript",
        "unsafe": 'if (localStorage.getItem("isAdmin") === "true") showAdmin();',
        "safe": 'const { isAdmin } = await fetch("/api/me").then(r => r.json());',
    },
    "FE004": {
        "lang": "javascript",
        "unsafe": 'window.addEventListener("message", (e) => handle(e.data));',
        "safe": 'window.addEventListener("message", (e) => { if (e.origin !== "https://app.example.com") return; handle(e.data); });',
    },
    "FE005": {
        "lang": "javascript",
        "unsafe": 'localStorage.setItem("auth_token", jwt);',
        "safe": "// issue an httpOnly, Secure, SameSite=Lax cookie from the server",
    },
    "AUTH001": {
        "lang": "python",
        "unsafe": '@app.post("/api/orders")\ndef create_order():\n    db.save(request.json)',
        "safe": '@app.post("/api/orders")\n@login_required\ndef create_order():\n    db.save(request.json)',
    },
    "AUTH002": {
        "lang": "javascript",
        "unsafe": 'app.post("/admin/delete-user", requireAuth, deleteUser);',
        "safe": 'app.post("/admin/delete-user", requireAuth, requireRole("admin"), deleteUser);',
    },
    "AUTH003": {
        "lang": "python",
        "unsafe": "Order.query.filter_by(id=order_id).delete()",
        "safe": "Order.query.filter_by(id=order_id, user_id=current_user.id).delete()",
    },
    "AUTH008": {
        "lang": "python",
        "unsafe": "def verify_token(token):\n    return True",
        "safe": 'def verify_token(token):\n    return jwt.decode(token, SECRET, algorithms=["HS256"])',
    },
    "AUTH010": {
        "lang": "javascript",
        "unsafe": 'app.post("/login", loginHandler);',
        "safe": 'app.post("/login", loginRateLimiter, loginHandler);',
    },
    "AUTH011": {
        "lang": "javascript",
        "unsafe": "jwt.verify(token, secret);",
        "safe": 'jwt.verify(token, secret, { algorithms: ["HS256"] });',
    },
    "CFG001": {
        "lang": "dockerfile",
        "unsafe": "FROM python:3.12-slim\nCMD [\"python\", \"app.py\"]",
        "safe": "FROM python:3.12-slim\nRUN useradd -m app\nUSER app\nCMD [\"python\", \"app.py\"]",
    },
    "CFG004": {
        "lang": "yaml",
        "unsafe": "run: echo \"${{ github.event.issue.title }}\"",
        "safe": 'env:\n  TITLE: ${{ github.event.issue.title }}\nrun: echo "$TITLE"',
    },
    "CFG010": {
        "lang": "yaml",
        "unsafe": "- uses: actions/checkout@v4",
        "safe": "- uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1  # v7.0.1",
    },
    "LLM001": {
        "lang": "python",
        "unsafe": 'messages = [{"role": "system", "content": f"Help with: {user_input}"}]',
        "safe": 'messages = [{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": user_input}]',
    },
    "LLM002": {
        "lang": "python",
        "unsafe": "exec(completion.choices[0].message.content)",
        "safe": "data = MySchema.model_validate_json(completion.choices[0].message.content)",
    },
    "LLM003": {
        "lang": "python",
        "unsafe": 'client.chat.completions.create(model="gpt-4o", messages=msgs)',
        "safe": 'client.chat.completions.create(model="gpt-4o", max_tokens=1024, messages=msgs)',
    },
    "LLM005": {
        "lang": "python",
        "unsafe": "@tool\ndef run_shell(cmd: str):\n    return subprocess.check_output(cmd, shell=True)",
        "safe": "@tool\ndef lookup_doc(doc_id: str):\n    return docs_allowlist.get(doc_id)",
    },
    "LLM011": {
        "lang": "python",
        "unsafe": "data = json.loads(resp.choices[0].message.content)",
        "safe": "try:\n    data = json.loads(resp.choices[0].message.content)\nexcept json.JSONDecodeError:\n    data = None",
    },
    "DATA001": {
        "lang": "python",
        "unsafe": "for u in users:\n    orders = db.query(Order).filter_by(user_id=u.id).all()",
        "safe": "orders = db.query(Order).filter(Order.user_id.in_([u.id for u in users])).all()",
    },
    "DATA004": {
        "lang": "python",
        "unsafe": "total = float(price) * quantity",
        "safe": 'total = Decimal(str(price)) * quantity  # or store integer cents',
    },
    "REL001": {
        "lang": "python",
        "unsafe": "resp = requests.get(url)",
        "safe": "resp = requests.get(url, timeout=10)",
    },
    "QA003": {
        "lang": "python",
        "unsafe": "try:\n    charge_card()\nexcept Exception:\n    pass",
        "safe": 'try:\n    charge_card()\nexcept PaymentError as err:\n    logger.exception("charge failed: %s", err); raise',
    },
    "QA006": {
        "lang": "python",
        "unsafe": "from .missing_helper import build_invoice",
        "safe": "from .billing import build_invoice  # import from an existing module",
    },
}


def get_example(rule_id: str) -> Dict[str, str]:
    """Return curated unsafe/safe examples for `rule_id`, or a clear generic template if uncurated."""
    rid = rule_id.upper()
    if rid in EXAMPLES:
        return dict(EXAMPLES[rid])
    from .rules import RULES

    rule = RULES.get(rid)
    hint = rule.fix if rule is not None else "Follow the rule's remediation guidance."
    return {
        "lang": "text",
        "unsafe": f"# Pattern flagged by {rid}: {rule.title if rule else rid}",
        "safe": f"# Remediation: {hint}",
    }
