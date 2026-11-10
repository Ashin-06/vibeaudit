"""Property tests for the rules, on top of the example fixtures.

1. Vulnerability-preserving mutations (shifted lines, renamed variables, reordered imports, CRLF, trailing
   whitespace and tabs, the whole app moved into a monorepo subfolder, routes wrapped in a function) must
   keep every finding. The `expect:` markers travel with the code, so expectations are recomputed from the
   mutated files: a finding that is lost or invented fails.
2. Safe rewrites (parameterise the query, add the auth check, pin the token limit, ...) must remove exactly
   the targeted finding and add nothing else.
"""
import re
from pathlib import Path

import pytest

from helpers import MARKER, materialize
from vibeaudit.scanner import Options, scan

VULN = ["vuln_flask_llm", "vuln_next_supabase", "vuln_express", "vuln_agent", "vuln_config"]
COMMENT = {".py": "# ", ".js": "// ", ".ts": "// ", ".tsx": "// ", ".jsx": "// ", ".sql": "-- ", ".rules": "// ",
           ".yml": "# ", ".yaml": "# ", ".html": None, ".txt": "# "}
PROJECT_LEVEL = {"QA001", "QA002", "DEP005"}


def expected_from(root: Path, extra_file: Path, prefix: str = ""):
    out = set()
    for path in root.rglob("*"):
        if path.is_file():
            rel = path.relative_to(root).as_posix()
            for i, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                for m in MARKER.finditer(line):
                    out.update((rel, i, r.strip()) for r in m.group(1).split(","))
    if extra_file.exists():
        for line in extra_file.read_text().splitlines():
            if line.strip() and not line.startswith("#"):
                rel, ln, rule = line.strip().rsplit(":", 2)
                out.add((prefix + rel, int(ln), rule))
    return out


def run(root: Path):
    res = scan(str(root), Options(offline=True, external="none"))
    assert res.meta["internal_errors"] == [] and res.meta["skipped"] == []
    return {(f.file, f.line, f.rule_id) for f in res.findings}


def files(root: Path, *suffixes):
    return [p for p in root.rglob("*") if p.is_file() and (not suffixes or p.suffix in suffixes)]


def rewrite(path: Path, fn):
    raw = path.read_bytes().decode("utf-8")
    path.write_bytes(fn(raw).encode("utf-8"))


# ------------------------------------------------------------------ mutations
def m_shift(root):
    """Prepend comment lines to every file that can hold comments (findings move with the code)."""
    for p in files(root):
        prefix = COMMENT.get(p.suffix)
        if prefix and p.name not in ("Dockerfile", "requirements.txt", "docker-compose.yml"):
            rewrite(p, lambda t: f"{prefix}generated header\n{prefix}another line\n\n" + t)


def m_crlf(root):
    for p in files(root):
        rewrite(p, lambda t: t.replace("\n", "\r\n"))


def m_trailing_whitespace_and_tabs(root):
    for p in files(root, ".py", ".js", ".ts", ".tsx", ".sql", ".html"):
        def fix(t, js=p.suffix in (".js", ".ts", ".tsx")):
            lines = [ln + "   " if ln.strip() else ln for ln in t.split("\n")]
            if js:
                lines = [re.sub(r"^((?:  )+)", lambda m: "\t" * (len(m.group(1)) // 2), ln) for ln in lines]
            return "\n".join(lines)
        rewrite(p, fix)


RENAMES = {
    "vuln_flask_llm": {"completion": "llm_result", "script": "generated_code", "blob": "raw_bytes", "resp": "upstream",
                       "rows": "records", "plan": "model_plan", "obj": "decoded", "config": "parsed_cfg"},
    "vuln_next_supabase": {"completion": "llmResult", "reply": "answerText", "supabase": "adminClient", "body": "payload",
                           "html": "markup", "setHtml": "setMarkup", "schema": "formSchema"},
    "vuln_express": {"rows": "records", "note": "created", "q": "searchTerm", "r": "upstream", "user": "account"},
    "vuln_agent": {"result": "agent_output", "weights": "state_dict", "fh": "handle", "command": "cmd_line", "path": "file_path"},
    "vuln_config": {},
}


def m_rename(root):
    names = RENAMES[root.name]
    for p in files(root, ".py", ".js", ".ts", ".tsx", ".html"):
        def fix(t):
            for old, new in names.items():
                t = re.sub(r"(?<![\w$.\"'/@-])" + re.escape(old) + r"(?![\w$\"'/-])", new, t)  # not inside package names
            return t
        rewrite(p, fix)


def m_reverse_imports(root):
    for p in files(root, ".py", ".js", ".ts", ".tsx"):
        def fix(t):
            lines = t.split("\n")
            i = 0
            while i < len(lines) and not re.match(r"(import |from |const \w+ = require\()", lines[i]):
                if lines[i].strip() and not lines[i].startswith(('"use', "'use")):
                    return t
                i += 1
            j = i
            while j < len(lines) and re.match(r"(import |from |const \{?[\w, ]+\}? = require\()", lines[j]):
                j += 1
            lines[i:j] = lines[i:j][::-1]
            return "\n".join(lines)
        rewrite(p, fix)


MUTATIONS = [m_shift, m_crlf, m_trailing_whitespace_and_tabs, m_rename, m_reverse_imports]


@pytest.mark.parametrize("mutate", MUTATIONS, ids=[m.__name__ for m in MUTATIONS])
@pytest.mark.parametrize("name", VULN)
def test_findings_survive_neutral_mutations(tmp_path, name, mutate):
    root = materialize(name, tmp_path)
    mutate(root)
    exp = expected_from(root, Path(__file__).parent / "fixtures" / f"{name}.expected")
    act = run(root)
    assert act == exp, f"missing {sorted(exp - act)}\nunexpected {sorted(act - exp)}"


@pytest.mark.parametrize("name", VULN + ["clean_app"])
def test_findings_survive_moving_into_a_monorepo_subfolder(tmp_path, name):
    staged = materialize(name, tmp_path / "stage")
    root = tmp_path / "mono"
    target = root / "services" / name
    target.parent.mkdir(parents=True)
    staged.rename(target)
    if (target / ".github").exists():  # GitHub only runs workflows from the repository root
        (target / ".github").rename(root / ".github")
    exp = expected_from(root, Path(__file__).parent / "fixtures" / f"{name}.expected")
    exp = {(f if f.startswith((".github/", "services/")) else "services/" + name + "/" + f, ln, r) for f, ln, r in exp}
    act = run(root)
    # project-wide findings are anchored to whatever manifest is at the root, so compare those by rule only
    assert {x for x in act if x[2] not in PROJECT_LEVEL} == {x for x in exp if x[2] not in PROJECT_LEVEL}
    assert {x[2] for x in act if x[2] in PROJECT_LEVEL} == {x[2] for x in exp if x[2] in PROJECT_LEVEL}


def test_express_routes_wrapped_in_a_registration_function(tmp_path):
    root = materialize("vuln_express", tmp_path)
    server = root / "server.js"
    text = server.read_text()
    start = text.index('app.post("/api/login"')
    end = text.index("app.use((err, req, res, next)")
    server.write_text(text[:start] + "function registerRoutes(app) {\n" + text[start:end] + "}\nregisterRoutes(app);\n\n" + text[end:])
    exp = expected_from(root, Path(__file__).parent / "fixtures" / "vuln_express.expected")
    assert run(root) == exp


def test_python_route_moved_into_a_blueprint_module(tmp_path):
    root = materialize("vuln_flask_llm", tmp_path)
    app = root / "app.py"
    text = app.read_text()
    start = text.index('@app.route("/api/users/<user_id>", methods=["DELETE"])')
    end = text.index('@app.route("/admin/users")')
    (root / "users.py").write_text("from flask import Blueprint\nfrom app import get_db\n\nbp = Blueprint(\"users\", __name__)\n\n\n"
                                   + text[start:end].replace("@app.route", "@bp.route"))
    app.write_text(text[:start] + text[end:])
    exp = expected_from(root, Path(__file__).parent / "fixtures" / "vuln_flask_llm.expected")
    assert run(root) == exp


# --------------------------------------------------------------- safe rewrites
# (fixture, file, exact line in the fixture, replacement lines). The replacement carries no marker, so the
# finding on that line must disappear; markers elsewhere must all still be found.
SAFE_REWRITES = [
    ("vuln_flask_llm", "app.py", '    db.execute(f"DELETE FROM users WHERE id = {user_id}")  # expect: BE001',
     '    db.execute("DELETE FROM users WHERE id = ?", (user_id,))'),
    ("vuln_flask_llm", "app.py", '    os.system("echo " + request.args.get("name", ""))  # expect: BE002',
     '    subprocess.run(["echo", request.args.get("name", "")], check=True)'),
    ("vuln_flask_llm", "app.py", '            {"role": "system", "content": f"You are a helpful assistant. The user asked: {question}"},  # expect: LLM001',
     '            {"role": "system", "content": "You are a helpful assistant."},'),
    ("vuln_flask_llm", "app.py", '    completion = client.chat.completions.create(  # expect: LLM003',
     '    completion = client.chat.completions.create(\n        max_tokens=300,'),
    ("vuln_flask_llm", "app.py", '    exec(script)  # expect: LLM002', '    result = script.strip()'),
    ("vuln_flask_llm", "app.py", 'app.secret_key = "dev-secret-change-me"  # expect: SEC004', 'app.secret_key = os.environ["SECRET_KEY"]'),
    ("vuln_flask_llm", "app.py", 'CORS(app, supports_credentials=True)  # expect: BE012',
     'CORS(app, origins=["https://app.example.com"], supports_credentials=True)'),
    ("vuln_flask_llm", "app.py", '    if user and user.password == request.form["password"]:  # expect: BE014',
     '    if user and bcrypt.checkpw(request.form["password"].encode(), user.password_hash):'),
    ("vuln_flask_llm", "app.py", '    token = "".join(random.choice("abcdef0123456789") for _ in range(16))  # expect: BE015',
     '    token = secrets.token_hex(8)'),
    ("vuln_flask_llm", "app.py", '    app.run(debug=True)  # expect: BE011', '    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")'),
    ("vuln_flask_llm", "app.py", '    resp = requests.get(url, timeout=5)  # expect: BE005',
     '    resp = requests.get("https://api.example.com/lookup", params={"url": url}, timeout=5)'),
    ("vuln_flask_llm", "app.py", '    return redirect(request.args.get("next"))  # expect: BE008', '    return redirect("/dashboard")'),
    ("vuln_flask_llm", "app.py", '    obj = pickle.loads(blob)  # expect: BE004', '    obj = json.loads(blob)'),
    ("vuln_flask_llm", "app.py", 'def verify_token(token):  # expect: AUTH008', 'def verify_token(token):\n    jwt.decode(token, KEY, algorithms=["HS256"])'),
    ("vuln_express", "server.js", 'app.post("/api/notes", async (req, res) => { // expect: AUTH001',
     'app.post("/api/notes", requireAuth, async (req, res) => {'),
    ("vuln_express", "server.js", "  const rows = await db.query(`SELECT * FROM items WHERE name = '${q}'`); // expect: BE001",
     '  const rows = await db.query("SELECT * FROM items WHERE name = $1", [q]);'),
    ("vuln_express", "server.js", '  exec("ping -c 1 " + req.query.host, (err, out) => res.send(out)); // expect: BE002',
     '  execFile("ping", ["-c", "1", String(req.query.host)], (err, out) => res.send(out));'),
    ("vuln_express", "server.js", "  res.send(`<h1>Results for ${q}</h1><p>${rows.length}</p>`); // expect: FE001",
     "  res.json({ q, count: rows.length });"),
    ("vuln_express", "server.js", "app.use(cors({ origin: true, credentials: true })); // expect: BE012",
     'app.use(cors({ origin: "https://app.example.com", credentials: true }));'),
    ("vuln_express", "server.js", "  const r = await fetch(req.query.url); // expect: BE005",
     '  const r = await fetch("https://api.example.com/items?url=" + encodeURIComponent(req.query.url));'),
    ("vuln_express", "server.js", "  } catch (e) {} // expect: QA003", '  } catch (e) {\n    res.status(401).end();\n  }'),
    ("vuln_next_supabase", "app/api/chat/route.ts",
     "      { role: \"system\", content: `You are a support bot. The customer says: ${message}` }, // expect: LLM001",
     '      { role: "system", content: "You are a support bot." },'),
    ("vuln_next_supabase", "app/api/chat/route.ts", "  const completion = await openai.chat.completions.create({ // expect: LLM003",
     "  const completion = await openai.chat.completions.create({\n    max_tokens: 500,"),
    ("vuln_next_supabase", "components/Chat.tsx",
     "const openai = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true }); // expect: FE002, SEC008",
     'const endpoint = "/api/chat";'),
    ("vuln_next_supabase", "components/Chat.tsx",
     '  return <div dangerouslySetInnerHTML={{ __html: html }} onClick={() => send("hi")} />; // expect: FE001',
     '  return <div onClick={() => send("hi")}>{html}</div>;'),
    ("vuln_next_supabase", "components/Chat.tsx", '    localStorage.setItem("isAdmin", "false"); // expect: FE003',
     '    sessionStorage.setItem("draft", message);'),
    ("vuln_agent", "main.py", '    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout  # expect: LLM005',
     '    return subprocess.run(["ls", "-l"], capture_output=True, text=True).stdout'),
    ("vuln_agent", "main.py", 'llm = ChatOpenAI(model="gpt-4o-mini")  # expect: LLM003', 'llm = ChatOpenAI(model="gpt-4o-mini", max_tokens=500)'),
    ("vuln_agent", "main.py", '    while True:  # expect: LLM009', '    for _step in range(5):'),
    ("vuln_agent", "main.py", 'weights = torch.load("weights.pt")  # expect: LLM008', 'weights = torch.load("weights.pt", weights_only=True)'),
    ("vuln_config", "mysite/settings.py", 'DEBUG = True  # expect: BE011', 'DEBUG = os.environ.get("DJANGO_DEBUG") == "1"'),
    ("vuln_config", "mysite/settings.py", 'ALLOWED_HOSTS = ["*"]  # expect: CFG006', 'ALLOWED_HOSTS = ["app.example.com"]'),
    ("vuln_config", "firestore.rules", "      allow read: if true; // expect: AUTH007", "      allow read: if request.auth != null;"),
]

# Adding auth to an id-based write must turn "no auth" into "check ownership" (IDOR), not into silence.
AUTH_THEN_IDOR = ("vuln_flask_llm", "app.py", "def delete_user(user_id):  # expect: AUTH001",
                  "@login_required\ndef delete_user(user_id):  # expect: AUTH003")


@pytest.mark.parametrize("case", SAFE_REWRITES + [AUTH_THEN_IDOR], ids=lambda c: f"{c[0]}:{c[2].strip()[:40]}")
def test_safe_rewrite_removes_exactly_that_finding(tmp_path, case):
    name, rel, old, new = case
    root = materialize(name, tmp_path)
    path = root / rel
    text = path.read_text(encoding="utf-8")
    assert text.count(old + "\n") == 1, "rewrite target not found; fixture changed?"
    path.write_text(text.replace(old + "\n", new + "\n"), encoding="utf-8")
    exp = expected_from(root, Path(__file__).parent / "fixtures" / f"{name}.expected")
    act = run(root)
    assert act == exp, f"missing {sorted(exp - act)}\nunexpected {sorted(act - exp)}"
