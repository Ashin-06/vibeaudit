"""Reliability rules (REL001-REL006)."""
from vibeaudit.scanner import Options, scan


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


def _rules(tmp_path):
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    return sorted((f.file, f.line, f.rule_id) for f in res.findings if f.rule_id.startswith("REL"))


def test_timeouts_and_blocking_calls(tmp_path):
    write(tmp_path, "a.py",
          "import time, requests, httpx\nfrom urllib.request import urlopen\n\n"
          "def sync_call():\n    requests.get('https://api.example.com')\n    requests.get('https://api.example.com', timeout=5)\n"
          "    httpx.get('https://api.example.com')\n    urlopen('https://example.com')\n    requests.post(url, **opts)\n\n"
          "async def handler():\n    time.sleep(1)\n    r = requests.get('https://x', timeout=3)\n    await asyncio.sleep(1)\n")
    assert _rules(tmp_path) == [("a.py", 5, "REL001"), ("a.py", 8, "REL001"), ("a.py", 12, "REL002"), ("a.py", 13, "REL002")]


def test_uploads(tmp_path):
    write(tmp_path, "api.py",
          "from fastapi import UploadFile\n\n@app.post('/up')\nasync def up(file: UploadFile):\n    data = await file.read()\n    return {}\n\n"
          "@app.post('/up2')\nasync def up2(file: UploadFile):\n    if file.size > MAX_BYTES:\n        raise ValueError()\n    data = await file.read()\n    return {}\n")
    write(tmp_path, "server.js", "const upload = multer({ dest: 'uploads/' });\nconst safe = multer({ dest: 'u/', limits: { fileSize: 1e6 } });\n")
    assert _rules(tmp_path) == [("api.py", 4, "REL004"), ("server.js", 1, "REL004")]


def test_flask_upload_without_max_content_length(tmp_path):
    write(tmp_path, "app.py", "@app.post('/up')\ndef up():\n    f = request.files['file']\n    return ''\n")
    assert _rules(tmp_path) == [("app.py", 3, "REL004")]
    write(tmp_path, "config.py", "MAX_CONTENT_LENGTH = 16 * 1024 * 1024\n")
    assert _rules(tmp_path) == []


def test_webhook_idempotency(tmp_path):
    write(tmp_path, "app.py",
          "@app.post('/webhooks/stripe')\ndef hook():\n    event = stripe.Webhook.construct_event(request.data, sig, secret)\n"
          "    db.orders.update(paid=True)\n    return ''\n\n"
          "@app.post('/webhooks/github')\ndef gh():\n    verify_signature(request)\n    if Event.exists(event_id=request.json['id']):\n"
          "        return ''\n    db.events.insert(request.json)\n    return ''\n")
    assert _rules(tmp_path) == [("app.py", 2, "REL003")]


def test_in_memory_state_on_serverless(tmp_path):
    write(tmp_path, "package.json", '{"dependencies": {"next": "14.0.0"}}')
    write(tmp_path, "app/api/chat/route.ts", "const rateLimits = new Map<string, number>();\nconst MODEL = 'x';\n"
                                             "export async function POST() { return Response.json({}); }\n")
    write(tmp_path, "lib/cache.ts", "const cache = new Map();\n")  # not a route file
    assert _rules(tmp_path) == [("app/api/chat/route.ts", 1, "REL005")]


def test_health_check_needs_a_deployment_and_routes(tmp_path):
    routes = "".join(f"@app.get('/r{i}')\ndef r{i}():\n    return ''\n\n" for i in range(5))
    write(tmp_path, "app.py", routes)
    assert _rules(tmp_path) == []  # not deployed
    write(tmp_path, ".devcontainer/Dockerfile", "FROM python:3.12\n")
    assert _rules(tmp_path) == []  # a dev container is not a deployment
    write(tmp_path, "Dockerfile", "FROM python:3.12\n")
    assert _rules(tmp_path) == [("Dockerfile", 1, "REL006")]
    write(tmp_path, "app.py", routes + "@app.get('/healthz')\ndef healthz():\n    return ''\n")
    assert _rules(tmp_path) == []
