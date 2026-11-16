"""Router prefixes: FastAPI include_router / APIRouter(prefix), Flask blueprints, Express app.use."""
from pathlib import Path

from vibeaudit.model import join_path
from vibeaudit.scanner import Options, scan

SEEDED = Path(__file__).parent.parent / "benchmark" / "seeded" / "prefix_app"


def write(root, files):
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text)
    return root


def routes(root):
    res = scan(str(root), Options(offline=True, external="none"))
    assert res.meta.get("internal_errors", []) == []
    return {(tuple(r.methods), r.path): r.prefix_resolved for r in res.routes}


def test_join_path():
    assert join_path("/api/", "/users") == "/api/users" and join_path("/api", "") == "/api" and join_path("", "/x") == "/x"


def test_fastapi_nested_routers(tmp_path):
    root = write(tmp_path, {
        "app/__init__.py": "", "app/routers/__init__.py": "",
        "app/routers/items.py": 'from fastapi import APIRouter\nrouter = APIRouter(prefix="/items")\n'
                                '@router.get("/{item_id}")\ndef get_item(item_id: int): return {}\n',
        "app/main.py": 'from fastapi import FastAPI, APIRouter\nfrom app.routers import items\napi = APIRouter()\n'
                       'api.include_router(items.router, prefix="/v1")\napp = FastAPI()\napp.include_router(api, prefix="/api")\n'
                       '@app.get("/health")\ndef health(): return {}\n'})
    assert routes(root) == {(("GET",), "/api/v1/items/{item_id}"): True, (("GET",), "/health"): True}


def test_flask_registration_prefix_replaces_the_blueprints(tmp_path):
    root = write(tmp_path, {
        "app/admin.py": 'from flask import Blueprint\nbp = Blueprint("admin", __name__, url_prefix="/admin")\n'
                        '@bp.route("/users", methods=["POST"])\ndef users(): return "x"\n',
        "app/__init__.py": 'from flask import Flask\nfrom .admin import bp\napp = Flask(__name__)\n'
                           'app.register_blueprint(bp, url_prefix="/backoffice")\n'})
    assert routes(root) == {(("POST",), "/backoffice/users"): True}


def test_unresolvable_prefixes_keep_their_paths(tmp_path):
    root = write(tmp_path, {
        "main.py": 'from fastapi import FastAPI, APIRouter\nfrom config import settings\nrouter = APIRouter()\n'
                   '@router.get("/me")\ndef me(): return {}\napp = FastAPI()\napp.include_router(router, prefix=settings.API_PREFIX)\n',
        "config.py": "class S:\n    API_PREFIX = '/api'\nsettings = S()\n"})
    assert routes(root) == {(("GET",), "/me"): False}


def test_express_nested_routers_and_the_contract_check():
    got = routes(SEEDED)
    assert got == {(("GET",), "/api/notes"): True, (("POST",), "/api/notes"): True}
    res = scan(str(SEEDED), Options(offline=True, external="none", include_preview=True, min_severity="low"))
    assert sorted((f.file, f.line) for f in res.findings if f.rule_id.startswith("API")) == [("web/notes.js", 3)]
