"""DEP009: vulnerable transitive dependencies from lockfiles, checked against the offline OSV index (0.8.5)."""
import json
import time

from test_offline import osv_dump
from vibeaudit import bundle, deps
from vibeaudit.files import Project
from vibeaudit.rules import RULES
from vibeaudit.scanner import Options, scan

ADVISORIES = osv_dump(
    {"id": "GHSA-py-0001", "database_specific": {"severity": "HIGH"},
     "affected": [{"package": {"ecosystem": "PyPI", "name": "urllib3"}, "versions": ["1.26.4"],
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.26.5"}]}]}]},
    {"id": "GHSA-py-0002", "affected": [{"package": {"ecosystem": "PyPI", "name": "requests"}, "versions": ["2.0.0"]}]},
)
NPM_ADVISORIES = osv_dump(
    {"id": "GHSA-npm-0001", "database_specific": {"severity": "MODERATE"},
     "affected": [{"package": {"ecosystem": "npm", "name": "minimist"}, "versions": ["1.2.5"],
                   "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.6"}]}]}]},
    {"id": "GHSA-npm-0002", "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "versions": ["4.17.20"]}]},
)


def import_index(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "_download", lambda url: ADVISORIES if "PyPI" in url else NPM_ADVISORIES)
    path = tmp_path / "bundle.zip"
    bundle.export(path, ["PyPI", "npm"], lambda m: None)
    bundle.import_bundle(path, lambda m: None)


def dep009(root):
    res = scan(str(root), Options(offline=True, external="none"))
    return sorted((f.file, f.line, f.message.split(",")[0]) for f in res.findings if f.rule_id == "DEP009")


def test_rule_is_preview():
    assert RULES["DEP009"].preview and RULES["DEP009"].preview_reason


def test_npm_lockfile_transitive_vulnerabilities(tmp_path, monkeypatch):
    import_index(tmp_path, monkeypatch)
    app = tmp_path / "app"
    app.mkdir()
    (app / "package.json").write_text('{"dependencies": {"lodash": "4.17.20", "mkdirp": "0.5.5"}}')
    lock = {"lockfileVersion": 3, "packages": {
        "": {"dependencies": {"lodash": "4.17.20", "mkdirp": "0.5.5"}},
        "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/mkdirp": {"version": "0.5.5"},
        "node_modules/minimist": {"version": "1.2.5"},
        "node_modules/a/node_modules/minimist": {"version": "1.2.5"},
        "node_modules/devtool/node_modules/lodash": {"version": "4.17.20", "dev": True}}}
    (app / "package-lock.json").write_text(json.dumps(lock, indent=2))
    # lodash is direct (DEP004's), the nested minimist copy is the same version, the dev-only copy is skipped
    assert dep009(app) == [("package-lock.json", 16, "minimist 1.2.5")]


def test_python_lockfiles(tmp_path, monkeypatch):
    import_index(tmp_path, monkeypatch)
    app = tmp_path / "app"
    app.mkdir()
    (app / "pyproject.toml").write_text('[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "2.0.0"\n')
    (app / "poetry.lock").write_text(
        '[[package]]\nname = "requests"\nversion = "2.0.0"\ncategory = "main"\n\n'
        '[[package]]\nname = "urllib3"\nversion = "1.26.4"\ncategory = "main"\n\n'      # 6
        '[[package]]\nname = "urllib3"\nversion = "1.26.4"\ncategory = "dev"\n')
    assert dep009(app) == [("poetry.lock", 6, "urllib3 1.26.4")]
    msg = [f.message for f in scan(str(app), Options(offline=True, external="none")).findings if f.rule_id == "DEP009"][0]
    assert "1.26.5 fixes them" in msg


def test_lockfile_formats_parse(tmp_path):
    pnpm = ("lockfileVersion: '6.0'\n\npackages:\n\n  /minimist@1.2.5:\n    resolution: {integrity: x}\n    dev: false\n\n"
            "  /@scope/pkg@2.0.0(react@18.0.0):\n    resolution: {integrity: y}\n    dev: true\n")
    assert deps._lock_entries("pnpm-lock.yaml", pnpm) == [("minimist", "1.2.5", 5)]
    yarn = ('"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.2.0"\n  resolved "x"\n\n'
            'app@workspace:.:\n  version: 0.0.0-use.local\n\nminimist@^1.2.0:\n  version "1.2.5"\n')
    assert deps._lock_entries("yarn.lock", yarn) == [("@babel/core", "7.2.0", 1), ("minimist", "1.2.5", 8)]
    bun = '{\n  "packages": {\n    "minimist": ["minimist@1.2.5", "", {}, "sha"],\n    "@a/b": ["@a/b@1.0.0", "", {}, "s"],\n  }\n}\n'
    assert deps._lock_entries("bun.lock", bun) == [("minimist", "1.2.5", 3), ("@a/b", "1.0.0", 4)]
    pipfile = json.dumps({"default": {"urllib3": {"version": "==1.26.4"}}, "develop": {"pytest": {"version": "==7.0.0"}}}, indent=4)
    assert deps._lock_entries("Pipfile.lock", pipfile) == [("urllib3", "1.26.4", 3)]


def test_lockfile_parsing_is_linear(tmp_path):
    lock = {"lockfileVersion": 3, "packages": {f"node_modules/p{i}": {"version": "1.0.0"} for i in range(20000)}}
    (tmp_path / "package.json").write_text('{"dependencies": {}}')
    (tmp_path / "package-lock.json").write_text(json.dumps(lock, indent=2))
    (tmp_path / "yarn.lock").write_text("a@^1:\n" * 20000 + '"' * 20000)
    start = time.time()
    found = deps.locked_packages(Project(tmp_path), [])
    assert len(found) == 20000 and time.time() - start < 10
    start = time.time()
    deps._lock_entries("yarn.lock", (tmp_path / "yarn.lock").read_text())
    deps._lock_entries("pnpm-lock.yaml", "packages:\n" + "  /a@1:\n" * 20000)
    assert time.time() - start < 10


def test_online_path_queries_transitive_packages_separately(tmp_path, monkeypatch):
    (tmp_path / "package.json").write_text('{"dependencies": {"lodash": "4.17.20"}}')
    (tmp_path / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/lodash": {"version": "4.17.20"}, "node_modules/minimist": {"version": "1.2.5"}}}, indent=2))
    calls = []

    def lookup(ds):
        calls.append(sorted(d.name for d in ds))
        if any(d.name == "minimist" for d in ds):
            raise ConnectionError("down")
        return {}
    monkeypatch.setattr(deps, "registry_info", lambda d: ("ok", None, ""))
    monkeypatch.setattr(deps, "osv_lookup", lookup)
    res = scan(str(tmp_path), Options(offline=False, external="none"))
    assert calls == [["lodash"], ["minimist"]]
    assert any("transitive dependencies failed" in n for n in res.meta["notes"])
