"""Stage 3: the user cache (registry, OSV, LLM verdicts), `vibeaudit update` and the feedback store."""
import gzip
import json
import time

from helpers import materialize

from vibeaudit import aiscan, deps, feedback, llm, store, updater
from vibeaudit.cli import main
from vibeaudit.scanner import Options, scan


def _enable_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("VIBEAUDIT_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(store, "ENABLED", True)


# ------------------------------------------------------------------ cache
def test_timed_cache_round_trip_expiry_and_corruption(tmp_path, monkeypatch):
    _enable_cache(monkeypatch, tmp_path)
    c = store.TimedCache("t.json", ttl=60)
    c.put("a", {"x": 1})
    c.save()
    fresh = store.TimedCache("t.json", ttl=60)
    assert fresh.get("a") == {"x": 1}
    assert fresh.get("a", ttl=-1) is None  # older than the ttl asked for
    (tmp_path / "cache" / "t.json").write_text("{not json")
    assert store.TimedCache("t.json", ttl=60).get("a") is None
    monkeypatch.setattr(store, "ENABLED", False)
    off = store.TimedCache("t.json", ttl=60)
    off.put("b", 1)
    off.save()
    assert off.get("b") is None


def test_registry_answers_are_cached_but_errors_are_not(tmp_path, monkeypatch):
    _enable_cache(monkeypatch, tmp_path)
    monkeypatch.setattr(deps.REGISTRY_CACHE, "_data", None)
    answers = {"good-pkg": ("ok", None, ""), "gone-pkg": ("missing", None, ""), "flaky-pkg": ("error", None, "")}
    calls = []

    def lookup(dep):
        calls.append(dep.name)
        return answers[dep.name]

    monkeypatch.setattr(deps, "_registry_lookup", lookup)
    for _ in range(2):
        for name in answers:
            deps.registry_info(deps.Dep(name, "PyPI", "requirements.txt", 1))
    assert sorted(calls) == ["flaky-pkg", "flaky-pkg", "gone-pkg", "good-pkg"]
    # "missing" is trusted for an hour only: a name can be registered at any time
    data = deps.REGISTRY_CACHE._load()
    for key in data:
        data[key][0] -= 2 * 3600
    calls.clear()
    for name in ("good-pkg", "gone-pkg"):
        deps.registry_info(deps.Dep(name, "PyPI", "requirements.txt", 1))
    assert calls == ["gone-pkg"]
    deps.save_caches()
    assert json.loads((tmp_path / "cache" / "registry.json").read_text())


def test_osv_details_are_cached(tmp_path, monkeypatch):
    _enable_cache(monkeypatch, tmp_path)
    monkeypatch.setattr(deps.OSV_CACHE, "_data", None)
    fetched = []

    def get_json(url, data=None):
        if data is not None:
            return 200, {"results": [{"vulns": [{"id": "GHSA-1"}]}]}
        fetched.append(url)
        return 200, {"id": "GHSA-1", "summary": "bad", "affected": [], "details": "x" * 50000}

    monkeypatch.setattr(deps, "_get_json", get_json)
    dep = deps.Dep("flask", "PyPI", "requirements.txt", 1, "0.1")
    for _ in range(2):
        out = deps.osv_lookup([dep])
    assert len(fetched) == 1 and out[("PyPI", "flask", "0.1")][0]["id"] == "GHSA-1"
    assert "details" not in deps.OSV_CACHE.get("GHSA-1")  # only the fields the report uses are kept


def test_llm_verdicts_are_reused(tmp_path, monkeypatch):
    _enable_cache(monkeypatch, tmp_path)
    monkeypatch.setattr(llm.VERDICT_CACHE, "_data", None)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key-not-real")
    root = materialize("vuln_express", tmp_path)

    def fake_complete(self, prompt):
        self.requests += 1
        return json.dumps({"results": [{"id": i, "verdict": "true_positive", "reason": "real"} for i in range(6)]})

    monkeypatch.setattr(llm.Provider, "complete", fake_complete)
    first = scan(str(root), Options(offline=True, external="none", llm="gemini", llm_max_requests=50))
    second = scan(str(root), Options(offline=True, external="none", llm="gemini", llm_max_requests=50))
    assert "used 0 requests" in " ".join(second.meta["notes"]) and "used 0 requests" not in " ".join(first.meta["notes"])
    assert [f.llm_verdict for f in second.findings] == [f.llm_verdict for f in first.findings]
    assert any(f.llm_verdict == "true_positive" for f in second.findings)


# ----------------------------------------------------------------- update
def _top(n=1500):
    return gzip.compress("\n".join(f"pkg{i}" for i in range(n)).encode())


def test_update_validates_before_replacing(tmp_path, monkeypatch):
    _enable_cache(monkeypatch, tmp_path)
    good_models = b"# comment\nold-model-1\nold-model-2\nold-model-3\nold-model-4\nlegacy-*\n"
    files = {"pypi_top.txt.gz": _top(), "npm_top.txt.gz": b"not gzip", "retired_models.txt": good_models}
    logs = []
    failed = updater.update_data(logs.append, fetch=lambda url: files[url.rsplit("/", 1)[1]])
    assert failed == 1 and any("npm_top.txt.gz: downloaded file failed validation" in m for m in logs)
    assert updater.data_bytes("pypi_top.txt.gz") == files["pypi_top.txt.gz"]
    assert len(gzip.decompress(updater.data_bytes("npm_top.txt.gz")).split()) > 1000  # packaged copy kept
    monkeypatch.setattr(aiscan, "_RETIRED", [])
    assert aiscan.retired_models().search('"legacy-v2"') and not aiscan.retired_models().search('"claude-2.1"')


def test_corrupt_refreshed_file_falls_back_to_the_packaged_copy(tmp_path, monkeypatch):
    _enable_cache(monkeypatch, tmp_path)
    (tmp_path / "cache" / "data").mkdir(parents=True)
    (tmp_path / "cache" / "data" / "retired_models.txt").write_text("only-one\n")
    assert b"text-davinci-003" in updater.data_bytes("retired_models.txt")


def test_update_network_failure_and_self_upgrade(tmp_path, monkeypatch):
    _enable_cache(monkeypatch, tmp_path)

    def offline(url):
        raise OSError("no route to host")

    logs = []
    assert updater.update_data(logs.append, fetch=offline) == 3
    assert all("download failed" in m for m in logs)
    ran = []
    assert updater.update_self(logs.append, run=lambda cmd: ran.append(cmd) or 0) == 0
    assert ran[0][1:4] == ["-m", "pip", "install"] and ran[0][-1] == updater.REPO_URL


# --------------------------------------------------------------- feedback
def test_feedback_hides_false_positives_and_survives_line_moves(tmp_path, capsys):
    root = materialize("vuln_flask_llm", tmp_path)
    base = scan(str(root), Options(offline=True, external="none"))
    target = next(f for f in base.findings if f.rule_id == "AUTH001")
    assert main(["feedback", "false-positive", "AUTH001", f"./{target.file}:{target.line}", "--note", "internal only",
                 "--path", str(root)]) == 0
    res = scan(str(root), Options(offline=True, external="none"))
    assert target.fingerprint not in {f.fingerprint for f in res.findings}
    assert len(res.findings) == len(base.findings) - 1 and res.meta["feedback_hidden"] == 1
    # the entry follows the code when lines move
    app = root / target.file
    app.write_text("\n\n" + app.read_text())
    assert target.fingerprint not in {f.fingerprint for f in scan(str(root), Options(offline=True, external="none")).findings}
    # an untrusted repository's feedback file is ignored with --no-config (Options.feedback=False)
    assert len(scan(str(root), Options(offline=True, external="none", feedback=False)).findings) == len(base.findings)
    # the verdict can be changed, and listing shows it
    assert main(["feedback", "confirmed", "AUTH001", f"{target.file}:{target.line + 2}", "--path", str(root)]) == 0
    assert [e["verdict"] for e in feedback.load(root)] == ["confirmed"]
    capsys.readouterr()
    assert main(["feedback", "list", "--path", str(root)]) == 0
    assert "AUTH001: 0 false positive, 1 confirmed" in capsys.readouterr().out


def test_feedback_errors(tmp_path, capsys):
    root = materialize("clean_app", tmp_path)
    assert main(["feedback", "false-positive", "AUTH001", "app.py:1", "--path", str(root)]) == 1
    assert main(["feedback", "false-positive", "AUTH001", "app.py", "--path", str(root)]) == 2
    assert main(["feedback", "list", "--path", str(root)]) == 0
    assert "no feedback recorded" in capsys.readouterr().out
    (root / ".vibeaudit").mkdir()
    (root / ".vibeaudit" / "feedback.json").write_text('{"entries": [1, {"fingerprint": 2}, {"fingerprint": "x", "verdict": "maybe"}]}')
    assert feedback.load(root) == []


def test_shipped_data_files_pass_their_own_validation():
    """Found by running `vibeaudit update` live: npm has a real package called "-", and the all-names check
    rejected the whole npm list, so it could never be refreshed."""
    from importlib import resources

    for name, valid in updater.FILES.items():
        assert valid(resources.files("vibeaudit").joinpath("data", name).read_bytes()), name
    assert not updater.FILES["npm_top.txt.gz"](gzip.compress(b"<script>\n" * 2000))
