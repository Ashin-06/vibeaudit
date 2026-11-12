"""Offline and air-gapped use: data bundles, the offline vulnerability index, and no network in --offline."""
from __future__ import annotations

import hashlib
import io
import json
import socket
import zipfile
from pathlib import Path

import pytest

from helpers import materialize
from vibeaudit import bundle
from vibeaudit.cli import main
from vibeaudit.scanner import Options, scan
from vibeaudit.store import cache_dir


def osv_dump(*docs) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i, d in enumerate(docs):
            z.writestr(f"{d.get('id', i)}.json", json.dumps(d))
    return buf.getvalue()


ADVISORY = {"id": "GHSA-test-0001", "summary": "Session fixation", "database_specific": {"severity": "HIGH"},
            "affected": [{"package": {"ecosystem": "PyPI", "name": "Flask-Login"}, "versions": ["0.6.0", "0.6.1"],
                          "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0.6.0"}, {"fixed": "0.6.3"}]}]}]}
DUMP = osv_dump(
    ADVISORY,
    {"id": "GHSA-ranges-only", "affected": [{"package": {"ecosystem": "PyPI", "name": "x"},
                                             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]},
    {"id": "GHSA-npm", "affected": [{"package": {"ecosystem": "npm", "name": "y"}, "versions": ["1.0.0"]}]},
    {"id": "GHSA-withdrawn", "withdrawn": "2026-01-01", "affected": [{"package": {"ecosystem": "PyPI", "name": "z"}, "versions": ["1"]}]},
)


def make_bundle(tmp_path, monkeypatch) -> Path:
    monkeypatch.setattr(bundle, "_download", lambda url: DUMP if "PyPI" in url else osv_dump())
    path = tmp_path / "bundle.zip"
    bundle.export(path, ["PyPI"], lambda m: None)
    return path


def test_index_keeps_listed_versions_only():
    data, counts = bundle.build_index(DUMP, "PyPI")
    assert counts == {"advisories": 3, "used": 1, "without_versions": 1}  # npm entry skipped, withdrawn not counted
    index = bundle._check_index(data, "PyPI")
    (entry,) = index["packages"]["flask-login"]
    assert entry["id"] == "GHSA-test-0001" and entry["versions"] == ["0.6.0", "0.6.1"]
    assert entry["affected"][0]["ranges"][0]["events"][1] == {"fixed": "0.6.3"}


def test_export_import_and_offline_vulnerabilities(tmp_path, monkeypatch):
    path = make_bundle(tmp_path, monkeypatch)
    with zipfile.ZipFile(path) as z:
        assert set(z.namelist()) == {"manifest.json", "data/pypi_top.txt.gz", "data/npm_top.txt.gz",
                                     "data/retired_models.txt", "osv/PyPI.json.gz"}
    bundle.import_bundle(path, lambda m: None)
    assert (cache_dir() / "osv" / "PyPI.json.gz").is_file()
    app = tmp_path / "app"
    app.mkdir()
    (app / "requirements.txt").write_text("flask-login==0.6.1\nrequests==2.31.0\n")
    res = scan(str(app), Options(offline=True, external="none"))
    (vuln,) = [f for f in res.findings if f.rule_id == "DEP004"]
    assert vuln.line == 1 and "GHSA-test-0001" in vuln.message and "0.6.3" in vuln.message and vuln.severity == "high"
    assert any("imported OSV index (PyPI from" in n for n in res.meta["notes"])
    (app / "requirements.txt").write_text("flask-login==0.6.3\n")
    assert not [f for f in scan(str(app), Options(offline=True, external="none")).findings if f.rule_id == "DEP004"]


def test_offline_scan_without_an_index_says_so(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask-login==0.6.1\n")
    res = scan(str(tmp_path), Options(offline=True, external="none"))
    assert not [f for f in res.findings if f.rule_id == "DEP004"]
    assert any("PyPI packages were not checked" in n for n in res.meta["notes"])


def tampered(path: Path, change) -> Path:
    with zipfile.ZipFile(path) as z:
        members = {n: z.read(n) for n in z.namelist()}
    change(members)
    out = path.with_name("tampered.zip")
    with zipfile.ZipFile(out, "w") as z:
        for n, b in members.items():
            z.writestr(n, b)
    return out


def _manifest(members, edit):
    m = json.loads(members["manifest.json"])
    edit(m)
    members["manifest.json"] = json.dumps(m).encode()


@pytest.mark.parametrize("change", [
    lambda m: m.__setitem__("data/retired_models.txt", b"changed\n" * 10),  # hash mismatch
    lambda m: m.__setitem__("../evil.txt", b"x"),  # not listed, not allowed
    lambda m: (m.__setitem__("osv/../../x.json.gz", b"x"),
               _manifest(m, lambda d: d["files"].__setitem__("osv/../../x.json.gz", {"sha256": hashlib.sha256(b"x").hexdigest()}))),
    lambda m: (m.__setitem__("osv/PyPI.json.gz", b"not gzip"),
               _manifest(m, lambda d: d["files"]["osv/PyPI.json.gz"].__setitem__("sha256", hashlib.sha256(b"not gzip").hexdigest()))),
    lambda m: (m.__setitem__("data/retired_models.txt", b"???\n"),
               _manifest(m, lambda d: d["files"]["data/retired_models.txt"].__setitem__("sha256", hashlib.sha256(b"???\n").hexdigest()))),
    lambda m: m.__setitem__("manifest.json", b"{}"),
    lambda m: m.pop("manifest.json"),
])
def test_bad_bundles_are_rejected_and_install_nothing(tmp_path, monkeypatch, change):
    bad = tampered(make_bundle(tmp_path, monkeypatch), change)
    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(bad, lambda m: None)
    assert not (cache_dir() / "osv").exists() and not (cache_dir() / "data").exists()


def test_not_a_zip(tmp_path):
    (tmp_path / "x.zip").write_text("hello")
    with pytest.raises(bundle.BundleError):
        bundle.import_bundle(tmp_path / "x.zip", lambda m: None)


def test_cli_export_import(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(bundle, "_download", lambda url: DUMP)
    out = tmp_path / "b.zip"
    assert main(["update", "--export", str(out), "--osv", "PyPI"]) == 0
    assert main(["update", "--import", str(out)]) == 0
    assert "imported a bundle made by vibeaudit" in capsys.readouterr().out
    assert main(["update", "--export", str(out), "--osv", "Maven"]) == 1
    assert main(["update", "--osv", "PyPI"]) == 2


@pytest.fixture
def no_network(monkeypatch):
    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args[:2])
        raise OSError("network disabled by the test")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(socket.socket, "connect", lambda self, *a: refuse(*a))
    return attempts


def test_offline_commands_make_no_network_connection(tmp_path, monkeypatch, no_network, capsys):
    path = make_bundle(tmp_path, monkeypatch)  # made before the guard matters: _download is stubbed anyway
    for name in ("vuln_flask_llm", "vuln_next_supabase", "vuln_express"):
        root = materialize(name, tmp_path / name)
        assert main(["scan", str(root), "--offline", "--external", "none", "--fail-on", "none", "-q"]) == 0
        main(["routes", str(root)])
        main(["fix", str(root)])
    assert main(["update", "--import", str(path)]) == 0
    assert main(["scan", str(tmp_path / "vuln_flask_llm"), "--offline", "--external", "none", "--fail-on", "none", "-q"]) == 0
    assert no_network == [], no_network


def test_equal_versions_match():
    """OSV lists Django "3.2" while a requirement pins "3.2.0" (PEP 440: equal); npm stays exact."""
    k = bundle.version_key
    assert k("3.2.0", "PyPI") == k("3.2", "PyPI") == k("v3.2.0.0", "PyPI") and k("3.20", "PyPI") != k("3.2", "PyPI")
    assert k("1.0.0rc1", "PyPI") == k("1rc1", "PyPI") and k("2.0.1", "PyPI") != k("2.0", "PyPI")
    assert k("1.0.0", "npm") != k("1.0", "npm")
