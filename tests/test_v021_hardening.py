"""Tests for v0.21.0 hardening and shipping fixes."""
from __future__ import annotations

import http.client
from importlib import resources
import pytest

from vibeaudit import bundle, cli, config, deps, exploit, llm, probe, review, updater
from vibeaudit.store import loads_toml, validate_http_url


def test_py_typed_marker_is_packaged():
    assert resources.files("vibeaudit").joinpath("py.typed").is_file()


@pytest.mark.parametrize("bad_url", [
    "",
    "file:///etc/passwd",
    "ftp://example.com/data.zip",
    "data:text/plain,hello",
    "http://example.com/api",
    "https://",
    "/relative/path",
])
def test_validate_http_url_rejects_unsafe_schemes(bad_url):
    with pytest.raises(ValueError):
        validate_http_url(bad_url)
    with pytest.raises(ValueError):
        validate_http_url(bad_url, allow_local_http=True)


def test_validate_http_url_allows_https_and_local_http_when_opted_in():
    assert validate_http_url("https://api.osv.dev/v1/querybatch").startswith("https://")
    with pytest.raises(ValueError):
        validate_http_url("http://127.0.0.1:11434/v1")
    for local in ("http://127.0.0.1:11434/v1", "http://localhost:8080/v1", "http://[::1]:8000/v1"):
        assert validate_http_url(local, allow_local_http=True) == local


def test_network_callers_reject_file_and_ftp_urls():
    with pytest.raises(bundle.BundleError):
        bundle._download("file:///etc/passwd")
    with pytest.raises(ValueError):
        updater._download("file:///etc/passwd")
    with pytest.raises(ValueError):
        deps._get_json("file:///etc/passwd")
    with pytest.raises(review.ReviewError):
        review._request("GET", "file:///etc/passwd", "tok")
    with pytest.raises(llm.LLMError):
        llm._post("file:///etc/passwd", {}, {})
    with pytest.raises(llm.LLMError):
        llm._post("http://remote-host.example/v1/chat", {}, {})


def test_probe_target_warns_loudly_when_tls_verification_disabled(capsys):
    local_https = probe.Target("https://127.0.0.1:8443", own=False, rate=10.0, max_requests=5)
    err = capsys.readouterr().err
    assert local_https.tls_verified is False
    assert local_https.tls_warning is not None
    assert "TLS certificate verification is DISABLED" in err

    insecure_own = probe.Target("https://example.com", own=True, rate=10.0, max_requests=5, insecure=True)
    err2 = capsys.readouterr().err
    assert insecure_own.tls_verified is False
    assert insecure_own.tls_warning is not None
    assert "TLS certificate verification is DISABLED" in err2

    verified = probe.Target("https://example.com", own=True, rate=10.0, max_requests=5, insecure=False)
    err3 = capsys.readouterr().err
    assert verified.tls_verified is True
    assert verified.tls_warning is None
    assert err3 == ""

    plain = probe.Target("http://127.0.0.1:8000", own=False, rate=10.0, max_requests=5)
    err4 = capsys.readouterr().err
    assert plain.tls_verified is True
    assert plain.tls_warning is None
    assert err4 == ""


def test_exploit_send_poc_warns_loudly_on_https_loopback(monkeypatch, capsys):
    class _FakeResp:
        status = 200

        def read(self, _n):
            return b"ok"

        def getheader(self, _name, default=""):
            return default

    class _FakeConn:
        def __init__(self, *_a, **_kw):
            pass

        def request(self, *_a, **_kw):
            pass

        def getresponse(self):
            return _FakeResp()

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPSConnection", _FakeConn)
    poc = {
        "url": "https://127.0.0.1:8443/admin",
        "method": "GET",
        "headers": {},
        "body": "",
        "expected_safe": "401/403",
        "oracle": "HTTP 200",
        "curl": "curl https://127.0.0.1:8443/admin",
        "finding": {"rule_id": "AUTH001", "title": "Missing auth", "file": "app.py", "line": 1},
    }
    res = exploit.send_poc(poc)
    err = capsys.readouterr().err
    assert res["tls_verified"] is False
    assert "TLS certificate verification is DISABLED" in res["tls_warning"]
    assert "TLS certificate verification is DISABLED" in err
    assert "WARNING:" in exploit.render_text(res)


def test_fail_on_partial_flag_and_config_key(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "huge.py").write_text("a = 1\n" * 500, encoding="utf-8")

    # Complete scan passes with --fail-on-partial
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--fail-on", "none", "--fail-on-partial", "-q"]) == 0

    # Forcing size_limit triggers partial coverage and fails with exit code 1
    assert cli.main([
        "scan", str(tmp_path), "--offline", "--external", "none",
        "--fail-on", "none", "--max-file-size", "200", "--fail-on-partial", "-q",
    ]) == 1

    # Config key fail-on-partial works identically
    (tmp_path / ".vibeaudit.toml").write_text("fail-on-partial = true\nmax-file-size = 200\n", encoding="utf-8")
    assert cli.main(["scan", str(tmp_path), "--offline", "--external", "none", "--fail-on", "none", "-q"]) == 1


def test_scan_timeout_marks_partial_coverage(tmp_path, monkeypatch):
    import time

    (tmp_path / "app.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    report_path = tmp_path / "out.json"
    ticks = iter([100.0, 200.0, 200.0, 200.0, 200.0])
    monkeypatch.setattr(time, "perf_counter", lambda: next(ticks, 200.0))
    rc = cli.main([
        "scan", str(tmp_path), "--offline", "--external", "none",
        "--fail-on", "none", "--scan-timeout", "5", "--fail-on-partial",
        "-r", f"json:{report_path}", "-q",
    ])
    assert rc == 1
    import json

    data = json.loads(report_path.read_text(encoding="utf-8"))
    cov = data["meta"]["coverage"]
    assert cov["overall_status"] == "partial"
    assert cov["scan_timed_out"] is True
    assert any("scan_timeout" in r for r in cov["incomplete_reasons"])
    assert cli.main(["scan", str(tmp_path), "--scan-timeout", "0"]) == 2


def test_config_parser_adversarial_inputs(tmp_path):
    bad_toml = [
        "",
        "[",
        "exclude = [",
        "fail-on-partial = 'yes'",
        "scan-timeout = 0",
        "unknown-flag = 1",
        "deep = " + "[" * 300 + "1" + "]" * 300,
    ]
    for idx, body in enumerate(bad_toml):
        sub = tmp_path / f"t{idx}"
        sub.mkdir()
        (sub / ".vibeaudit.toml").write_text(body, encoding="utf-8")
        try:
            config.load(sub)
        except (config.ConfigError, ValueError):
            pass
    with pytest.raises(ValueError):
        loads_toml("[broken")
    with pytest.raises(config.ConfigError):
        config.parse({"scan_timeout": -1}, "test")
    with pytest.raises(config.ConfigError):
        config.parse({"fail_on_partial": "true"}, "test")
