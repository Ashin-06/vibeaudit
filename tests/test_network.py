"""Registry and OSV lookups under every network failure mode, with a stubbed transport.

The rule: a failed lookup is a note in the report, never a crash, never a hang, and never a claim that
a package does not exist.
"""
import io
import json
import socket
import time
import urllib.error

import pytest

from vibeaudit import deps
from vibeaudit.scanner import Options, scan


class Resp:
    def __init__(self, body, status=200):
        self.body = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.status = status

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def http_error(code, retry_after=None):
    headers = {"Retry-After": str(retry_after)} if retry_after is not None else {}
    import email.message

    msg = email.message.Message()
    for k, v in headers.items():
        msg[k] = v
    return urllib.error.HTTPError("https://x", code, "err", msg, io.BytesIO(b""))


@pytest.fixture
def transport(monkeypatch):
    """Replace urlopen; `plan` maps a URL substring to a list of outcomes consumed in order."""
    calls = []
    plan = {}
    sleeps = []

    def fake_urlopen(req, timeout=None):
        url = req.full_url
        calls.append(url)
        for key, outcomes in plan.items():
            if key in url:
                outcome = outcomes.pop(0) if len(outcomes) > 1 else outcomes[0]
                if isinstance(outcome, BaseException):
                    raise outcome
                return outcome
        raise AssertionError("unplanned request " + url)

    monkeypatch.setattr(deps.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setattr(deps.time, "sleep", lambda s: sleeps.append(s))
    deps.BREAKER.reset()
    return plan, calls, sleeps


def _dep(name="some-unknown-pkg", eco="PyPI"):
    return deps.Dep(name, eco, "requirements.txt", 1)


FAILURES = {
    "timeout": socket.timeout("timed out"),
    "dns": urllib.error.URLError(socket.gaierror("name resolution failed")),
    "reset": ConnectionResetError("reset by peer"),
    "server_error": http_error(500),
    "unavailable": http_error(503),
    "rate_limited": http_error(429, retry_after=1),
    "forbidden": http_error(403),
    "html_page": Resp(b"<html>maintenance</html>"),
    "truncated_json": Resp(b'{"releases": {"1.0": [{"upload_'),
    "json_list": Resp([1, 2, 3]),
    "json_null": Resp(b"null"),
    "empty_body": Resp(b""),
}


@pytest.mark.parametrize("mode", sorted(FAILURES))
@pytest.mark.parametrize("eco", ["PyPI", "npm"])
def test_failures_are_errors_never_missing(transport, mode, eco):
    plan, calls, _ = transport
    plan["pypi.org" if eco == "PyPI" else "registry.npmjs.org"] = [FAILURES[mode]]
    status, first, _note = deps.registry_info(_dep(eco=eco))
    assert status == "error" and first is None
    assert 1 <= len(calls) <= deps.MAX_ATTEMPTS


@pytest.mark.parametrize("code", [404, 410])
def test_only_404_and_410_mean_missing(transport, code):
    plan, calls, _ = transport
    plan["pypi.org"] = [http_error(code)]
    assert deps.registry_info(_dep())[0] == "missing"
    assert len(calls) == 1  # a definite answer is not retried


def test_rate_limit_is_retried_honouring_retry_after_with_a_cap(transport):
    plan, calls, sleeps = transport
    ok = Resp({"releases": {"1.0": [{"upload_time_iso_8601": "2015-01-01T00:00:00Z"}]}})
    plan["pypi.org"] = [http_error(429, retry_after=3), http_error(429, retry_after=9999), ok]
    status, first, _ = deps.registry_info(_dep())
    assert status == "ok" and first.year == 2015
    assert sleeps == [3.0, deps.MAX_RETRY_AFTER]


def test_transient_error_then_success(transport):
    plan, _calls, _ = transport
    plan["registry.npmjs.org"] = [socket.timeout(), Resp({"dist-tags": {"latest": "1.0.0"}, "time": {"created": "2020-01-01T00:00:00Z"}})]
    assert deps.registry_info(_dep(eco="npm"))[0] == "ok"


def test_malformed_but_valid_json_documents_do_not_crash(transport):
    plan, _calls, _ = transport
    plan["pypi.org"] = [Resp({"releases": {"1.0": "nope", "2.0": [5, None, {"upload_time_iso_8601": 7}]}})]
    assert deps.registry_info(_dep()) == ("ok", None, "")
    plan.clear()
    plan["registry.npmjs.org"] = [Resp({"dist-tags": [], "time": "x", "description": None})]
    assert deps.registry_info(_dep(eco="npm"))[0] == "ok"


def test_outage_trips_the_breaker_and_finishes_fast(tmp_path, transport):
    plan, calls, _ = transport
    plan["pypi.org"] = [socket.timeout()]
    plan["api.osv.dev"] = [socket.timeout()]
    (tmp_path / "requirements.txt").write_text("".join(f"unknown-pkg-{i}==1.0\n" for i in range(60)))
    start = time.monotonic()
    res = scan(str(tmp_path), Options(external="none"))
    assert time.monotonic() - start < 20
    assert not [f for f in res.findings if f.rule_id in ("DEP001", "DEP003", "DEP004")]
    assert any("registry lookups failed" in n for n in res.meta["notes"])
    assert any("OSV" in n for n in res.meta["notes"])
    pypi_calls = [c for c in calls if "pypi.org" in c]
    assert len(pypi_calls) < 60, "the breaker should stop calling a host that is down"


def test_osv_partial_and_malformed_answers(transport):
    plan, _calls, _ = transport
    pinned = [deps.Dep("a", "PyPI", "r", 1, "1.0"), deps.Dep("b", "PyPI", "r", 2, "1.0")]
    plan["querybatch"] = [Resp({"results": [{"vulns": [{"id": "GHSA-1"}]}]})]  # one result for two queries
    with pytest.raises(ConnectionError):
        deps.osv_lookup(pinned)
    plan.clear()
    plan["querybatch"] = [Resp({"results": [{"vulns": "x"}, {"vulns": [{"id": "GHSA-2"}, 5, {"no": "id"}]}]})]
    plan["/v1/vulns/"] = [socket.timeout()]
    out = deps.osv_lookup(pinned)
    assert out == {("PyPI", "b", "1.0"): [{"id": "GHSA-2"}]}  # details failed, the id is still reported


def test_osv_outage_is_a_note(tmp_path, transport):
    plan, _calls, _ = transport
    plan["pypi.org"] = [Resp({"releases": {"1.0": [{"upload_time_iso_8601": "2015-01-01T00:00:00Z"}]}})]
    plan["querybatch"] = [http_error(503)]
    (tmp_path / "requirements.txt").write_text("unknown-pkg==1.0\n")
    res = scan(str(tmp_path), Options(external="none"))
    assert res.findings == []
    assert any("OSV vulnerability lookup failed" in n for n in res.meta["notes"])
