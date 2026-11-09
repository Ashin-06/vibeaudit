"""Every vulnerable fixture must produce exactly the findings marked in it, and the clean app none."""
import pytest

from helpers import actual, diff_message, expected, materialize
from vibeaudit.scanner import Options, scan

FIXTURES = ["vuln_flask_llm", "vuln_next_supabase", "vuln_express", "vuln_agent", "vuln_config", "clean_app"]


@pytest.mark.parametrize("name", FIXTURES)
def test_fixture_findings_match_markers(name, tmp_path):
    root = materialize(name, tmp_path)
    result = scan(str(root), Options(offline=True, external="none"))
    exp, act = expected(name), actual(result)
    assert act == exp, diff_message(exp, act)


def test_clean_app_has_no_findings(tmp_path):
    root = materialize("clean_app", tmp_path)
    result = scan(str(root), Options(offline=True, external="none"))
    assert result.findings == [], [(f.rule_id, f.file, f.line, f.message) for f in result.findings]
    assert result.meta["routes_found"] >= 5  # the clean app is not clean merely because nothing was parsed


def test_secrets_are_masked_in_findings(tmp_path):
    from helpers import fake_values

    root = materialize("vuln_flask_llm", tmp_path)
    result = scan(str(root), Options(offline=True, external="none"))
    blob = repr([f.to_dict() for f in result.findings])
    for value in fake_values().values():
        assert value not in blob
