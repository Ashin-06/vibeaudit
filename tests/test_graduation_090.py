"""Rules that left preview in 0.9.0: each had at least 5 held-out findings at 90% or more after a release in preview."""
from vibeaudit.rules import RULES

GRADUATED = ("CFG010", "CFG016", "DATA012", "QA011")  # UI014 went back to preview in 0.9.2


def test_graduated_rules_are_stable():
    assert not any(RULES[r].preview for r in GRADUATED)


def test_data013_stays_in_preview_with_its_measured_reason():
    assert RULES["DATA013"].preview and "75%" in RULES["DATA013"].preview_reason


def test_demotions_in_092_keep_their_measured_reasons():
    assert RULES["UI014"].preview and "6 of 7" in RULES["UI014"].preview_reason
    a = RULES["AUTH001"]
    assert a.preview and a.gates_in_preview and "14 of 16" in a.preview_reason
