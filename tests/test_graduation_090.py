"""Rules that left preview in 0.9.0: each had at least 5 held-out findings at 90% or more after a release in preview."""
from vibeaudit.rules import RULES

GRADUATED = ("CFG010", "CFG016", "DATA012", "QA011", "UI014")


def test_graduated_rules_are_stable():
    assert not any(RULES[r].preview for r in GRADUATED)


def test_data013_stays_in_preview_with_its_measured_reason():
    assert RULES["DATA013"].preview and "75%" in RULES["DATA013"].preview_reason
