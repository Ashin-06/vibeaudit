"""Rules that left preview in 0.9.0: each had at least 5 held-out findings at 90% or more after a release in preview."""
from vibeaudit.rules import RULES

GRADUATED = ("CFG010", "CFG016", "QA011")  # UI014 went back to preview in 0.9.2, DATA012 after 0.10.0


def test_graduated_rules_are_stable():
    assert not any(RULES[r].preview for r in GRADUATED)


def test_data013_stays_in_preview_with_its_measured_reason():
    assert RULES["DATA013"].preview and "75%" in RULES["DATA013"].preview_reason


def test_demotions_in_092_and_the_regraduation():
    assert RULES["UI014"].preview and "6 of 7" in RULES["UI014"].preview_reason
    assert not RULES["AUTH001"].preview  # back to stable: dev-only server actions are no longer reported


def test_demotions_after_the_new_language_held_out_repositories():
    assert not RULES["QA001"].preview  # stable again: tests in any language count (6/6 held-out)
    for rid, measured in (("CFG002", "5 of 6"), ("QA007", "6 of 7"), ("DATA012", "19 of 28"),
                          ("UI009", "4 of 5")):
        assert RULES[rid].preview and measured in RULES[rid].preview_reason
        assert not RULES[rid].gates_in_preview  # none is a severe class
