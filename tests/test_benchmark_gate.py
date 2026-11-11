"""The benchmark CI gate (tools/benchmark.py check) on hand-made results, without fetching the corpus."""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import benchmark  # noqa: E402


def _results(by_repo, lost_tp=0, recall=1.0):
    rule = {"by_repo": by_repo, "lost_tp": lost_tp, "needs_review": sum(v[2] for v in by_repo.values()),
            "seeded_recall": recall, "seeded_found": 1, "seeded_expected": 1}
    return {"repos": {name: {} for name in by_repo}, "rules": {"BE001": rule}}


def _gate(tmp_path, monkeypatch, results):
    base = tmp_path / "baseline.json"
    base.write_text(json.dumps({"rules": {"BE001": {"precision": 0.75, "seeded_recall": 1.0,
                                                    "by_repo": {"a": [3, 1], "b": [0, 3]}}}}))
    monkeypatch.setattr(benchmark, "BASELINE", base)
    return benchmark.check(results)


def test_gate_passes_unchanged_and_fails_on_new_noise_lost_tps_and_recall(tmp_path, monkeypatch):
    assert _gate(tmp_path, monkeypatch, _results({"a": [3, 1, 0], "b": [0, 3, 0]})) == []
    assert "need review" in _gate(tmp_path, monkeypatch, _results({"a": [3, 1, 1], "b": [0, 3, 0]}))[0]
    assert "no longer reported" in _gate(tmp_path, monkeypatch, _results({"a": [2, 1, 0], "b": [0, 3, 0]}, lost_tp=1))[-1]
    assert "seeded recall" in _gate(tmp_path, monkeypatch, _results({"a": [3, 1, 0], "b": [0, 3, 0]}, recall=0.0))[0]


def test_a_repository_that_could_not_be_fetched_does_not_fail_the_gate(tmp_path, monkeypatch):
    # only "a" was scanned: its baseline precision (3 of 4) is the bar, not the corpus-wide 3 of 7
    assert _gate(tmp_path, monkeypatch, _results({"a": [3, 1, 0]})) == []
    assert _gate(tmp_path, monkeypatch, _results({})) == []


def test_seeded_manifests_pin_no_versions():
    # A pinned version in a seeded sample enters GitHub's dependency graph: Dependabot then opens alerts and
    # security-update jobs for an app that is never installed (and fails on its made-up package index).
    import re

    seeded = Path(__file__).resolve().parent.parent / "benchmark" / "seeded"
    for path in list(seeded.rglob("requirements*.txt")) + list(seeded.rglob("package.json")):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"==\s*\d|\"[~^]?\d+\.\d+", text), f"{path} pins a version"
