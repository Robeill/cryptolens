"""Structural checks on the held-out evaluation set and its ground truth.

Deliberately *not* a measurement. Step 15 does the measuring; this file only asserts that the
ground truth is internally consistent and describes the samples that are actually on disk, so
that the Day 23 numbers are computed against something well-formed.
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

EVAL_REPO = Path(__file__).resolve().parent.parent / "fixtures" / "eval_repo"
GROUND_TRUTH = EVAL_REPO / "GROUND_TRUTH.json"

PURPOSES = {
    "encryption", "key_establishment", "digital_signature", "hashing",
    "mac", "key_derivation", "random", "unknown",
}


@pytest.fixture(scope="module")
def truth() -> dict:
    return json.loads(GROUND_TRUTH.read_text())


@pytest.fixture(scope="module")
def sources() -> dict[str, list[str]]:
    return {
        str(path.relative_to(EVAL_REPO)): path.read_text().splitlines()
        for path in sorted(EVAL_REPO.rglob("*.py"))
    }


# ------------------------------------------------------------------------ the samples


def test_the_eval_repo_is_separate_from_the_development_fixtures():
    """Detectors were written against `example_repo`. Measuring on it would be circular."""
    assert EVAL_REPO.is_dir()
    assert EVAL_REPO.name == "eval_repo"
    assert (EVAL_REPO.parent / "example_repo").is_dir()


def test_every_sample_is_valid_python(sources):
    for name, lines in sources.items():
        ast.parse("\n".join(lines), filename=name)


def test_the_set_is_large_enough_to_mean_something(sources):
    assert len(sources) >= 12
    assert sum(len(lines) for lines in sources.values()) >= 300


def test_it_contains_crypto_adjacent_negatives(truth):
    """Without these a false-positive rate means nothing."""
    negative_files = {entry["path"] for entry in truth["negatives"]}
    assert "games/cards.py" in negative_files
    assert "web/inventory.py" in negative_files
    assert "web/payloads.py" in negative_files
    assert "web/naming.py" in negative_files


def test_it_contains_a_weak_algorithm_used_for_a_non_security_purpose(truth):
    """MD5 as an ETag: real detection, wrong to grade HIGH. This is the purpose-awareness
    test and it is the one most likely to fail."""
    cache = [e for e in truth["entries"] if e["path"] == "web/caching.py"]
    assert cache
    assert all(e["algorithm"] == "MD5" for e in cache)
    assert all(e["security_relevant"] is False for e in cache)


def test_it_contains_correct_usage_that_should_not_alarm_anyone(truth):
    sessions = [e for e in truth["entries"] if e["path"] == "web/sessions.py"]
    assert sessions
    assert all(e["purpose"] == "random" for e in sessions)


# -------------------------------------------------------------------- the ground truth


def test_the_ground_truth_was_written_before_the_first_run(truth):
    """Recorded as a claim here; the git history is the evidence. `GROUND_TRUTH.json` and the
    samples are committed in the same commit, before any evaluation code exists."""
    assert truth["schema"] == "cryptolens/ground-truth/1"
    assert truth["written"] == "2026-09-13"
    assert any("before the scanner was run" in line for line in truth["method"])


def test_every_entry_points_at_a_line_that_exists(truth, sources):
    for entry in truth["entries"]:
        lines = sources[entry["path"]]
        assert 1 <= entry["line"] <= len(lines), entry
        assert lines[entry["line"] - 1].strip(), entry


def test_every_negative_points_at_a_line_that_exists(truth, sources):
    for negative in truth["negatives"]:
        lines = sources[negative["path"]]
        assert 1 <= negative["line"] <= len(lines), negative


def test_no_line_is_both_an_entry_and_a_negative(truth):
    entries = {(e["path"], e["line"]) for e in truth["entries"]}
    negatives = {(n["path"], n["line"]) for n in truth["negatives"]}
    assert entries & negatives == set()


def test_no_duplicate_entries(truth):
    keys = [(e["path"], e["line"], e["algorithm"]) for e in truth["entries"]]
    assert len(keys) == len(set(keys))


def test_every_purpose_is_one_the_model_knows(truth):
    for entry in truth["entries"]:
        assert entry["purpose"] in PURPOSES, entry


def test_every_entry_names_a_file_that_exists(truth, sources):
    for entry in truth["entries"]:
        assert entry["path"] in sources, entry["path"]


def test_every_negative_gives_a_reason(truth):
    for negative in truth["negatives"]:
        assert negative["why"].strip()


def test_the_counts_in_the_document_match_its_contents(truth):
    counts = truth["counts"]
    assert counts["entries"] == len(truth["entries"])
    assert counts["negatives"] == len(truth["negatives"])
    assert counts["marginal"] == sum(1 for e in truth["entries"] if e.get("marginal"))


def test_the_open_matching_questions_are_recorded_not_resolved(truth):
    """Step 15 has to state the matching rule before running anything. Two cases in this set
    are genuinely ambiguous and are written down rather than decided by whichever answer
    flatters the tool."""
    assert len(truth["open_matching_questions"]) >= 2


def test_marginal_entries_are_a_small_minority(truth):
    marginal = sum(1 for e in truth["entries"] if e.get("marginal"))
    assert 0 < marginal < len(truth["entries"]) // 4
