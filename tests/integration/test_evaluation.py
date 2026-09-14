"""The evaluator runs, and its scoring arithmetic is right.

Not a measurement -- `EVALUATION.md` holds the numbers. This only guards the machinery
that produces them, because a scoring bug is indistinguishable from a tool result.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import evaluate


@pytest.fixture(scope="module")
def report() -> dict:
    return evaluate.evaluate("cryptolens")


def test_the_protocol_is_committed_and_the_scorer_implements_it():
    assert (ROOT / "tools" / "PROTOCOL.md").is_file()


def test_the_evaluator_runs_as_a_script():
    completed = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "evaluate.py"), "--tool", "cryptolens"],
        capture_output=True, text=True, check=False, timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["tool"] == "cryptolens"


# ------------------------------------------------------------------------ the arithmetic


def test_precision_and_recall_are_computed_the_usual_way():
    outcome = evaluate.Score(true_positives=[1, 2, 3], false_positives=[4], false_negatives=[5])
    assert outcome.precision() == 0.75
    assert outcome.recall() == 0.75
    assert outcome.f1() == 0.75


def test_an_empty_score_does_not_divide_by_zero():
    outcome = evaluate.Score()
    assert outcome.precision() == 0.0
    assert outcome.recall() == 0.0
    assert outcome.f1() == 0.0


def test_every_fact_is_matched_at_most_once():
    """Two identical findings on one line must not both claim the same ground-truth fact."""
    fact = evaluate.Fact("a.py", 1, "MD5", "hashing")
    twice = [
        evaluate.Observation("a.py", 1, "MD5", "hashing", 1.0, "high"),
        evaluate.Observation("a.py", 1, "MD5", "hashing", 1.0, "high"),
    ]
    outcome = evaluate.score(twice, [fact])
    assert len(outcome.true_positives) == 1
    assert len(outcome.false_positives) == 1


def test_a_weakness_entry_yields_two_facts():
    facts, _ = evaluate.load_facts()
    at_line = [f for f in facts if f.path == "transport/tls.py" and f.line == 19]
    assert {f.kind for f in at_line} == {"algorithm", "weakness"}


def test_marginal_entries_can_be_excluded():
    everything, _ = evaluate.load_facts(include_marginal=True)
    trimmed, _ = evaluate.load_facts(include_marginal=False)
    assert len(trimmed) < len(everything)
    assert all(not f.marginal for f in trimmed)


# --------------------------------------------------------- the Bandit adapter's fairness


def test_bandit_algorithms_are_matched_on_whole_tokens_not_substrings():
    """`modes` contains `des`, which scored Bandit's ECB finding as DES and cost it a true
    positive it had earned."""
    ecb = {
        "test_id": "B305",
        "issue_text": "Use of insecure cipher mode cryptography.hazmat.primitives.ciphers.modes.ECB.",
    }
    assert evaluate._bandit_algorithm(ecb) is None


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("Use of weak MD5 hash for security.", "MD5"),
        ("Use of weak SHA1 hash for security.", "SHA-1"),
        ("Use of insecure cipher ...algorithms.TripleDES. Replace with AES.", "3DES"),
        ("Use of insecure cipher ...algorithms.ARC4.", "RC4"),
        ("RSA key sizes below 2048 bits are considered breakable.", "RSA"),
    ],
)
def test_bandit_algorithm_extraction(text, expected):
    assert evaluate._bandit_algorithm({"test_id": "B324", "issue_text": text}) == expected


def test_bandit_is_scored_on_its_own_remit_as_well_as_the_full_truth():
    facts, _ = evaluate.load_facts()
    in_remit = [f for f in facts if evaluate._within_bandit_remit(f)]
    assert in_remit
    assert len(in_remit) < len(facts), "the remit must be a strict subset, or the split is a lie"
    assert all(f.weakness in evaluate.BANDIT_REMIT_WEAKNESSES for f in in_remit)


# ----------------------------------------------------------- the results the report cites


def test_the_headline_numbers_are_reproducible(report):
    """If these drift, `EVALUATION.md` is stale and must be regenerated."""
    call_site = report["all_entries"]["call_site"]
    assert call_site["precision"] == pytest.approx(0.836, abs=0.01)
    assert call_site["recall"] == pytest.approx(0.773, abs=0.01)
    assert report["all_entries"]["file_level"]["f1"] == pytest.approx(0.895, abs=0.01)


def test_the_predicted_purpose_awareness_failure_still_happens(report):
    """Predicted before the first run and left unfixed: MD5 as an ETag is graded HIGH.
    If this ever passes, something suppressed a true detection and that needs justifying."""
    awareness = report["all_entries"]["purpose_awareness"]
    assert awareness["non_security_facts"] == 3
    assert awareness["graded_high_or_worse"] == 3


def test_the_baited_negatives_mostly_hold(report):
    negatives = report["all_entries"]["negative_lines"]
    assert negatives["baited_lines"] == 18
    assert negatives["lines_hit"] <= 1
