"""Score a tool's findings against the held-out ground truth.

The matching rules are frozen in `tools/PROTOCOL.md`, committed before this file existed.
Read that first; this is only its implementation.

    python tools/evaluate.py --tool cryptolens
    python tools/evaluate.py --tool bandit --output bandit.json
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from cryptolens.detectors.normalize import normalize_algorithm
from cryptolens.model import RiskLevel
from cryptolens.scan import scan

EVAL_REPO = ROOT / "tests" / "fixtures" / "eval_repo"
GROUND_TRUTH = EVAL_REPO / "GROUND_TRUTH.json"

WEAKNESS = "<weakness>"

CONFIDENCE_THRESHOLDS = (0.0, 0.5, 0.9)

# Protocol section 4: Bandit reports issue types, not algorithms.
BANDIT_REMIT = {"B303", "B324", "B304", "B305", "B505", "B501"}

# Matched against whole tokens of `issue_text`, never as substrings: "modes" contains "des",
# which scored Bandit's ECB finding as DES and cost it a true positive it had earned.
BANDIT_ALGORITHMS = {
    "md5": "MD5",
    "md4": "MD4",
    "md2": "MD2",
    "sha1": "SHA-1",
    "sha": "SHA-1",
    "tripledes": "3DES",
    "des": "DES",
    "arc4": "RC4",
    "rc4": "RC4",
    "blowfish": "Blowfish",
    "idea": "IDEA",
    "rsa": "RSA",
    "dsa": "DSA",
}

# Checks that assert a weakness as well as (or instead of) naming an algorithm. Same
# treatment CryptoLens gets: a result that does both contributes both observations.
BANDIT_WEAKNESS_CHECKS = {"B501", "B505", "B304", "B305", "B303", "B324"}


@dataclass(frozen=True)
class Fact:
    path: str
    line: int
    algorithm: str
    purpose: str
    security_relevant: bool = True
    marginal: bool = False
    kind: str = "algorithm"
    weakness: str | None = None

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.path, self.line, self.algorithm)

    @property
    def file_key(self) -> tuple[str, str]:
        return (self.path, self.algorithm)


@dataclass(frozen=True)
class Observation:
    path: str
    line: int
    algorithm: str
    purpose: str
    confidence: float
    risk: str
    kind: str = "algorithm"

    @property
    def key(self) -> tuple[str, int, str]:
        return (self.path, self.line, self.algorithm)

    @property
    def file_key(self) -> tuple[str, str]:
        return (self.path, self.algorithm)


@dataclass
class Score:
    true_positives: list = field(default_factory=list)
    false_positives: list = field(default_factory=list)
    false_negatives: list = field(default_factory=list)

    def precision(self) -> float:
        found = len(self.true_positives) + len(self.false_positives)
        return len(self.true_positives) / found if found else 0.0

    def recall(self) -> float:
        real = len(self.true_positives) + len(self.false_negatives)
        return len(self.true_positives) / real if real else 0.0

    def f1(self) -> float:
        precision, recall = self.precision(), self.recall()
        return 2 * precision * recall / (precision + recall) if precision + recall else 0.0

    def summary(self) -> dict:
        return {
            "tp": len(self.true_positives),
            "fp": len(self.false_positives),
            "fn": len(self.false_negatives),
            "precision": round(self.precision(), 4),
            "recall": round(self.recall(), 4),
            "f1": round(self.f1(), 4),
        }


# ------------------------------------------------------------------------- ground truth


def load_facts(include_marginal: bool = True) -> tuple[list[Fact], set[tuple[str, int]]]:
    document = json.loads(GROUND_TRUTH.read_text())
    facts: list[Fact] = []
    for entry in document["entries"]:
        if not include_marginal and entry.get("marginal"):
            continue
        facts.append(
            Fact(
                path=entry["path"],
                line=entry["line"],
                algorithm=normalize_algorithm(entry["algorithm"]),
                purpose=entry["purpose"],
                security_relevant=entry["security_relevant"],
                marginal=bool(entry.get("marginal")),
                weakness=entry.get("weakness"),
            )
        )
        if entry.get("weakness"):
            facts.append(
                Fact(
                    path=entry["path"],
                    line=entry["line"],
                    algorithm=WEAKNESS,
                    purpose=entry["purpose"],
                    security_relevant=entry["security_relevant"],
                    marginal=bool(entry.get("marginal")),
                    kind="weakness",
                    weakness=entry["weakness"],
                )
            )
    negatives = {(n["path"], n["line"]) for n in document["negatives"]}
    return facts, negatives


# ----------------------------------------------------------------------------- the tools


CRYPTOLENS_WEAKNESS_DETECTORS = {
    "jwt.verification_disabled",
    "ssl.verification_disabled",
    "ssl.hostname_check_disabled",
    "ssl.unverified_context",
}

# Protocol section 2: a weakness fact is matched by any tool that reports the weakness.
# Bandit reports these as B324/B304/B305/B505/B501; CryptoLens reports them as `Weakness`
# members on the assessment. Crediting only one of the two would be the asymmetry the
# protocol forbids.
CRYPTOLENS_WEAKNESSES = {
    "broken_algorithm",
    "deprecated_algorithm",
    "insecure_mode",
    "weak_key_size",
    "weak_curve",
    "verification_disabled",
    "hostname_check_disabled",
    "no_algorithm",
}

# Rejected: rewriting `TLS-unverified` to `TLS` so it could also match the algorithm fact.
# Protocol section 3 says normalisation canonicalises spelling and "does not map one algorithm
# to another", and section 2 already names that finding as the weakness report.


def observe_cryptolens() -> tuple[list[Observation], float]:
    started = time.monotonic()
    result = scan(EVAL_REPO)
    elapsed = time.monotonic() - started

    observations = []
    seen_weaknesses: set[tuple[str, int]] = set()

    def remember_weakness(finding, assessment) -> None:
        site = (finding.location.file, finding.location.line)
        if site in seen_weaknesses:
            return
        seen_weaknesses.add(site)
        observations.append(
            Observation(
                path=finding.location.file,
                line=finding.location.line,
                algorithm=WEAKNESS,
                purpose=finding.purpose.value,
                confidence=finding.confidence,
                risk=assessment.risk.value,
                kind="weakness",
            )
        )

    for finding in result.findings:
        assessment = result.assessments[finding.finding_id]
        if finding.detector in CRYPTOLENS_WEAKNESS_DETECTORS:
            remember_weakness(finding, assessment)
            continue
        observations.append(
            Observation(
                path=finding.location.file,
                line=finding.location.line,
                algorithm=normalize_algorithm(finding.algorithm),
                purpose=finding.purpose.value,
                confidence=finding.confidence,
                risk=assessment.risk.value,
            )
        )
        if {w.value for w in assessment.weaknesses} & CRYPTOLENS_WEAKNESSES:
            remember_weakness(finding, assessment)
    return observations, elapsed


def observe_bandit() -> tuple[list[Observation], float, list[dict]]:
    started = time.monotonic()
    completed = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", str(EVAL_REPO), "-f", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    elapsed = time.monotonic() - started
    payload = json.loads(completed.stdout)

    observations = []
    seen_weaknesses: set[tuple[str, int]] = set()
    for result in payload["results"]:
        if result["test_id"] not in BANDIT_REMIT:
            continue
        path = str(Path(result["filename"]).resolve().relative_to(EVAL_REPO))
        line = result["line_number"]
        severity = result["issue_severity"].lower()
        algorithm = _bandit_algorithm(result)
        if algorithm is not None:
            observations.append(
                Observation(path, line, algorithm, "unknown", 1.0, severity)
            )
        if result["test_id"] in BANDIT_WEAKNESS_CHECKS and (path, line) not in seen_weaknesses:
            seen_weaknesses.add((path, line))
            observations.append(
                Observation(path, line, WEAKNESS, "unknown", 1.0, severity, kind="weakness")
            )
    return observations, elapsed, payload["results"]


def _bandit_algorithm(result: dict) -> str | None:
    """The algorithm Bandit named, or None when it named only a weakness."""
    for token in re.split(r"[^A-Za-z0-9]+", result["issue_text"].lower()):
        if token in BANDIT_ALGORITHMS:
            return normalize_algorithm(BANDIT_ALGORITHMS[token])
    return None


# -------------------------------------------------------------------------- the scoring


def score(observations: list[Observation], facts: list[Fact]) -> Score:
    remaining: dict[tuple[str, int, str], list[Fact]] = {}
    for fact in facts:
        remaining.setdefault(fact.key, []).append(fact)

    outcome = Score()
    for observation in observations:
        candidates = remaining.get(observation.key)
        if candidates:
            outcome.true_positives.append((observation, candidates.pop(0)))
        else:
            outcome.false_positives.append(observation)
    for leftovers in remaining.values():
        outcome.false_negatives.extend(leftovers)
    return outcome


def score_by_file(observations: list[Observation], facts: list[Fact]) -> Score:
    observed = {o.file_key for o in observations}
    real = {f.file_key for f in facts}
    outcome = Score()
    outcome.true_positives = sorted(observed & real)
    outcome.false_positives = sorted(observed - real)
    outcome.false_negatives = sorted(real - observed)
    return outcome


def attribute_errors(outcome: Score) -> dict:
    comparable = [
        (o, f) for o, f in outcome.true_positives
        if f.kind == "algorithm" and f.purpose != "unknown"
    ]
    wrong = [(o, f) for o, f in comparable if o.purpose != f.purpose]
    return {
        "comparable": len(comparable),
        "wrong_purpose": len(wrong),
        "rate": round(len(wrong) / len(comparable), 4) if comparable else 0.0,
        "examples": [
            {"at": f"{o.path}:{o.line}", "algorithm": o.algorithm,
             "expected": f.purpose, "reported": o.purpose}
            for o, f in wrong
        ],
    }


def purpose_awareness_failures(observations: list[Observation], facts: list[Fact]) -> dict:
    non_security = {f.key for f in facts if not f.security_relevant}
    loud = [
        o for o in observations
        if o.key in non_security and RiskLevel(o.risk).rank >= RiskLevel.HIGH.rank
    ]
    return {
        "non_security_facts": len(non_security),
        "graded_high_or_worse": len(loud),
        "rate": round(len(loud) / len(non_security), 4) if non_security else 0.0,
        "sites": sorted(f"{o.path}:{o.line} {o.algorithm} -> {o.risk}" for o in loud),
    }


def naming_granularity(outcome: Score) -> dict:
    """How much of the error is "did not detect" versus "named at a different granularity".

    A reporting statistic, not a matching rule: an FN with an FP on the same line means the
    tool saw the call and described it differently -- `AES-GCM` where the ground truth says
    `AES-256-GCM`. Chasing these by renaming algorithms to match the ground truth would be
    overfitting to the evaluation set, so they are counted and left.
    """
    missed = {(f.path, f.line) for f in outcome.false_negatives}
    spurious = {(o.path, o.line) for o in outcome.false_positives}
    both = missed & spurious
    return {
        "false_negatives_with_a_finding_on_the_same_line": sum(
            1 for f in outcome.false_negatives if (f.path, f.line) in both
        ),
        "false_positives_with_a_miss_on_the_same_line": sum(
            1 for o in outcome.false_positives if (o.path, o.line) in both
        ),
        "lines": sorted(f"{path}:{line}" for path, line in both),
    }


def negative_line_hits(observations: list[Observation], negatives: set) -> dict:
    hits = [o for o in observations if (o.path, o.line) in negatives]
    return {
        "baited_lines": len(negatives),
        "lines_hit": len({(o.path, o.line) for o in hits}),
        "findings": sorted(f"{o.path}:{o.line} {o.algorithm}" for o in hits),
    }


def by_confidence(observations: list[Observation], facts: list[Fact]) -> dict:
    report = {}
    for threshold in CONFIDENCE_THRESHOLDS:
        kept = [o for o in observations if o.confidence >= threshold]
        report[f">={threshold}"] = {
            "findings": len(kept),
            **score(kept, facts).summary(),
        }
    return report


def evaluate(tool: str) -> dict:
    if tool == "cryptolens":
        observations, elapsed = observe_cryptolens()
        extra = {}
    else:
        observations, elapsed, raw = observe_bandit()
        extra = {
            "bandit_results_total": len(raw),
            "bandit_results_in_remit": len(observations),
            "bandit_checks_seen": sorted({r["test_id"] for r in raw}),
        }

    report = {"tool": tool, "seconds": round(elapsed, 3), "findings": len(observations), **extra}

    for label, include_marginal in (("all_entries", True), ("without_marginal", False)):
        facts, negatives = load_facts(include_marginal)
        primary = score(observations, facts)
        report[label] = {
            "call_site": primary.summary(),
            "file_level": score_by_file(observations, facts).summary(),
            "attribute_errors": attribute_errors(primary),
            "naming_granularity": naming_granularity(primary),
            "purpose_awareness": purpose_awareness_failures(observations, facts),
            "negative_lines": negative_line_hits(observations, negatives),
            "by_confidence": by_confidence(observations, facts),
            "false_positives": sorted(
                f"{o.path}:{o.line} {o.algorithm}" for o in primary.false_positives
            ),
            "false_negatives": sorted(
                f"{f.path}:{f.line} {f.algorithm}" for f in primary.false_negatives
            ),
        }

    if tool == "bandit":
        facts, _ = load_facts(True)
        in_remit = [f for f in facts if _within_bandit_remit(f)]
        report["bandit_own_remit"] = {
            "facts_in_remit": len(in_remit),
            "call_site": score(observations, in_remit).summary(),
        }
    return report


BANDIT_REMIT_WEAKNESSES = {
    "broken_algorithm",
    "deprecated_algorithm",
    "insecure_mode",
    "weak_key_size",
    "verification_disabled",
    "hostname_check_disabled",
}


def _within_bandit_remit(fact: Fact) -> bool:
    """Facts Bandit's documented checks are meant to cover -- protocol section 4.

    Weak hash, insecure cipher and mode, weak key size, certificate validation disabled.
    Everything else in the ground truth is inventory, which Bandit does not attempt.
    """
    return fact.weakness in BANDIT_REMIT_WEAKNESSES


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", choices=["cryptolens", "bandit"], default="cryptolens")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()

    report = evaluate(arguments.tool)
    document = json.dumps(report, indent=2, sort_keys=True)
    if arguments.output:
        arguments.output.write_text(document + "\n")
    print(document)


if __name__ == "__main__":
    main()
