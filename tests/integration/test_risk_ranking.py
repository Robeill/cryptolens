"""Detectors and certificates -> risk, over both fixture sets.

The pair this file exists to prove sits in one fixture module: `exchange_ecdh` and
`sign_ecdsa` in `ecdsa_sign.py` use the same curve and the same mathematics, and come out at
different priorities.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from cryptolens.analyzers.python_ast import analyze_file
from cryptolens.certs import scan_artifacts
from cryptolens.detectors.engine import detect
from cryptolens.discovery.source_files import discover_source_files
from cryptolens.model import AssetType, RiskLevel
from cryptolens.risk import Priority, Weakness, assess, assess_all, priority_rank

EXAMPLE_REPO = Path(__file__).resolve().parent.parent / "fixtures" / "example_repo"
NOW = datetime(2026, 9, 10, tzinfo=UTC)


@pytest.fixture(scope="module")
def source_findings() -> list:
    usages = [
        usage
        for path in discover_source_files(EXAMPLE_REPO)
        for usage in analyze_file(path, EXAMPLE_REPO)
    ]
    return detect(usages)


def at(findings, module, line, detector=None):
    matched = [
        f
        for f in findings
        if f.location.file == module
        and f.location.line == line
        and (detector is None or f.detector == detector)
    ]
    assert matched, f"no finding at {module}:{line}"
    return matched[0]


# ------------------------------------------------------------------------- the slide


def test_ecdh_and_ecdsa_in_one_file_get_different_priorities(source_findings):
    """Same curve, same file, same mathematics. Opposite urgency."""
    exchange = assess(at(source_findings, "ecdsa_sign.py", 30), NOW)
    signing = assess(at(source_findings, "ecdsa_sign.py", 14), NOW)

    assert exchange.priority is Priority.URGENT
    assert signing.priority is Priority.SCHEDULED
    assert priority_rank(exchange.priority) > priority_rank(signing.priority)
    assert Weakness.HARVEST_NOW_DECRYPT_LATER in exchange.weaknesses
    assert Weakness.QUANTUM_VULNERABLE_SIGNATURE in signing.weaknesses


def test_rsa_splits_the_same_way_across_two_call_sites(source_findings):
    exchange = assess(at(source_findings, "rsa_signing.py", 37), NOW)
    signing = assess(at(source_findings, "rsa_signing.py", 29), NOW)
    assert exchange.priority is Priority.URGENT
    assert signing.priority is Priority.SCHEDULED


# -------------------------------------------------------------- the classically broken


@pytest.mark.parametrize(
    ("module", "line", "detector"),
    [
        ("hash_sha256.py", 21, None),
        ("hash_sha256.py", 25, None),
        ("aes_encrypt.py", 30, None),
        ("rsa_signing.py", 10, None),
        ("jwt_tokens.py", 25, None),
        ("jwt_tokens.py", 45, "jwt.verification_disabled"),
        ("jwt_tokens.py", 49, "jwt.verification_disabled"),
    ],
    ids=["md5", "sha1", "ecb", "rsa-1024", "alg-none", "verify-false", "verify-option"],
)
def test_things_already_broken_today_come_out_immediate(
    source_findings, module, line, detector
):
    assert assess(at(source_findings, module, line, detector), NOW).priority is Priority.IMMEDIATE


def test_one_line_can_hold_a_safe_finding_and_a_broken_one(source_findings):
    """`jwt.decode(token, verify=False)` is two facts: a JWT is verified here, and it is
    not really. They are graded separately."""
    algorithm = assess(at(source_findings, "jwt_tokens.py", 45, "jwt.decode"), NOW)
    disabled = assess(at(source_findings, "jwt_tokens.py", 45, "jwt.verification_disabled"), NOW)
    assert algorithm.priority is Priority.SCHEDULED
    assert disabled.priority is Priority.IMMEDIATE


def test_the_strong_hashes_are_left_alone(source_findings):
    for line in (7, 11, 17):
        assessment = assess(at(source_findings, "hash_sha256.py", line), NOW)
        assert assessment.risk is RiskLevel.INFO
        assert assessment.priority is Priority.NONE


def test_hmac_and_pbkdf2_are_not_migration_targets(source_findings):
    for line in (33, 41):
        assessment = assess(at(source_findings, "hash_sha256.py", line), NOW)
        assert assessment.priority is Priority.NONE


# --------------------------------------------------------------------- whole-repo shape


def test_every_finding_gets_exactly_one_assessment(source_findings):
    assessments = assess_all(source_findings, NOW)
    assert len(assessments) == len({f.finding_id for f in source_findings})


def test_the_repo_sorts_into_a_usable_worklist(source_findings):
    assessments = assess_all(source_findings, NOW)
    ranked = sorted(
        source_findings,
        key=lambda f: (
            -priority_rank(assessments[f.finding_id].priority),
            -assessments[f.finding_id].risk.rank,
            f.location.file,
            f.location.line,
        ),
    )
    top = assessments[ranked[0].finding_id]
    assert top.priority is Priority.IMMEDIATE
    assert top.risk is RiskLevel.CRITICAL

    bottom = assessments[ranked[-1].finding_id]
    assert bottom.priority is Priority.NONE


def test_nothing_quantum_safe_is_ever_urgent(source_findings):
    for finding in source_findings:
        assessment = assess(finding, NOW)
        if assessment.quantum_risk is RiskLevel.INFO and not assessment.broken_today:
            assert assessment.priority in {Priority.NONE, Priority.MONITOR}


# ------------------------------------------------------------------------ certificates


def test_certificates_are_ranked_by_what_is_in_them(artifact_repo):
    findings = scan_artifacts(artifact_repo)
    by_subject = {
        f.extra.get("subject"): f for f in findings if f.asset_type is AssetType.CERTIFICATE
    }

    expired = assess(by_subject["CN=expired.example"], NOW)
    assert Weakness.EXPIRED_CERTIFICATE in expired.weaknesses
    assert expired.priority is Priority.IMMEDIATE

    long_lived = assess(by_subject["CN=longlived.example"], NOW)
    assert Weakness.OUTLIVES_QUANTUM_DEADLINE in long_lived.weaknesses
    assert long_lived.priority is Priority.IMMEDIATE

    agreement = assess(by_subject["CN=agreement.example"], NOW)
    assert agreement.priority is Priority.URGENT

    signing = assess(by_subject["CN=signing.example"], NOW)
    assert signing.priority is Priority.SCHEDULED


def test_a_long_lived_signing_certificate_outranks_a_short_lived_one(artifact_repo):
    """Both are ECDSA signing certificates. Only the validity window differs, and it is
    enough to move one from 'scheduled' to 'immediate'."""
    findings = scan_artifacts(artifact_repo)
    by_subject = {
        f.extra.get("subject"): f for f in findings if f.asset_type is AssetType.CERTIFICATE
    }
    long_lived = assess(by_subject["CN=longlived.example"], NOW)
    short_lived = assess(by_subject["CN=signing.example"], NOW)
    assert priority_rank(long_lived.priority) > priority_rank(short_lived.priority)


def test_the_sha1_signature_on_a_certificate_is_immediate(artifact_repo):
    findings = scan_artifacts(artifact_repo)
    sha1 = [f for f in findings if f.algorithm == "RSA-SHA-1"]
    assert sha1
    for finding in sha1:
        assert assess(finding, NOW).priority is Priority.IMMEDIATE


def test_the_pqc_certificate_is_quiet(artifact_repo):
    findings = scan_artifacts(artifact_repo)
    pqc = [f for f in findings if f.algorithm.startswith(("ML-", "SLH-"))]
    assert pqc
    for finding in pqc:
        assessment = assess(finding, NOW)
        assert assessment.risk is RiskLevel.INFO
        assert assessment.priority is Priority.NONE
