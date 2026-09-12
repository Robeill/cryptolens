"""Detectors -> PQC mapping over both fixture sets.

The pair this file exists to prove: one algorithm, two purposes, two different post-quantum
replacements. That claim is the project's thesis and it has to hold end to end, not just in
a unit test with a hand-built finding.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cryptolens.analyzers.python_ast import analyze_file
from cryptolens.certs import scan_artifacts
from cryptolens.detectors.engine import detect
from cryptolens.discovery.source_files import discover_source_files
from cryptolens.model import AssetType, CryptoPurpose, MigrationStatus
from cryptolens.pqc import liboqs_bridge, recommend, recommend_all

EXAMPLE_REPO = Path(__file__).resolve().parent.parent / "fixtures" / "example_repo"


@pytest.fixture(scope="module")
def source_findings() -> list:
    usages = [
        usage
        for path in discover_source_files(EXAMPLE_REPO)
        for usage in analyze_file(path, EXAMPLE_REPO)
    ]
    return detect(usages)


@pytest.fixture(params=[True, False], ids=["liboqs", "no-liboqs"])
def both_liboqs_states(request, monkeypatch):
    if not request.param:
        monkeypatch.setattr(liboqs_bridge, "_probe", (None,))
    elif not liboqs_bridge.available():
        pytest.skip("liboqs is not installed in this environment")
    return request.param


def primaries(findings, algorithm, purpose):
    return {
        recommendation.primary.name
        for finding in findings
        if finding.algorithm == algorithm and finding.purpose is purpose
        for recommendation in [recommend(finding)]
        if recommendation is not None and recommendation.primary is not None
    }


def test_rsa_maps_to_two_different_mechanisms_in_one_scan(source_findings, both_liboqs_states):
    """The slide: same algorithm, same codebase, different answer per call site."""
    signing = primaries(source_findings, "RSA", CryptoPurpose.DIGITAL_SIGNATURE)
    establishing = primaries(source_findings, "RSA", CryptoPurpose.KEY_ESTABLISHMENT)

    assert signing == {"ML-DSA-65"}
    assert establishing == {"ML-KEM-768"}


def test_ecdh_and_ecdsa_diverge_the_same_way(source_findings, both_liboqs_states):
    assert primaries(source_findings, "ECDH", CryptoPurpose.KEY_ESTABLISHMENT) == {"ML-KEM-768"}
    assert primaries(source_findings, "ECDSA", CryptoPurpose.DIGITAL_SIGNATURE) == {"ML-DSA-65"}


def test_every_quantum_vulnerable_finding_gets_a_recommendation(
    source_findings, both_liboqs_states
):
    vulnerable = [
        f for f in source_findings if f.migration_status is MigrationStatus.QUANTUM_VULNERABLE
    ]
    assert vulnerable
    assert all(recommend(f) is not None for f in vulnerable)


def test_nothing_else_gets_one(source_findings, both_liboqs_states):
    others = [
        f
        for f in source_findings
        if f.migration_status is not MigrationStatus.QUANTUM_VULNERABLE
    ]
    assert others
    assert all(recommend(f) is None for f in others)


def test_the_hmac_in_the_fixture_repo_is_left_alone(source_findings, both_liboqs_states):
    """HS256 travels with RS256 through the JWT rules and must not be swept up with it."""
    hmac = [f for f in source_findings if f.algorithm == "HMAC-SHA-256"]
    assert hmac
    assert all(recommend(f) is None for f in hmac)


def test_recommendations_are_identical_with_and_without_liboqs(source_findings, monkeypatch):
    """The plan's done-when condition, over every finding in the fixture repo."""
    if not liboqs_bridge.available():
        pytest.skip("liboqs is not installed, so there is nothing to compare against")
    with_liboqs = recommend_all(source_findings)
    monkeypatch.setattr(liboqs_bridge, "_probe", (None,))
    without_liboqs = recommend_all(source_findings)
    assert with_liboqs == without_liboqs
    assert with_liboqs


def test_certificates_are_mapped_through_their_key_usage(artifact_repo, both_liboqs_states):
    findings = scan_artifacts(artifact_repo)
    certificates = {
        f.extra.get("subject"): f for f in findings if f.asset_type is AssetType.CERTIFICATE
    }

    signing = certificates["CN=signing.example"]
    assert recommend(signing).primary.name == "ML-DSA-65"

    agreement = certificates["CN=agreement.example"]
    assert recommend(agreement).primary.name == "ML-KEM-768"

    tls = certificates["CN=tls.example"]
    assert recommend(tls).ambiguous is True


def test_the_pqc_certificate_needs_no_migration(artifact_repo, both_liboqs_states):
    findings = scan_artifacts(artifact_repo)
    pqc = [f for f in findings if f.algorithm.startswith(("ML-", "SLH-"))]
    assert pqc
    assert all(recommend(f) is None for f in pqc)
