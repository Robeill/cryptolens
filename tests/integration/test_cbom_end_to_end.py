"""Scan -> findings -> assets -> CycloneDX, validated, over both fixture sets.

This is the first file that runs the whole pipeline in one go, so it is also where the
finding/asset collapse can be seen doing its job on real input.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from cryptolens.analyzers.python_ast import analyze_file
from cryptolens.cbom import aggregate, build_bom, to_json, validate
from cryptolens.certs import scan_artifacts
from cryptolens.detectors.engine import detect
from cryptolens.discovery.source_files import discover_source_files
from cryptolens.model import AssetType, RiskLevel
from cryptolens.risk import Priority, assess_all

EXAMPLE_REPO = Path(__file__).resolve().parent.parent / "fixtures" / "example_repo"
SERIAL = UUID("11111111-2222-3333-4444-555555555555")
STAMP = datetime(2026, 9, 10, tzinfo=UTC)


@pytest.fixture(scope="module")
def source_findings() -> list:
    usages = [
        usage
        for path in discover_source_files(EXAMPLE_REPO)
        for usage in analyze_file(path, EXAMPLE_REPO)
    ]
    return detect(usages)


def document(findings, target="fixture") -> str:
    bom = build_bom(
        aggregate(findings), target_name=target, serial_number=SERIAL, timestamp=STAMP
    )
    return to_json(bom)


def test_the_source_repo_produces_a_valid_cbom(source_findings):
    doc = document(source_findings)
    assert validate(doc) is None
    payload = json.loads(doc)
    assert payload["specVersion"] == "1.6"
    assert len(payload["components"]) == len(aggregate(source_findings))


def test_the_artifact_repo_produces_a_valid_cbom(artifact_repo):
    doc = document(scan_artifacts(artifact_repo), target="artifacts")
    assert validate(doc) is None


def test_a_combined_scan_produces_a_valid_cbom(source_findings, artifact_repo):
    """Source findings and certificate findings in one document, which is what a real scan
    of an application repository looks like."""
    doc = document(source_findings + scan_artifacts(artifact_repo), target="everything")
    assert validate(doc) is None
    payload = json.loads(doc)
    kinds = {c["cryptoProperties"]["assetType"] for c in payload["components"]}
    assert kinds == {a.value for a in AssetType}


def test_sixty_eight_findings_collapse_into_fewer_assets(source_findings):
    """The collapse is the reason the CBOM is readable. If these numbers were equal the
    aggregation step would be doing nothing."""
    assets = aggregate(source_findings)
    assert len(assets) < len(source_findings)
    assert sum(a.occurrence_count for a in assets) == len(source_findings)


def test_the_commonest_algorithm_is_one_component_with_many_occurrences(source_findings):
    assets = aggregate(source_findings)
    sha256 = [a for a in assets if a.algorithm == "SHA-256"]
    assert len(sha256) == 1
    assert sha256[0].occurrence_count > 5
    assert len(sha256[0].files) > 1


def test_rsa_stays_split_by_purpose_in_the_inventory(source_findings):
    """The CBOM must not merge RSA-for-signing with RSA-for-key-transport, because they carry
    different migration advice."""
    purposes = {
        a.purpose.value for a in aggregate(source_findings) if a.algorithm == "RSA"
    }
    assert {"digital_signature", "key_establishment"} <= purposes


def test_asset_risk_is_the_worst_of_its_call_sites(source_findings):
    """Holds for every asset, not just the one that happened to be convenient."""
    assets = aggregate(source_findings)
    assessments = assess_all(source_findings, STAMP)

    for asset in assets:
        worst = max(assessments[o.finding_id].risk.rank for o in asset.occurrences)
        assert asset.risk(assessments).rank == worst, asset.algorithm

    multi = [a for a in assets if a.occurrence_count > 1]
    assert multi, "nothing to prove if no asset has more than one call site"


def test_a_configuration_weakness_is_not_merged_into_the_asset_it_weakens(source_findings):
    """`ssl.SSLContext(...)` and `verify_mode = CERT_NONE` are not the same inventory entry.
    Merging them buried a CRITICAL finding inside a URGENT component."""
    assets = {a.algorithm: a for a in aggregate(source_findings)}
    assessments = assess_all(source_findings, STAMP)

    assert assets["TLS"].risk(assessments) is RiskLevel.HIGH
    assert assets["TLS"].priority(assessments) is Priority.URGENT

    assert assets["TLS-unverified"].risk(assessments) is RiskLevel.CRITICAL
    assert assets["TLS-unverified"].priority(assessments) is Priority.IMMEDIATE
    assert assets["TLS-unverified-hostname"].risk(assessments) is RiskLevel.CRITICAL

    assert assets["JWT"].risk(assessments) is RiskLevel.MEDIUM
    assert assets["JWT-unverified"].risk(assessments) is RiskLevel.CRITICAL


def test_a_weakened_protocol_still_reports_as_that_protocol(source_findings):
    payload = json.loads(document(source_findings))
    protocols = {
        component["name"]: component["cryptoProperties"]["protocolProperties"]["type"]
        for component in payload["components"]
        if component["cryptoProperties"]["assetType"] == "protocol"
    }
    assert protocols == {
        "TLS": "tls",
        "TLS-unverified": "tls",
        "TLS-unverified-hostname": "tls",
    }


def test_the_pqc_certificate_appears_as_a_quantum_safe_component(artifact_repo):
    findings = scan_artifacts(artifact_repo)
    payload = json.loads(document(findings, target="artifacts"))
    names = {c["name"] for c in payload["components"]}
    assert "ML-DSA-65" in names
    assert "ML-KEM-768" in names

    ml_dsa = next(c for c in payload["components"] if c["name"] == "ML-DSA-65"
                  and c["cryptoProperties"]["assetType"] == "algorithm")
    assert ml_dsa["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3


def test_each_certificate_is_its_own_component_with_its_subject(artifact_repo):
    payload = json.loads(document(scan_artifacts(artifact_repo), target="artifacts"))
    certificates = [
        c for c in payload["components"]
        if c["cryptoProperties"]["assetType"] == "certificate"
    ]
    subjects = [
        c["cryptoProperties"]["certificateProperties"].get("subjectName") for c in certificates
    ]
    assert len(subjects) == len(set(subjects)), "one component per certificate, not per file"
    assert "CN=expired.example" in subjects
    assert "CN=longlived.example" in subjects


def test_one_certificate_in_three_files_is_one_component(artifact_repo):
    """`rsa_cert.pem`, `rsa_cert.der` and `chain.pem` hold the same certificate. Its identity
    is its subject, issuer and serial; the files are occurrences of it."""
    assets = aggregate(scan_artifacts(artifact_repo))
    rsa_certs = [
        a
        for a in assets
        if a.asset_type is AssetType.CERTIFICATE
        and a.details.get("subject") == "CN=rsa.example"
    ]
    assert len(rsa_certs) == 1
    assert set(rsa_certs[0].files) >= {"rsa_cert.pem", "rsa_cert.der", "chain.pem"}


def test_a_rescan_produces_byte_identical_output(source_findings):
    assert document(source_findings) == document(source_findings)
