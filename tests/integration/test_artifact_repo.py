"""Discovery -> certificate parser over a directory of real artifacts.

The point of this file is the *whole directory*: a scan meets certificates, keys, and junk in
the same pass, and one unreadable file must not cost the findings from the others.
"""

from __future__ import annotations

from cryptolens.certs import scan_artifacts
from cryptolens.discovery.artifact_files import discover_artifact_files
from cryptolens.model import AssetType, CryptoStatus, MigrationStatus


def test_discovery_finds_every_artifact_including_the_broken_ones(artifact_repo):
    names = {p.name for p in discover_artifact_files(artifact_repo)}
    assert "rsa_cert.pem" in names
    assert "rsa_cert.der" in names
    assert "unknown_oid_cert.der" in names
    assert "encrypted.key" in names
    assert "malformed.pem" in names


def test_a_full_scan_survives_the_unreadable_files(artifact_repo):
    findings = scan_artifacts(artifact_repo)
    assert findings
    assert {f.location.file for f in findings}, "locations should be repo-relative"
    assert all(not f.location.file.startswith("/") for f in findings)


def test_a_scan_separates_certificates_keys_and_algorithms(artifact_repo):
    by_type: dict[AssetType, int] = {}
    for finding in scan_artifacts(artifact_repo):
        by_type[finding.asset_type] = by_type.get(finding.asset_type, 0) + 1

    assert by_type[AssetType.CERTIFICATE] >= 5
    assert by_type[AssetType.ALGORITHM] >= 5
    assert by_type[AssetType.RELATED_CRYPTO_MATERIAL] >= 3


def test_the_scan_separates_the_pqc_certificate_from_the_classical_ones(artifact_repo):
    findings = scan_artifacts(artifact_repo)
    pqc = [f for f in findings if f.status is CryptoStatus.PQC]
    assert {f.algorithm for f in pqc} == {"ML-DSA-65", "ML-KEM-768", "SLH-DSA-SHA2-128s"}
    assert all(f.migration_status is MigrationStatus.QUANTUM_SAFE for f in pqc)

    vulnerable = {
        f.algorithm for f in findings if f.migration_status is MigrationStatus.QUANTUM_VULNERABLE
    }
    assert {"RSA", "EC", "Ed25519", "RSA-SHA-256"} <= vulnerable


def test_every_artifact_finding_has_a_stable_id(artifact_repo):
    first = {f.finding_id for f in scan_artifacts(artifact_repo)}
    second = {f.finding_id for f in scan_artifacts(artifact_repo)}
    assert first == second


def test_artifact_findings_carry_line_zero(artifact_repo):
    """There is no line number in a DER file; 0 marks 'the file itself'."""
    assert {f.location.line for f in scan_artifacts(artifact_repo)} == {0}
