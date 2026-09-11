"""Findings collapse into assets.

A `sha256()` call inside a loop must not become 40 CBOM components. But two RSA-2048
certificates *are* two certificates, and the line between those two cases is what this file
pins down.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cryptolens.cbom.aggregate import aggregate, asset_key
from cryptolens.model import (
    AssetType,
    CryptoFinding,
    CryptoFunction,
    CryptoMode,
    CryptoPrimitive,
    CryptoPurpose,
    CryptoStatus,
    MigrationStatus,
    RiskLevel,
    SourceLocation,
)
from cryptolens.risk import Priority, assess_all

NOW = datetime(2026, 9, 10, tzinfo=UTC)


def finding(file="pkg/a.py", line=1, **overrides) -> CryptoFinding:
    kwargs = {
        "algorithm": "SHA-256",
        "location": SourceLocation(file, line),
        "purpose": CryptoPurpose.HASHING,
        "evidence": "hashlib.sha256(data)",
        "primitive": CryptoPrimitive.HASH,
        "status": CryptoStatus.CLASSICAL,
        "classical_security_level": 128,
        "crypto_functions": [CryptoFunction.DIGEST],
    }
    kwargs.update(overrides)
    return CryptoFinding(**kwargs)


def certificate(file="certs/a.pem", subject="CN=a", serial="01", **overrides) -> CryptoFinding:
    kwargs = {
        "algorithm": "RSA",
        "location": SourceLocation(file, 0),
        "purpose": CryptoPurpose.UNKNOWN,
        "evidence": f"X.509 certificate ({subject})",
        "asset_type": AssetType.CERTIFICATE,
        "primitive": CryptoPrimitive.PKE,
        "key_size": 2048,
        "status": CryptoStatus.CLASSICAL,
        "extra": {"subject": subject, "serial_number": serial},
    }
    kwargs.update(overrides)
    return CryptoFinding(**kwargs)


# ------------------------------------------------------------------------- deduplication


def test_the_same_algorithm_in_forty_places_is_one_asset():
    findings = [finding(line=n) for n in range(1, 41)]
    assets = aggregate(findings)
    assert len(assets) == 1
    assert assets[0].occurrence_count == 40


def test_occurrences_are_never_lost():
    """The invariant the CBOM rests on: one occurrence per finding, no more, no fewer."""
    findings = [
        finding(line=1),
        finding(line=2),
        finding(algorithm="MD5", line=3),
        certificate(),
        certificate(file="certs/b.pem", subject="CN=b", serial="02"),
    ]
    assets = aggregate(findings)
    assert sum(asset.occurrence_count for asset in assets) == len(findings)


def test_no_two_assets_share_a_dedupe_key():
    findings = [finding(line=n) for n in range(5)] + [
        finding(algorithm="AES-256", mode=CryptoMode.GCM, primitive=CryptoPrimitive.BLOCK_CIPHER)
    ]
    assets = aggregate(findings)
    keys = [asset.key for asset in assets]
    assert len(keys) == len(set(keys))
    ids = [asset.asset_id for asset in assets]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize(
    "overrides",
    [
        {"algorithm": "SHA-512"},
        {"primitive": CryptoPrimitive.MAC},
        {"mode": CryptoMode.GCM},
        {"purpose": CryptoPurpose.MAC},
        {"key_size": 256},
        {"parameter_set": "SECP256R1"},
        {"asset_type": AssetType.PROTOCOL},
        {"oid": "1.2.3.4"},
    ],
    ids=["algorithm", "primitive", "mode", "purpose", "key-size", "parameter-set",
         "asset-type", "oid"],
)
def test_each_key_element_splits_an_asset(overrides):
    assets = aggregate([finding(), finding(**overrides)])
    assert len(assets) == 2


def test_the_same_algorithm_for_two_purposes_is_two_assets():
    """RSA signing and RSA key transport are one algorithm and two inventory entries, because
    they carry different migration advice."""
    assets = aggregate(
        [
            finding(
                algorithm="RSA",
                purpose=CryptoPurpose.DIGITAL_SIGNATURE,
                primitive=CryptoPrimitive.SIGNATURE,
            ),
            finding(
                algorithm="RSA",
                purpose=CryptoPurpose.KEY_ESTABLISHMENT,
                primitive=CryptoPrimitive.PKE,
            ),
        ]
    )
    assert len(assets) == 2
    assert {a.purpose for a in assets} == {
        CryptoPurpose.DIGITAL_SIGNATURE,
        CryptoPurpose.KEY_ESTABLISHMENT,
    }


# ---------------------------------------------------------- algorithms vs. instances


def test_two_certificates_with_identical_keys_stay_two_assets():
    """Merging them would discard one subject, and the subject is the point of a certificate."""
    assets = aggregate(
        [
            certificate(file="certs/a.pem", subject="CN=a", serial="01"),
            certificate(file="certs/b.pem", subject="CN=b", serial="02"),
        ]
    )
    assert len(assets) == 2
    assert {a.details["subject"] for a in assets} == {"CN=a", "CN=b"}


def test_the_same_certificate_seen_twice_is_one_asset():
    assets = aggregate([certificate(), certificate()])
    assert len(assets) == 1
    assert assets[0].occurrence_count == 2


def test_two_key_files_are_two_assets_even_with_the_same_algorithm():
    material = {
        "asset_type": AssetType.RELATED_CRYPTO_MATERIAL,
        "algorithm": "RSA",
        "primitive": CryptoPrimitive.PKE,
        "key_size": 2048,
        "extra": {"artifact": "private-key"},
    }
    assets = aggregate(
        [
            finding(file="keys/a.key", **material),
            finding(file="keys/b.key", **material),
        ]
    )
    assert len(assets) == 2


def test_an_algorithm_deduplicates_across_files_but_a_key_does_not():
    algorithms = aggregate([finding(file="a.py"), finding(file="b.py")])
    keys = aggregate(
        [
            finding(file="a.key", asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
                    extra={"artifact": "private-key"}),
            finding(file="b.key", asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
                    extra={"artifact": "private-key"}),
        ]
    )
    assert len(algorithms) == 1
    assert len(keys) == 2


def test_one_certificate_stored_in_two_files_is_one_asset():
    """A certificate's identity is subject, issuer and serial -- the X.509 definition. The
    same certificate as PEM and as DER is one certificate in two places."""
    assets = aggregate(
        [certificate(file="a.pem"), certificate(file="a.der")]
    )
    assert len(assets) == 1
    assert assets[0].files == ["a.der", "a.pem"]


def test_unknown_algorithms_with_different_oids_do_not_merge():
    """An unidentified algorithm is identified only by its OID. Merging would erase the one
    fact we have."""
    assets = aggregate(
        [
            finding(algorithm="unknown", oid="1.2.643.7.1.1.3.2", primitive=CryptoPrimitive.UNKNOWN),
            finding(algorithm="unknown", oid="1.2.643.7.1.1.3.3", primitive=CryptoPrimitive.UNKNOWN),
        ]
    )
    assert len(assets) == 2
    assert {a.oid for a in assets} == {"1.2.643.7.1.1.3.2", "1.2.643.7.1.1.3.3"}


# ------------------------------------------------------------------------ merged values


def test_crypto_functions_are_unioned():
    """A key generated in one file and used to sign in another is one asset, two functions."""
    assets = aggregate(
        [
            finding(algorithm="RSA", crypto_functions=[CryptoFunction.KEYGEN]),
            finding(algorithm="RSA", crypto_functions=[CryptoFunction.SIGN], line=2),
            finding(algorithm="RSA", crypto_functions=[CryptoFunction.SIGN], line=3),
        ]
    )
    assert len(assets) == 1
    assert assets[0].crypto_functions == [CryptoFunction.KEYGEN, CryptoFunction.SIGN]


def test_confidence_is_the_highest_of_the_occurrences():
    """One confident call site is enough to make the asset real."""
    assets = aggregate([finding(confidence=0.3), finding(confidence=1.0, line=2)])
    assert assets[0].confidence == 1.0


def test_a_known_status_beats_an_unknown_one():
    assets = aggregate(
        [
            finding(status=CryptoStatus.UNKNOWN, classical_security_level=None),
            finding(status=CryptoStatus.CLASSICAL, line=2),
        ]
    )
    assert assets[0].status is CryptoStatus.CLASSICAL
    assert assets[0].classical_security_level == 128


def test_certificate_details_are_carried_onto_the_asset():
    asset = aggregate([certificate(extra={"subject": "CN=a", "serial_number": "01",
                                          "not_after": "2030-01-01T00:00:00+00:00"})])[0]
    assert asset.details["not_after"] == "2030-01-01T00:00:00+00:00"


def test_files_are_listed_without_duplicates():
    asset = aggregate([finding(file="a.py", line=1), finding(file="a.py", line=2),
                       finding(file="b.py", line=1)])[0]
    assert asset.files == ["a.py", "b.py"]


# ----------------------------------------------------------------- risk at asset level


def test_asset_risk_is_the_worst_of_its_occurrences():
    """One bad call site makes the asset bad."""
    findings = [
        finding(algorithm="RSA", primitive=CryptoPrimitive.PKE,
                purpose=CryptoPurpose.KEY_ESTABLISHMENT, key_size=2048,
                classical_security_level=112, line=1),
        finding(algorithm="RSA", primitive=CryptoPrimitive.PKE,
                purpose=CryptoPurpose.KEY_ESTABLISHMENT, key_size=2048,
                classical_security_level=112, line=2),
    ]
    assessments = assess_all(findings, NOW)
    asset = aggregate(findings)[0]
    assert asset.risk(assessments) is RiskLevel.HIGH
    assert asset.priority(assessments) is Priority.URGENT


def test_asset_risk_keeps_the_two_axes_apart():
    findings = [
        finding(algorithm="ECDH", primitive=CryptoPrimitive.KEY_AGREE,
                purpose=CryptoPurpose.KEY_ESTABLISHMENT, curve="SECP256R1")
    ]
    asset = aggregate(findings)[0]
    assessments = assess_all(findings, NOW)
    assert asset.classical_risk(assessments) is RiskLevel.INFO
    assert asset.quantum_risk(assessments) is RiskLevel.HIGH


def test_an_asset_with_no_assessments_is_quiet_rather_than_broken():
    asset = aggregate([finding()])[0]
    assert asset.risk({}) is RiskLevel.INFO
    assert asset.priority({}) is Priority.NONE


def test_asset_migration_status_follows_its_findings():
    findings = [
        finding(algorithm="RSA", primitive=CryptoPrimitive.SIGNATURE,
                purpose=CryptoPurpose.DIGITAL_SIGNATURE, line=1),
        finding(algorithm="RSA", primitive=CryptoPrimitive.SIGNATURE,
                purpose=CryptoPurpose.DIGITAL_SIGNATURE, line=2),
    ]
    asset = aggregate(findings)[0]
    by_id = {f.finding_id: f for f in findings}
    assert asset.migration_status(by_id) is MigrationStatus.QUANTUM_VULNERABLE


def test_an_asset_whose_findings_disagree_needs_review():
    """They should not disagree, since the dedupe key fixes algorithm and purpose. If one
    ever does, say so rather than picking a side."""
    findings = [finding(line=1), finding(line=2, classical_security_level=0)]
    asset = aggregate(findings)[0]
    by_id = {f.finding_id: f for f in findings}
    assert asset.migration_status(by_id) is MigrationStatus.NEEDS_REVIEW


def test_an_asset_with_no_findings_to_consult_needs_review():
    assert aggregate([finding()])[0].migration_status({}) is MigrationStatus.NEEDS_REVIEW


# --------------------------------------------------------------------------- ordering


def test_aggregation_is_deterministic():
    findings = [finding(line=3), finding(algorithm="MD5", line=1), certificate()]
    first = [a.asset_id for a in aggregate(findings)]
    second = [a.asset_id for a in aggregate(list(reversed(findings)))]
    assert first == second


def test_occurrences_are_sorted_by_location():
    asset = aggregate(
        [finding(file="b.py", line=1), finding(file="a.py", line=9), finding(file="a.py", line=2)]
    )[0]
    assert [str(o) for o in asset.occurrences] == ["a.py:2", "a.py:9", "b.py:1"]


def test_the_key_is_computed_from_the_finding_alone():
    assert asset_key(finding(line=1)) == asset_key(finding(line=99))
    assert asset_key(finding()) != asset_key(finding(algorithm="MD5"))


def test_aggregating_nothing_yields_nothing():
    assert aggregate([]) == []
