import json

import pytest

from cryptolens.model import (
    AssetType,
    CryptoFinding,
    CryptoFunction,
    CryptoMode,
    CryptoPadding,
    CryptoPrimitive,
    CryptoPurpose,
    CryptoStatus,
    MigrationStatus,
    RiskLevel,
    SourceLocation,
    max_risk,
)


def make_finding(**overrides) -> CryptoFinding:
    kwargs = {
        "algorithm": "SHA-256",
        "location": SourceLocation("pkg/hashes.py", 12),
        "purpose": CryptoPurpose.HASHING,
        "evidence": "hashlib.sha256(data)",
    }
    kwargs.update(overrides)
    return CryptoFinding(**kwargs)


# --------------------------------------------------------------------------- defaults


def test_optional_fields_default_to_enum_members_not_none():
    f = make_finding()
    assert f.asset_type is AssetType.ALGORITHM
    assert f.primitive is CryptoPrimitive.UNKNOWN
    assert f.mode is CryptoMode.UNKNOWN
    assert f.padding is CryptoPadding.UNKNOWN
    assert f.status is CryptoStatus.UNKNOWN
    assert f.risk is RiskLevel.INFO


def test_mutable_defaults_are_not_shared_between_findings():
    a, b = make_finding(), make_finding()
    a.crypto_functions.append(CryptoFunction.DIGEST)
    a.extra["liboqs"] = "unavailable"
    assert b.crypto_functions == []
    assert b.extra == {}


def test_numeric_and_free_text_fields_default_to_none():
    f = make_finding()
    assert f.key_size is None
    assert f.curve is None
    assert f.parameter_set is None
    assert f.oid is None
    assert f.classical_security_level is None
    assert f.nist_quantum_security_level is None
    assert f.confidence == 1.0


# ---------------------------------------------------------------------- serialisation


def test_finding_round_trips_through_json():
    f = make_finding(
        primitive=CryptoPrimitive.BLOCK_CIPHER,
        mode=CryptoMode.GCM,
        crypto_functions=[CryptoFunction.ENCRYPT, CryptoFunction.TAG],
        risk=RiskLevel.HIGH,
        key_size=256,
    )
    payload = json.loads(json.dumps(f.to_dict()))

    # Enum members serialise as their bare string values, not "CryptoMode.GCM".
    assert payload["mode"] == "gcm"
    assert payload["primitive"] == "block-cipher"
    assert payload["risk"] == "high"
    assert payload["crypto_functions"] == ["encrypt", "tag"]
    assert payload["location"] == {"file": "pkg/hashes.py", "line": 12, "column": None}
    assert payload["migration_status"] == "needs_review"



# ------------------------------------------------------------------ migration status


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        (
            {"status": CryptoStatus.CLASSICAL, "primitive": CryptoPrimitive.SIGNATURE},
            MigrationStatus.QUANTUM_VULNERABLE,
        ),
        (
            {"status": CryptoStatus.CLASSICAL, "primitive": CryptoPrimitive.KEY_AGREE},
            MigrationStatus.QUANTUM_VULNERABLE,
        ),
        (
            {
                "status": CryptoStatus.CLASSICAL,
                "primitive": CryptoPrimitive.UNKNOWN,
                "purpose": CryptoPurpose.KEY_ESTABLISHMENT,
            },
            MigrationStatus.QUANTUM_VULNERABLE,
        ),
        (
            {
                "status": CryptoStatus.CLASSICAL,
                "primitive": CryptoPrimitive.BLOCK_CIPHER,
                "classical_security_level": 256,
            },
            MigrationStatus.QUANTUM_SAFE,
        ),
        (
            {
                "status": CryptoStatus.CLASSICAL,
                "primitive": CryptoPrimitive.MAC,
                "purpose": CryptoPurpose.MAC,
                "classical_security_level": 128,
            },
            MigrationStatus.QUANTUM_SAFE,
        ),
        (
            {
                "status": CryptoStatus.CLASSICAL,
                "primitive": CryptoPrimitive.BLOCK_CIPHER,
                "classical_security_level": 112,
            },
            MigrationStatus.NEEDS_REVIEW,
        ),
        (
            {
                "status": CryptoStatus.CLASSICAL,
                "primitive": CryptoPrimitive.HASH,
                "classical_security_level": None,
            },
            MigrationStatus.NEEDS_REVIEW,
        ),
        ({"status": CryptoStatus.PQC}, MigrationStatus.QUANTUM_SAFE),
        ({"status": CryptoStatus.HYBRID}, MigrationStatus.QUANTUM_SAFE),
        ({"status": CryptoStatus.UNKNOWN}, MigrationStatus.NEEDS_REVIEW),
        (
            {
                "status": CryptoStatus.CLASSICAL,
                "purpose": CryptoPurpose.DIGITAL_SIGNATURE,
                "classical_security_level": 0,
            },
            MigrationStatus.NOT_APPLICABLE,
        ),
    ],
    ids=[
        "signature",
        "key-agree",
        "key-establishment-without-primitive",
        "aes-256",
        "hmac-sha-256",
        "3des",
        "broken-hash",
        "pqc",
        "hybrid",
        "unknown",
        "no-algorithm-at-all",
    ],
)
def test_migration_status_is_derived_from_status_primitive_and_strength(overrides, expected):
    assert make_finding(**overrides).migration_status is expected


def test_migration_status_cannot_be_set_independently_of_status():
    """It is a property, so no caller can put it out of step with `status`."""
    with pytest.raises(TypeError):
        make_finding(migration_status=MigrationStatus.QUANTUM_SAFE)


def test_a_mac_is_not_treated_as_a_signature():
    """HS256 is a MAC: Grover only halves it, so it is not a PQC migration target."""
    hs256 = make_finding(
        algorithm="HMAC-SHA-256",
        purpose=CryptoPurpose.MAC,
        primitive=CryptoPrimitive.MAC,
        status=CryptoStatus.CLASSICAL,
        classical_security_level=128,
    )
    rs256 = make_finding(
        algorithm="RSA",
        purpose=CryptoPurpose.DIGITAL_SIGNATURE,
        primitive=CryptoPrimitive.SIGNATURE,
        status=CryptoStatus.CLASSICAL,
        classical_security_level=112,
    )
    assert hs256.migration_status is MigrationStatus.QUANTUM_SAFE
    assert rs256.migration_status is MigrationStatus.QUANTUM_VULNERABLE


def test_identical_findings_get_identical_ids():
    assert make_finding().finding_id == make_finding().finding_id


@pytest.mark.parametrize(
    "overrides",
    [
        {"location": SourceLocation("pkg/hashes.py", 13)},
        {"location": SourceLocation("pkg/other.py", 12)},
        {"algorithm": "SHA-1"},
        {"purpose": CryptoPurpose.MAC},
        {"detector": "other.rule"},
    ],
    ids=["line", "file", "algorithm", "purpose", "detector"],
)
def test_id_changes_when_any_identifying_field_changes(overrides):
    assert make_finding(**overrides).finding_id != make_finding().finding_id


def test_explicit_id_is_preserved():
    assert make_finding(finding_id="deadbeef").finding_id == "deadbeef"




def test_risk_rank_orders_by_severity_not_alphabetically():
    ordered = sorted(RiskLevel, key=lambda level: level.rank)
    assert ordered == [
        RiskLevel.INFO,
        RiskLevel.LOW,
        RiskLevel.MEDIUM,
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    ]


def test_max_risk_picks_most_severe_and_tolerates_empty():
    assert max_risk([RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MEDIUM]) is RiskLevel.CRITICAL
    assert max_risk([]) is RiskLevel.INFO


# -------------------------------------------------------------------------- location


def test_source_location_is_relative_and_prints_as_path_colon_line():
    loc = SourceLocation("pkg/hashes.py", 12)
    assert str(loc) == "pkg/hashes.py:12"
    assert isinstance(loc.line, int)


# ------------------------------------------------------------- CycloneDX vocabulary


def test_enum_values_match_cyclonedx():
    from cyclonedx.model import crypto as cdx

    pairs = [
        (AssetType, cdx.CryptoAssetType),
        (CryptoPrimitive, cdx.CryptoPrimitive),
        (CryptoMode, cdx.CryptoMode),
        (CryptoPadding, cdx.CryptoPadding),
        (CryptoFunction, cdx.CryptoFunction),
    ]
    for ours, theirs in pairs:
        assert {m.value for m in ours} == {m.value for m in theirs}, ours.__name__
