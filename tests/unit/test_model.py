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
    assert f.migration_status is MigrationStatus.NEEDS_REVIEW


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
