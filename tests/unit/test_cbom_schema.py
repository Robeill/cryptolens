"""Definition of done for Step 11 is schema validation, not output.

Every `AssetType`, every `CryptoPrimitive`, every `CryptoMode`, every `CryptoPadding` and
every `CryptoFunction` in CryptoLens' vocabulary is pushed through the generator and
validated against the CycloneDX schema bundled with `cyclonedx-python-lib`. No network.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import UUID

import pytest
from cyclonedx.schema import SchemaVersion

from cryptolens.cbom import aggregate, build_bom, generate, to_json, validate
from cryptolens.model import (
    AssetType,
    CryptoFinding,
    CryptoFunction,
    CryptoMode,
    CryptoPadding,
    CryptoPrimitive,
    CryptoPurpose,
    CryptoStatus,
    SourceLocation,
)

SERIAL = UUID("11111111-2222-3333-4444-555555555555")
STAMP = datetime(2026, 9, 10, tzinfo=UTC)

SCHEMA_VERSIONS = [SchemaVersion.V1_6, SchemaVersion.V1_7]


def finding(**overrides) -> CryptoFinding:
    kwargs = {
        "algorithm": "AES-256",
        "location": SourceLocation("pkg/a.py", 1),
        "purpose": CryptoPurpose.ENCRYPTION,
        "evidence": "Cipher(algorithms.AES256(key), modes.GCM(iv))",
        "primitive": CryptoPrimitive.BLOCK_CIPHER,
        "mode": CryptoMode.GCM,
        "status": CryptoStatus.CLASSICAL,
        "key_size": 256,
        "classical_security_level": 256,
    }
    kwargs.update(overrides)
    return CryptoFinding(**kwargs)


def document(findings, schema_version=SchemaVersion.V1_6) -> str:
    bom = build_bom(
        aggregate(findings), target_name="fixture", serial_number=SERIAL, timestamp=STAMP
    )
    return to_json(bom, schema_version)


# --------------------------------------------------------------- the vocabulary matrix


@pytest.mark.parametrize("schema_version", SCHEMA_VERSIONS, ids=lambda v: v.name)
@pytest.mark.parametrize("primitive", list(CryptoPrimitive), ids=lambda p: p.value)
def test_every_primitive_validates(primitive, schema_version):
    assert validate(document([finding(primitive=primitive)], schema_version), schema_version) is None


@pytest.mark.parametrize("schema_version", SCHEMA_VERSIONS, ids=lambda v: v.name)
@pytest.mark.parametrize("mode", list(CryptoMode), ids=lambda m: m.value)
def test_every_mode_validates(mode, schema_version):
    assert validate(document([finding(mode=mode)], schema_version), schema_version) is None


@pytest.mark.parametrize("padding", list(CryptoPadding), ids=lambda p: p.value)
def test_every_padding_validates(padding):
    assert validate(document([finding(padding=padding)])) is None


@pytest.mark.parametrize("function", list(CryptoFunction), ids=lambda f: f.value)
def test_every_crypto_function_validates(function):
    assert validate(document([finding(crypto_functions=[function])])) is None


@pytest.mark.parametrize("schema_version", SCHEMA_VERSIONS, ids=lambda v: v.name)
@pytest.mark.parametrize("asset_type", list(AssetType), ids=lambda a: a.value)
def test_every_asset_type_validates(asset_type, schema_version):
    extra = {
        AssetType.CERTIFICATE: {
            "subject": "CN=example",
            "issuer": "CN=issuer",
            "serial_number": "0a",
            "not_before": "2024-01-01T00:00:00+00:00",
            "not_after": "2030-01-01T00:00:00+00:00",
        },
        AssetType.RELATED_CRYPTO_MATERIAL: {"artifact": "private-key"},
    }.get(asset_type, {})
    candidate = finding(asset_type=asset_type, extra=extra)
    assert validate(document([candidate], schema_version), schema_version) is None


def test_the_whole_vocabulary_in_one_document():
    """Not one asset type at a time -- all of them, plus every primitive, in a single BOM."""
    findings = [
        finding(primitive=primitive, algorithm=f"ALG-{primitive.value}")
        for primitive in CryptoPrimitive
    ]
    findings += [
        finding(
            asset_type=AssetType.CERTIFICATE,
            algorithm="RSA",
            extra={"subject": "CN=a", "serial_number": "01",
                   "not_after": "2030-01-01T00:00:00+00:00"},
        ),
        finding(asset_type=AssetType.PROTOCOL, algorithm="TLS", parameter_set="1.3"),
        finding(
            asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
            algorithm="RSA",
            extra={"artifact": "public-key"},
        ),
    ]
    doc = document(findings)
    assert validate(doc) is None
    payload = json.loads(doc)
    kinds = {c["cryptoProperties"]["assetType"] for c in payload["components"]}
    assert kinds == {a.value for a in AssetType}


# -------------------------------------------------------------------- document shape


def test_the_document_names_its_schema_and_the_tool():
    payload = json.loads(document([finding()]))
    assert payload["specVersion"] == "1.6"
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["serialNumber"] == f"urn:uuid:{SERIAL}"
    tools = payload["metadata"]["tools"]["components"]
    assert any(tool["name"] == "cryptolens" for tool in tools)


def test_the_document_describes_a_target():
    payload = json.loads(document([finding()]))
    assert payload["metadata"]["component"]["name"] == "fixture"
    assert payload["dependencies"]


def test_each_component_is_a_cryptographic_asset_with_a_stable_ref():
    payload = json.loads(document([finding(), finding(algorithm="MD5")]))
    for component in payload["components"]:
        assert component["type"] == "cryptographic-asset"
        assert component["bom-ref"].startswith("crypto/")
    refs = [c["bom-ref"] for c in payload["components"]]
    assert len(refs) == len(set(refs))


def test_algorithm_fields_are_copied_straight_through():
    """Step 2 mirrored the CycloneDX vocabulary so that this would be a field copy."""
    payload = json.loads(
        document(
            [
                finding(
                    algorithm="ECDSA",
                    primitive=CryptoPrimitive.SIGNATURE,
                    purpose=CryptoPurpose.DIGITAL_SIGNATURE,
                    mode=CryptoMode.UNKNOWN,
                    padding=CryptoPadding.UNKNOWN,
                    curve="SECP384R1",
                    parameter_set="SECP384R1",
                    classical_security_level=192,
                    crypto_functions=[CryptoFunction.SIGN, CryptoFunction.VERIFY],
                    key_size=None,
                )
            ]
        )
    )
    properties = payload["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert properties["primitive"] == "signature"
    assert properties["curve"] == "SECP384R1"
    assert properties["classicalSecurityLevel"] == 192
    assert properties["cryptoFunctions"] == ["sign", "verify"]
    assert "parameterSetIdentifier" not in properties


def test_a_pqc_asset_reports_its_parameter_set_and_nist_category():
    payload = json.loads(
        document(
            [
                finding(
                    algorithm="ML-KEM-768",
                    primitive=CryptoPrimitive.KEM,
                    purpose=CryptoPurpose.KEY_ESTABLISHMENT,
                    mode=CryptoMode.UNKNOWN,
                    parameter_set="ML-KEM-768",
                    status=CryptoStatus.PQC,
                    nist_quantum_security_level=3,
                    key_size=None,
                    classical_security_level=192,
                )
            ]
        )
    )
    properties = payload["components"][0]["cryptoProperties"]["algorithmProperties"]
    assert properties["parameterSetIdentifier"] == "ML-KEM-768"
    assert properties["nistQuantumSecurityLevel"] == 3


def test_an_oid_reaches_the_document():
    payload = json.loads(document([finding(oid="1.2.840.113549.1.1.11")]))
    assert payload["components"][0]["cryptoProperties"]["oid"] == "1.2.840.113549.1.1.11"


def test_the_occurrence_count_is_visible_to_a_reader():
    payload = json.loads(document([finding(), finding(evidence="second call")]))
    assert "2 places" in payload["components"][0]["description"]


# ------------------------------------------------------------------------ determinism


def test_two_runs_of_the_same_scan_produce_identical_bytes():
    findings = [finding(), finding(algorithm="MD5", primitive=CryptoPrimitive.HASH)]
    assert document(findings) == document(list(reversed(findings)))


def test_generate_is_a_shorthand_for_build_and_serialise():
    findings = [finding()]
    direct = generate(
        findings and aggregate(findings), target_name="fixture", serial_number=SERIAL,
        timestamp=STAMP,
    )
    assert direct == document(findings)


def test_an_empty_scan_still_produces_a_valid_document():
    doc = document([])
    assert validate(doc) is None
    assert json.loads(doc).get("components", []) == []


def test_an_unreadable_certificate_date_is_left_out_rather_than_fatal():
    doc = document(
        [
            finding(
                asset_type=AssetType.CERTIFICATE,
                extra={"subject": "CN=a", "not_after": "sometime next year"},
            )
        ]
    )
    assert validate(doc) is None
    properties = json.loads(doc)["components"][0]["cryptoProperties"]["certificateProperties"]
    assert "notValidAfter" not in properties


# -------------------------------------------------------------------------- validation


def test_the_validator_rejects_a_broken_document():
    """Proof that the validation in every other test is doing something."""
    assert validate('{"bomFormat": "CycloneDX"}') is not None


def test_validation_needs_no_network():
    """The schemas ship inside cyclonedx-python-lib; confirm the path exists on disk."""
    from pathlib import Path

    import cyclonedx.schema

    bundled = Path(cyclonedx.schema.__file__).parent / "_res"
    assert bundled.is_dir()
    assert any(bundled.glob("bom-1.6*.schema.json"))
