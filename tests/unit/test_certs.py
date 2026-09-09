"""Certificate and key parsing, and the OID fallback that keeps it working on unknown input."""

from __future__ import annotations

import pytest
from cryptography import x509

from cryptolens.certs import parser as certs
from cryptolens.certs.oids import (
    CURVE_OIDS,
    PUBLIC_KEY_OIDS,
    SIGNATURE_OIDS,
    lookup_curve,
    lookup_public_key,
    lookup_signature,
)
from cryptolens.model import (
    AssetType,
    CryptoPrimitive,
    CryptoPurpose,
    CryptoStatus,
    MigrationStatus,
)


def parse(root, name):
    return certs.parse_artifact(root / name, root)


def only(findings, asset_type):
    matched = [f for f in findings if f.asset_type is asset_type]
    assert len(matched) == 1, f"expected exactly one {asset_type}, got {len(matched)}"
    return matched[0]


# ------------------------------------------------------------------- the OID table


def test_every_oid_entry_has_a_normalised_algorithm_name():
    for table in (SIGNATURE_OIDS, PUBLIC_KEY_OIDS):
        for oid, entry in table.items():
            assert entry.algorithm, oid
            assert entry.algorithm == entry.algorithm.strip()


def test_pqc_entries_carry_a_status_and_a_nist_category():
    pqc = [e for e in SIGNATURE_OIDS.values() if e.status is CryptoStatus.PQC]
    assert pqc
    for entry in pqc:
        assert entry.nist_quantum_security_level in {1, 2, 3, 5}
        assert entry.parameter_set == entry.algorithm


def test_ml_kem_is_a_kem_and_ml_dsa_is_a_signature():
    assert lookup_public_key("2.16.840.1.101.3.4.4.2").primitive is CryptoPrimitive.KEM
    assert lookup_public_key("2.16.840.1.101.3.4.3.18").primitive is CryptoPrimitive.SIGNATURE


def test_unknown_oids_resolve_to_none_rather_than_raising():
    assert lookup_signature("1.2.3.4.5.6.7.8") is None
    assert lookup_public_key(None) is None
    assert lookup_curve("") is None


def test_curve_oids_agree_with_asn1crypto():
    from asn1crypto.keys import NamedCurve

    for oid, (name, _strength) in CURVE_OIDS.items():
        assert NamedCurve._map[oid].lower() == name.lower()


def test_signature_oids_agree_with_cryptography():
    from cryptography.hazmat._oid import SignatureAlgorithmOID as Upstream

    known = {
        getattr(Upstream, n).dotted_string
        for n in dir(Upstream)
        if not n.startswith("_") and n not in {"UNSIGNED"}
    }
    gost = {"1.2.643.7.1.1.3.2", "1.2.643.7.1.1.3.3", "1.2.643.2.2.3"}
    assert (known - gost) <= set(SIGNATURE_OIDS)


# --------------------------------------------------------------------- certificates


def test_rsa_certificate_yields_a_certificate_and_a_signature_finding(artifact_repo):
    findings = parse(artifact_repo, "rsa_cert.pem")
    assert len(findings) == 2

    cert = only(findings, AssetType.CERTIFICATE)
    assert cert.algorithm == "RSA"
    assert cert.key_size == 2048
    assert cert.classical_security_level == 112
    assert cert.migration_status is MigrationStatus.QUANTUM_VULNERABLE
    assert cert.confidence == 1.0

    signature = only(findings, AssetType.ALGORITHM)
    assert signature.algorithm == "RSA-SHA-256"
    assert signature.purpose is CryptoPurpose.DIGITAL_SIGNATURE
    assert signature.oid == "1.2.840.113549.1.1.11"


def test_certificate_metadata_is_recorded(artifact_repo):
    cert = only(parse(artifact_repo, "rsa_cert.pem"), AssetType.CERTIFICATE)
    assert cert.extra["subject"] == "CN=rsa.example"
    assert cert.extra["issuer"] == "CN=rsa.example"
    assert cert.extra["is_ca"] is True
    assert cert.extra["not_before"].startswith("2024-01-01")
    assert cert.extra["not_after"].startswith("2030-01-01")
    assert cert.extra["serial_number"]


def test_findings_do_not_depend_on_the_current_date(artifact_repo):
    """No `expired` flag: a finding must be reproducible, so 'now' belongs to the risk engine."""
    cert = only(parse(artifact_repo, "rsa_cert.pem"), AssetType.CERTIFICATE)
    assert "expired" not in cert.extra
    assert parse(artifact_repo, "rsa_cert.pem")[0].finding_id == cert.finding_id


def test_ec_certificate_records_its_curve(artifact_repo):
    cert = only(parse(artifact_repo, "ec_cert.pem"), AssetType.CERTIFICATE)
    assert cert.algorithm == "EC"
    assert cert.curve == "SECP384R1"
    assert cert.parameter_set == "SECP384R1"
    assert cert.classical_security_level == 192
    assert cert.migration_status is MigrationStatus.QUANTUM_VULNERABLE


def test_ed25519_certificate_is_recognised(artifact_repo):
    cert = only(parse(artifact_repo, "ed25519_cert.pem"), AssetType.CERTIFICATE)
    assert cert.algorithm == "Ed25519"
    assert cert.primitive is CryptoPrimitive.SIGNATURE
    assert cert.migration_status is MigrationStatus.QUANTUM_VULNERABLE


def test_sha1_signed_certificate_is_named_precisely(artifact_repo):
    """`cryptography` 50 refuses to *sign* with SHA-1, so this OID is grafted on. Real CAs
    issued millions of these and they are still in circulation, so reading them matters."""
    signature = only(parse(artifact_repo, "legacy_cert.der"), AssetType.ALGORITHM)
    assert signature.algorithm == "RSA-SHA-1"


def test_der_and_pem_encodings_of_one_certificate_agree(artifact_repo):
    from_pem = only(parse(artifact_repo, "rsa_cert.pem"), AssetType.CERTIFICATE)
    from_der = only(parse(artifact_repo, "rsa_cert.der"), AssetType.CERTIFICATE)
    assert from_pem.algorithm == from_der.algorithm
    assert from_pem.key_size == from_der.key_size
    assert from_pem.extra["subject"] == from_der.extra["subject"]


def test_a_pem_bundle_yields_every_certificate_in_it(artifact_repo):
    findings = parse(artifact_repo, "chain.pem")
    certificates = [f for f in findings if f.asset_type is AssetType.CERTIFICATE]
    assert {c.algorithm for c in certificates} == {"RSA", "EC"}
    assert len(findings) == 4


# ----------------------------------------------------------------- post-quantum


def test_an_ml_dsa_certificate_is_reported_as_quantum_safe(artifact_repo):
    findings = parse(artifact_repo, "mldsa_cert.pem")
    cert = only(findings, AssetType.CERTIFICATE)
    assert cert.algorithm == "ML-DSA-65"
    assert cert.status is CryptoStatus.PQC
    assert cert.nist_quantum_security_level == 3
    assert cert.migration_status is MigrationStatus.QUANTUM_SAFE

    signature = only(findings, AssetType.ALGORITHM)
    assert signature.algorithm == "ML-DSA-65"
    assert signature.migration_status is MigrationStatus.QUANTUM_SAFE


def test_an_slh_dsa_oid_resolves_from_the_table_alone(artifact_repo):
    """`cryptography` cannot parse SLH-DSA at all; the OID table is the only thing that can."""
    signature = only(parse(artifact_repo, "slh_dsa_cert.der"), AssetType.ALGORITHM)
    assert signature.algorithm == "SLH-DSA-SHA2-128s"
    assert signature.status is CryptoStatus.PQC
    assert signature.migration_status is MigrationStatus.QUANTUM_SAFE


# ------------------------------------------------------------ standalone key files


def test_public_key_file_is_related_crypto_material(artifact_repo):
    finding = only(parse(artifact_repo, "rsa_public.pem"), AssetType.RELATED_CRYPTO_MATERIAL)
    assert finding.algorithm == "RSA"
    assert finding.key_size == 2048
    assert finding.extra["artifact"] == "public-key"


def test_private_key_file_is_read_through_its_public_half(artifact_repo):
    finding = only(parse(artifact_repo, "ec_private.key"), AssetType.RELATED_CRYPTO_MATERIAL)
    assert finding.algorithm == "EC"
    assert finding.curve == "SECP384R1"
    assert finding.extra["artifact"] == "private-key"


def test_encrypted_private_key_is_recorded_without_being_opened(artifact_repo):
    finding = only(parse(artifact_repo, "encrypted.key"), AssetType.RELATED_CRYPTO_MATERIAL)
    assert finding.algorithm == "unknown"
    assert finding.detector == "certs.opaque"
    assert finding.confidence == certs.CONFIDENCE_UNKNOWN_OID


def test_dsa_certificate_is_recognised(artifact_repo):
    cert = only(parse(artifact_repo, "dsa_cert.pem"), AssetType.CERTIFICATE)
    assert cert.algorithm == "DSA"
    assert cert.key_size == 2048
    assert cert.migration_status is MigrationStatus.QUANTUM_VULNERABLE


def test_x25519_key_is_key_establishment_not_signing(artifact_repo):
    """X25519 and Ed25519 share a curve and nothing else. The urgency differs: recorded
    key-establishment traffic can be decrypted retroactively."""
    finding = only(parse(artifact_repo, "x25519_public.pem"), AssetType.RELATED_CRYPTO_MATERIAL)
    assert finding.algorithm == "X25519"
    assert finding.primitive is CryptoPrimitive.KEY_AGREE
    assert finding.purpose is CryptoPurpose.KEY_ESTABLISHMENT
    assert finding.migration_status is MigrationStatus.QUANTUM_VULNERABLE


def test_ml_kem_key_is_a_quantum_safe_kem(artifact_repo):
    finding = only(parse(artifact_repo, "mlkem_public.pem"), AssetType.RELATED_CRYPTO_MATERIAL)
    assert finding.algorithm == "ML-KEM-768"
    assert finding.primitive is CryptoPrimitive.KEM
    assert finding.purpose is CryptoPurpose.KEY_ESTABLISHMENT
    assert finding.status is CryptoStatus.PQC
    assert finding.migration_status is MigrationStatus.QUANTUM_SAFE


def test_private_keys_fall_back_to_the_oid_table_too(artifact_repo, monkeypatch):
    from cryptography.hazmat.primitives import serialization

    def refuse(*_args, **_kwargs):
        raise ValueError("simulating a build that cannot load this key")

    monkeypatch.setattr(serialization, "load_der_private_key", refuse)
    finding = only(parse(artifact_repo, "ec_private.key"), AssetType.RELATED_CRYPTO_MATERIAL)
    assert finding.algorithm == "EC"
    assert finding.curve == "SECP384R1"
    assert finding.confidence == certs.CONFIDENCE_OID_TABLE


def test_a_bare_der_key_is_identified_without_a_pem_label(artifact_repo):
    """DER has no armour to say what it is, so the parser tries certificate, then public key,
    then private key, and keeps the first that reads."""
    finding = only(parse(artifact_repo, "ec_private.der"), AssetType.RELATED_CRYPTO_MATERIAL)
    assert finding.algorithm == "EC"
    assert finding.curve == "SECP384R1"


def test_an_unreadable_key_falls_back_rather_than_giving_up(artifact_repo, monkeypatch):
    """`cryptography` parses certificates lazily: it can load the certificate and then fail on
    `public_key()`. That is one parser failing, not the file being unreadable."""
    monkeypatch.setattr(certs, "_public_key", lambda _cert: None)
    cert = only(parse(artifact_repo, "rsa_cert.pem"), AssetType.CERTIFICATE)
    assert cert.algorithm == "RSA"
    assert cert.key_size == 2048
    assert cert.confidence == certs.CONFIDENCE_OID_TABLE


def test_a_certificate_survives_both_parsers_failing_on_its_key(artifact_repo, monkeypatch):
    """The subject, the validity window and the signature algorithm are still worth reporting."""
    monkeypatch.setattr(certs, "_public_key", lambda _cert: None)
    monkeypatch.setattr(certs, "_raw_spki", lambda _tbs: None)
    findings = parse(artifact_repo, "rsa_cert.pem")
    cert = only(findings, AssetType.CERTIFICATE)
    assert cert.algorithm == "unknown"
    assert cert.status is CryptoStatus.UNKNOWN
    assert cert.confidence == certs.CONFIDENCE_UNKNOWN_OID
    assert cert.extra["subject"] == "CN=rsa.example"
    assert only(findings, AssetType.ALGORITHM).algorithm == "RSA-SHA-256"


# --------------------------------------------------------------- unknown and broken


def test_unknown_signature_oid_is_still_reported(artifact_repo):
    findings = parse(artifact_repo, "unknown_oid_cert.der")
    signature = only(findings, AssetType.ALGORITHM)
    assert signature.algorithm == "unknown"
    assert signature.oid == "1.2.643.7.1.1.3.2"
    assert signature.status is CryptoStatus.UNKNOWN
    assert signature.confidence == certs.CONFIDENCE_UNKNOWN_OID
    assert signature.migration_status is MigrationStatus.NEEDS_REVIEW

    assert only(findings, AssetType.CERTIFICATE).algorithm == "RSA"


def test_unknown_public_key_oid_is_recorded_rather_than_dropped(artifact_repo):
    """The OID is the only durable fact about an algorithm nobody has taught us yet."""
    cert = only(parse(artifact_repo, "unknown_key_oid_cert.der"), AssetType.CERTIFICATE)
    assert cert.algorithm == "unknown"
    assert cert.oid == "1.3.6.1.4.1.99999.1.1"
    assert cert.status is CryptoStatus.UNKNOWN
    assert cert.confidence == certs.CONFIDENCE_UNKNOWN_OID
    assert cert.migration_status is MigrationStatus.NEEDS_REVIEW
    assert cert.extra["parser"] == "asn1crypto"


@pytest.mark.parametrize(
    "name",
    ["empty.pem", "malformed.pem", "truncated.der", "garbage.key"],
    ids=["empty", "malformed-pem", "truncated-der", "random-bytes"],
)
def test_unreadable_artifacts_are_skipped_without_raising(artifact_repo, name):
    assert parse(artifact_repo, name) == []


def test_a_missing_file_is_a_clean_skip(artifact_repo):
    assert certs.parse_artifact(artifact_repo / "does_not_exist.pem", artifact_repo) == []


def test_an_oversized_artifact_is_skipped(artifact_repo, monkeypatch, tmp_path):
    big = tmp_path / "huge.pem"
    big.write_bytes(b"-----BEGIN CERTIFICATE-----\n")
    monkeypatch.setattr(certs, "MAX_ARTIFACT_BYTES", 4)
    assert certs.parse_artifact(big, tmp_path) == []


# ------------------------------------------------------- the asn1crypto fallback path


@pytest.fixture
def without_pyca_certificates(monkeypatch):
    def refuse(*_args, **_kwargs):
        raise ValueError("simulating a cryptography build that cannot parse this")

    monkeypatch.setattr(x509, "load_der_x509_certificate", refuse)


def test_certificates_still_parse_when_cryptography_cannot(
    artifact_repo, without_pyca_certificates
):
    findings = parse(artifact_repo, "rsa_cert.pem")
    cert = only(findings, AssetType.CERTIFICATE)
    assert cert.algorithm == "RSA"
    assert cert.key_size == 2048
    assert cert.extra["parser"] == "asn1crypto"
    assert cert.confidence == certs.CONFIDENCE_OID_TABLE

    signature = only(findings, AssetType.ALGORITHM)
    assert signature.algorithm == "RSA-SHA-256"


def test_the_fallback_still_finds_the_curve(artifact_repo, without_pyca_certificates):
    cert = only(parse(artifact_repo, "ec_cert.pem"), AssetType.CERTIFICATE)
    assert cert.algorithm == "EC"
    assert cert.curve == "SECP384R1"
    assert cert.classical_security_level == 192


def test_the_fallback_reads_an_ml_dsa_certificate_from_its_oid(
    artifact_repo, without_pyca_certificates
):
    """This is the forward-compatibility claim: no PQC support in the parser, still detected."""
    cert = only(parse(artifact_repo, "mldsa_cert.pem"), AssetType.CERTIFICATE)
    assert cert.algorithm == "ML-DSA-65"
    assert cert.status is CryptoStatus.PQC
    assert cert.migration_status is MigrationStatus.QUANTUM_SAFE


def test_the_fallback_degrades_to_a_skip_on_rubbish(artifact_repo, without_pyca_certificates):
    assert parse(artifact_repo, "truncated.der") == []
