"""Cryptographic artifacts for the `certs/` tests.

Generated at run time rather than committed as binaries: a checked-in certificate is opaque
in review, and one with a hard-coded expiry silently rots. The whole set is built once per
session because RSA and ML-DSA key generation is the slow part.
"""

from __future__ import annotations

import datetime
from pathlib import Path

import pytest
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, mldsa, mlkem, rsa, x25519
from cryptography.x509.oid import NameOID

NOT_BEFORE = datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC)
NOT_AFTER = datetime.datetime(2029, 1, 1, tzinfo=datetime.UTC)
EXPIRED_AFTER = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
LONG_LIVED_AFTER = datetime.datetime(2040, 1, 1, tzinfo=datetime.UTC)

GOST_SIGNATURE_OID = "1.2.643.7.1.1.3.2"
SLH_DSA_SHA2_128S_OID = "2.16.840.1.101.3.4.3.20"
UNASSIGNED_KEY_OID = "1.3.6.1.4.1.99999.1.1"
RSA_SHA1_OID = "1.2.840.113549.1.1.5"


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _key_usage(**flags) -> x509.KeyUsage:
    defaults = dict.fromkeys(
        (
            "digital_signature",
            "content_commitment",
            "key_encipherment",
            "data_encipherment",
            "key_agreement",
            "key_cert_sign",
            "crl_sign",
            "encipher_only",
            "decipher_only",
        ),
        False,
    )
    defaults.update(flags)
    return x509.KeyUsage(**defaults)


def _self_signed(
    key, common_name: str, algorithm, key_usage=None, not_after=NOT_AFTER
) -> x509.Certificate:
    subject = _name(common_name)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    )
    if key_usage is not None:
        builder = builder.add_extension(key_usage, critical=True)
    return builder.sign(key, algorithm)


def _with_signature_oid(cert: x509.Certificate, oid: str) -> bytes:
    """Rewrite a certificate's signature algorithm OID, leaving the signature bytes bogus.

    The point is not a verifiable certificate but a parseable one whose algorithm identifier
    CryptoLens has never seen -- which is what a PQC certificate looks like to an older
    parser.
    """
    parsed = asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    parsed["signature_algorithm"]["algorithm"] = oid
    parsed["tbs_certificate"]["signature"]["algorithm"] = oid
    return parsed.dump(force=True)


def _with_public_key_oid(cert: x509.Certificate, oid: str) -> bytes:
    parsed = asn1_x509.Certificate.load(cert.public_bytes(serialization.Encoding.DER))
    spki = parsed["tbs_certificate"]["subject_public_key_info"]
    spki["algorithm"]["algorithm"] = oid
    return parsed.dump(force=True)


@pytest.fixture(scope="session")
def artifact_repo(tmp_path_factory) -> Path:
    root = tmp_path_factory.mktemp("artifacts")

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec_key = ec.generate_private_key(ec.SECP384R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()
    pqc_key = mldsa.MLDSA65PrivateKey.generate()
    dsa_key = dsa.generate_private_key(key_size=2048)
    x25519_key = x25519.X25519PrivateKey.generate()
    kem_key = mlkem.MLKEM768PrivateKey.generate()

    rsa_cert = _self_signed(rsa_key, "rsa.example", hashes.SHA256())
    ec_cert = _self_signed(ec_key, "ec.example", hashes.SHA256())
    ed_cert = _self_signed(ed_key, "ed25519.example", None)
    pqc_cert = _self_signed(pqc_key, "pqc.example", None)

    pem = serialization.Encoding.PEM
    der = serialization.Encoding.DER

    (root / "rsa_cert.pem").write_bytes(rsa_cert.public_bytes(pem))
    (root / "ec_cert.pem").write_bytes(ec_cert.public_bytes(pem))
    (root / "ed25519_cert.pem").write_bytes(ed_cert.public_bytes(pem))
    (root / "mldsa_cert.pem").write_bytes(pqc_cert.public_bytes(pem))
    (root / "rsa_cert.der").write_bytes(rsa_cert.public_bytes(der))
    (root / "dsa_cert.pem").write_bytes(
        _self_signed(dsa_key, "dsa.example", hashes.SHA256()).public_bytes(pem)
    )

    (root / "signing_cert.pem").write_bytes(
        _self_signed(
            rsa_key, "signing.example", hashes.SHA256(), _key_usage(digital_signature=True)
        ).public_bytes(pem)
    )
    (root / "agreement_cert.pem").write_bytes(
        _self_signed(
            ec_key, "agreement.example", hashes.SHA256(), _key_usage(key_agreement=True)
        ).public_bytes(pem)
    )
    (root / "tls_cert.pem").write_bytes(
        _self_signed(
            rsa_key,
            "tls.example",
            hashes.SHA256(),
            _key_usage(digital_signature=True, key_encipherment=True),
        ).public_bytes(pem)
    )

    (root / "expired_cert.pem").write_bytes(
        _self_signed(
            rsa_key, "expired.example", hashes.SHA256(), not_after=EXPIRED_AFTER
        ).public_bytes(pem)
    )
    (root / "long_lived_cert.pem").write_bytes(
        _self_signed(
            ec_key,
            "longlived.example",
            hashes.SHA256(),
            _key_usage(digital_signature=True),
            not_after=LONG_LIVED_AFTER,
        ).public_bytes(pem)
    )

    (root / "chain.pem").write_bytes(rsa_cert.public_bytes(pem) + ec_cert.public_bytes(pem))

    (root / "rsa_public.pem").write_bytes(
        rsa_key.public_key().public_bytes(pem, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    (root / "x25519_public.pem").write_bytes(
        x25519_key.public_key().public_bytes(
            pem, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    (root / "mlkem_public.pem").write_bytes(
        kem_key.public_key().public_bytes(
            pem, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    (root / "ec_private.key").write_bytes(
        ec_key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    (root / "ec_private.der").write_bytes(
        ec_key.private_bytes(
            der, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    (root / "encrypted.key").write_bytes(
        rsa_key.private_bytes(
            pem,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(b"hunter2"),
        )
    )

    (root / "legacy_cert.der").write_bytes(_with_signature_oid(rsa_cert, RSA_SHA1_OID))
    (root / "unknown_key_oid_cert.der").write_bytes(
        _with_public_key_oid(rsa_cert, UNASSIGNED_KEY_OID)
    )
    (root / "unknown_oid_cert.der").write_bytes(_with_signature_oid(rsa_cert, GOST_SIGNATURE_OID))
    (root / "slh_dsa_cert.der").write_bytes(
        _with_signature_oid(rsa_cert, SLH_DSA_SHA2_128S_OID)
    )

    (root / "empty.pem").write_bytes(b"")
    (root / "malformed.pem").write_bytes(
        b"-----BEGIN CERTIFICATE-----\nnot base64 at all !!\n-----END CERTIFICATE-----\n"
    )
    (root / "truncated.der").write_bytes(rsa_cert.public_bytes(der)[:64])
    (root / "garbage.key").write_bytes(bytes(range(256)))

    return root
