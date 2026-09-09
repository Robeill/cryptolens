from __future__ import annotations

from dataclasses import dataclass

from cryptolens.model import CryptoPrimitive, CryptoPurpose, CryptoStatus


@dataclass(frozen=True)
class OidEntry:
    algorithm: str
    primitive: CryptoPrimitive
    purpose: CryptoPurpose
    status: CryptoStatus = CryptoStatus.CLASSICAL
    parameter_set: str | None = None
    classical_security_level: int | None = None
    nist_quantum_security_level: int | None = None


def _rsa_sig(algorithm: str) -> OidEntry:
    return OidEntry(
        algorithm=algorithm,
        primitive=CryptoPrimitive.SIGNATURE,
        purpose=CryptoPurpose.DIGITAL_SIGNATURE,
    )


def _ecdsa_sig(algorithm: str) -> OidEntry:
    return OidEntry(
        algorithm=algorithm,
        primitive=CryptoPrimitive.SIGNATURE,
        purpose=CryptoPurpose.DIGITAL_SIGNATURE,
    )


def _ml_dsa(parameter_set: str, strength: int, category: int) -> OidEntry:
    return OidEntry(
        algorithm=parameter_set,
        primitive=CryptoPrimitive.SIGNATURE,
        purpose=CryptoPurpose.DIGITAL_SIGNATURE,
        status=CryptoStatus.PQC,
        parameter_set=parameter_set,
        classical_security_level=strength,
        nist_quantum_security_level=category,
    )


def _ml_kem(parameter_set: str, strength: int, category: int) -> OidEntry:
    return OidEntry(
        algorithm=parameter_set,
        primitive=CryptoPrimitive.KEM,
        purpose=CryptoPurpose.KEY_ESTABLISHMENT,
        status=CryptoStatus.PQC,
        parameter_set=parameter_set,
        classical_security_level=strength,
        nist_quantum_security_level=category,
    )


def _slh_dsa(parameter_set: str, strength: int, category: int) -> OidEntry:
    return OidEntry(
        algorithm=parameter_set,
        primitive=CryptoPrimitive.SIGNATURE,
        purpose=CryptoPurpose.DIGITAL_SIGNATURE,
        status=CryptoStatus.PQC,
        parameter_set=parameter_set,
        classical_security_level=strength,
        nist_quantum_security_level=category,
    )


SIGNATURE_OIDS: dict[str, OidEntry] = {
    "1.2.840.113549.1.1.4": _rsa_sig("RSA-MD5"),
    "1.2.840.113549.1.1.5": _rsa_sig("RSA-SHA-1"),
    "1.2.840.113549.1.1.14": _rsa_sig("RSA-SHA-224"),
    "1.2.840.113549.1.1.11": _rsa_sig("RSA-SHA-256"),
    "1.2.840.113549.1.1.12": _rsa_sig("RSA-SHA-384"),
    "1.2.840.113549.1.1.13": _rsa_sig("RSA-SHA-512"),
    "1.2.840.113549.1.1.10": _rsa_sig("RSASSA-PSS"),
    "2.16.840.1.101.3.4.3.13": _rsa_sig("RSA-SHA3-224"),
    "2.16.840.1.101.3.4.3.14": _rsa_sig("RSA-SHA3-256"),
    "2.16.840.1.101.3.4.3.15": _rsa_sig("RSA-SHA3-384"),
    "2.16.840.1.101.3.4.3.16": _rsa_sig("RSA-SHA3-512"),
    "1.2.840.10045.4.1": _ecdsa_sig("ECDSA-SHA-1"),
    "1.2.840.10045.4.3.1": _ecdsa_sig("ECDSA-SHA-224"),
    "1.2.840.10045.4.3.2": _ecdsa_sig("ECDSA-SHA-256"),
    "1.2.840.10045.4.3.3": _ecdsa_sig("ECDSA-SHA-384"),
    "1.2.840.10045.4.3.4": _ecdsa_sig("ECDSA-SHA-512"),
    "2.16.840.1.101.3.4.3.9": _ecdsa_sig("ECDSA-SHA3-224"),
    "2.16.840.1.101.3.4.3.10": _ecdsa_sig("ECDSA-SHA3-256"),
    "2.16.840.1.101.3.4.3.11": _ecdsa_sig("ECDSA-SHA3-384"),
    "2.16.840.1.101.3.4.3.12": _ecdsa_sig("ECDSA-SHA3-512"),
    "1.2.840.10040.4.3": OidEntry(
        "DSA-SHA-1", CryptoPrimitive.SIGNATURE, CryptoPurpose.DIGITAL_SIGNATURE
    ),
    "2.16.840.1.101.3.4.3.1": OidEntry(
        "DSA-SHA-224", CryptoPrimitive.SIGNATURE, CryptoPurpose.DIGITAL_SIGNATURE
    ),
    "2.16.840.1.101.3.4.3.2": OidEntry(
        "DSA-SHA-256", CryptoPrimitive.SIGNATURE, CryptoPurpose.DIGITAL_SIGNATURE
    ),
    "2.16.840.1.101.3.4.3.3": OidEntry(
        "DSA-SHA-384", CryptoPrimitive.SIGNATURE, CryptoPurpose.DIGITAL_SIGNATURE
    ),
    "2.16.840.1.101.3.4.3.4": OidEntry(
        "DSA-SHA-512", CryptoPrimitive.SIGNATURE, CryptoPurpose.DIGITAL_SIGNATURE
    ),
    "1.3.101.112": OidEntry(
        "Ed25519",
        CryptoPrimitive.SIGNATURE,
        CryptoPurpose.DIGITAL_SIGNATURE,
        parameter_set="Ed25519",
        classical_security_level=128,
    ),
    "1.3.101.113": OidEntry(
        "Ed448",
        CryptoPrimitive.SIGNATURE,
        CryptoPurpose.DIGITAL_SIGNATURE,
        parameter_set="Ed448",
        classical_security_level=224,
    ),
    "2.16.840.1.101.3.4.3.17": _ml_dsa("ML-DSA-44", 128, 2),
    "2.16.840.1.101.3.4.3.18": _ml_dsa("ML-DSA-65", 192, 3),
    "2.16.840.1.101.3.4.3.19": _ml_dsa("ML-DSA-87", 256, 5),
    "2.16.840.1.101.3.4.3.20": _slh_dsa("SLH-DSA-SHA2-128s", 128, 1),
    "2.16.840.1.101.3.4.3.21": _slh_dsa("SLH-DSA-SHA2-128f", 128, 1),
    "2.16.840.1.101.3.4.3.22": _slh_dsa("SLH-DSA-SHA2-192s", 192, 3),
    "2.16.840.1.101.3.4.3.23": _slh_dsa("SLH-DSA-SHA2-192f", 192, 3),
    "2.16.840.1.101.3.4.3.24": _slh_dsa("SLH-DSA-SHA2-256s", 256, 5),
    "2.16.840.1.101.3.4.3.25": _slh_dsa("SLH-DSA-SHA2-256f", 256, 5),
    "2.16.840.1.101.3.4.3.26": _slh_dsa("SLH-DSA-SHAKE-128s", 128, 1),
    "2.16.840.1.101.3.4.3.27": _slh_dsa("SLH-DSA-SHAKE-128f", 128, 1),
    "2.16.840.1.101.3.4.3.28": _slh_dsa("SLH-DSA-SHAKE-192s", 192, 3),
    "2.16.840.1.101.3.4.3.29": _slh_dsa("SLH-DSA-SHAKE-192f", 192, 3),
    "2.16.840.1.101.3.4.3.30": _slh_dsa("SLH-DSA-SHAKE-256s", 256, 5),
    "2.16.840.1.101.3.4.3.31": _slh_dsa("SLH-DSA-SHAKE-256f", 256, 5),
}

PUBLIC_KEY_OIDS: dict[str, OidEntry] = {
    "1.2.840.113549.1.1.1": OidEntry("RSA", CryptoPrimitive.PKE, CryptoPurpose.UNKNOWN),
    "1.2.840.113549.1.1.10": OidEntry(
        "RSASSA-PSS", CryptoPrimitive.SIGNATURE, CryptoPurpose.DIGITAL_SIGNATURE
    ),
    "1.2.840.10045.2.1": OidEntry("EC", CryptoPrimitive.UNKNOWN, CryptoPurpose.UNKNOWN),
    "1.2.840.10040.4.1": OidEntry(
        "DSA", CryptoPrimitive.SIGNATURE, CryptoPurpose.DIGITAL_SIGNATURE
    ),
    "1.2.840.113549.1.3.1": OidEntry(
        "DH", CryptoPrimitive.KEY_AGREE, CryptoPurpose.KEY_ESTABLISHMENT
    ),
    "1.3.101.110": OidEntry(
        "X25519",
        CryptoPrimitive.KEY_AGREE,
        CryptoPurpose.KEY_ESTABLISHMENT,
        parameter_set="X25519",
        classical_security_level=128,
    ),
    "1.3.101.111": OidEntry(
        "X448",
        CryptoPrimitive.KEY_AGREE,
        CryptoPurpose.KEY_ESTABLISHMENT,
        parameter_set="X448",
        classical_security_level=224,
    ),
    "1.3.101.112": SIGNATURE_OIDS["1.3.101.112"],
    "1.3.101.113": SIGNATURE_OIDS["1.3.101.113"],
    "2.16.840.1.101.3.4.3.17": SIGNATURE_OIDS["2.16.840.1.101.3.4.3.17"],
    "2.16.840.1.101.3.4.3.18": SIGNATURE_OIDS["2.16.840.1.101.3.4.3.18"],
    "2.16.840.1.101.3.4.3.19": SIGNATURE_OIDS["2.16.840.1.101.3.4.3.19"],
    "2.16.840.1.101.3.4.4.1": _ml_kem("ML-KEM-512", 128, 1),
    "2.16.840.1.101.3.4.4.2": _ml_kem("ML-KEM-768", 192, 3),
    "2.16.840.1.101.3.4.4.3": _ml_kem("ML-KEM-1024", 256, 5),
}

CURVE_OIDS: dict[str, tuple[str, int]] = {
    "1.2.840.10045.3.1.1": ("SECP192R1", 96),
    "1.3.132.0.33": ("SECP224R1", 112),
    "1.2.840.10045.3.1.7": ("SECP256R1", 128),
    "1.3.132.0.10": ("SECP256K1", 128),
    "1.3.132.0.34": ("SECP384R1", 192),
    "1.3.132.0.35": ("SECP521R1", 256),
    "1.3.36.3.3.2.8.1.1.7": ("brainpoolP256r1", 128),
    "1.3.36.3.3.2.8.1.1.11": ("brainpoolP384r1", 192),
    "1.3.36.3.3.2.8.1.1.13": ("brainpoolP512r1", 256),
}

CURVE_STRENGTH: dict[str, int] = {name: strength for name, strength in CURVE_OIDS.values()}


def lookup_signature(oid: str | None) -> OidEntry | None:
    return SIGNATURE_OIDS.get(oid or "")


def lookup_public_key(oid: str | None) -> OidEntry | None:
    return PUBLIC_KEY_OIDS.get(oid or "") or SIGNATURE_OIDS.get(oid or "")


def lookup_curve(oid: str | None) -> tuple[str, int] | None:
    return CURVE_OIDS.get(oid or "")
