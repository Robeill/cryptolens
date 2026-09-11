from __future__ import annotations

from enum import Enum

from cryptolens.model import CryptoMode, CryptoPadding, CryptoPurpose, RiskLevel


class Weakness(str, Enum):
    BROKEN_ALGORITHM = "broken_algorithm"
    DEPRECATED_ALGORITHM = "deprecated_algorithm"
    WEAK_KEY_SIZE = "weak_key_size"
    WEAK_CURVE = "weak_curve"
    INSECURE_MODE = "insecure_mode"
    VULNERABLE_PADDING = "vulnerable_padding"
    VERIFICATION_DISABLED = "verification_disabled"
    NO_ALGORITHM = "no_algorithm"
    UNIDENTIFIED_ALGORITHM = "unidentified_algorithm"
    EXPIRED_CERTIFICATE = "expired_certificate"
    EXPIRING_CERTIFICATE = "expiring_certificate"
    OUTLIVES_QUANTUM_DEADLINE = "outlives_quantum_deadline"
    HARVEST_NOW_DECRYPT_LATER = "harvest_now_decrypt_later"
    QUANTUM_VULNERABLE_SIGNATURE = "quantum_vulnerable_signature"
    QUANTUM_VULNERABLE_UNKNOWN_PURPOSE = "quantum_vulnerable_unknown_purpose"


BROKEN_ALGORITHMS: dict[str, tuple[RiskLevel, Weakness, str]] = {
    "MD2": (RiskLevel.CRITICAL, Weakness.BROKEN_ALGORITHM, "MD2 is broken beyond repair."),
    "MD4": (RiskLevel.CRITICAL, Weakness.BROKEN_ALGORITHM, "MD4 is broken beyond repair."),
    "MD5": (
        RiskLevel.HIGH,
        Weakness.BROKEN_ALGORITHM,
        "MD5 collisions are computable in seconds on ordinary hardware.",
    ),
    "SHA-1": (
        RiskLevel.HIGH,
        Weakness.BROKEN_ALGORITHM,
        (
            "SHA-1 collisions have been demonstrated (SHAttered, 2017) and chosen-prefix "
            "collisions since 2020."
        ),
    ),
    "RIPEMD-160": (
        RiskLevel.MEDIUM,
        Weakness.DEPRECATED_ALGORITHM,
        "RIPEMD-160 is unbroken but its 160-bit output leaves an 80-bit collision margin.",
    ),
    "DES": (
        RiskLevel.CRITICAL,
        Weakness.BROKEN_ALGORITHM,
        "Single DES has a 56-bit key and is exhaustively searchable.",
    ),
    "3DES": (
        RiskLevel.MEDIUM,
        Weakness.DEPRECATED_ALGORITHM,
        (
            "3DES has a 64-bit block, which makes it vulnerable to Sweet32; NIST disallowed it "
            "after 2023."
        ),
    ),
    "RC4": (
        RiskLevel.CRITICAL,
        Weakness.BROKEN_ALGORITHM,
        "RC4 keystream biases allow plaintext recovery; prohibited in TLS by RFC 7465.",
    ),
    "RC2": (RiskLevel.HIGH, Weakness.BROKEN_ALGORITHM, "RC2 is a 64-bit block cipher, broken."),
    "Blowfish": (
        RiskLevel.MEDIUM,
        Weakness.DEPRECATED_ALGORITHM,
        (
            "Blowfish has a 64-bit block and is vulnerable to Sweet32; its author recommends "
            "against it."
        ),
    ),
    "IDEA": (
        RiskLevel.MEDIUM,
        Weakness.DEPRECATED_ALGORITHM,
        "IDEA has a 64-bit block and is no longer recommended.",
    ),
    "CAST5": (
        RiskLevel.MEDIUM,
        Weakness.DEPRECATED_ALGORITHM,
        "CAST5 has a 64-bit block and is no longer recommended.",
    ),
    "none": (
        RiskLevel.CRITICAL,
        Weakness.NO_ALGORITHM,
        "The token is accepted with no signature at all; anyone can forge one.",
    ),
}

SIGNATURE_COMPOSITE_PREFIXES: frozenset[str] = frozenset({"RSA", "ECDSA", "DSA"})

INSECURE_MODES: dict[CryptoMode, tuple[RiskLevel, str]] = {
    CryptoMode.ECB: (
        RiskLevel.HIGH,
        (
            "ECB encrypts identical plaintext blocks to identical ciphertext blocks, so it "
            "leaks structure."
        ),
    ),
}

VULNERABLE_PADDINGS: dict[CryptoPadding, tuple[RiskLevel, frozenset[CryptoPurpose], str]] = {
    CryptoPadding.PKCS1V15: (
        RiskLevel.HIGH,
        frozenset({CryptoPurpose.ENCRYPTION, CryptoPurpose.KEY_ESTABLISHMENT}),
        (
            "PKCS#1 v1.5 encryption padding is vulnerable to Bleichenbacher oracle attacks; "
            "use OAEP."
        ),
    ),
}

DISABLED_VERIFICATION_DETECTORS: frozenset[str] = frozenset(
    {
        "jwt.verification_disabled",
        "ssl.verification_disabled",
        "ssl.hostname_check_disabled",
        "ssl.unverified_context",
    }
)

RSA_KEY_SIZE_THRESHOLDS: tuple[tuple[int, RiskLevel, str], ...] = (
    (1024, RiskLevel.CRITICAL, "RSA keys below 1024 bits are trivially factorable."),
    (
        2048,
        RiskLevel.HIGH,
        (
            "RSA-1024 is factorable by a well-resourced attacker; NIST disallowed it "
            "after 2013."
        ),
    ),
    (
        3072,
        RiskLevel.INFO,
        "RSA-2048 gives 112-bit classical security, which NIST deprecates after 2030.",
    ),
)

MINIMUM_CURVE_STRENGTH = 128

QUANTUM_RISK: dict[CryptoPurpose, tuple[RiskLevel, Weakness, str]] = {
    CryptoPurpose.KEY_ESTABLISHMENT: (
        RiskLevel.HIGH,
        Weakness.HARVEST_NOW_DECRYPT_LATER,
        (
            "Traffic protected by this key exchange can be recorded today and decrypted once a "
            "quantum computer exists, so the exposure has already begun."
        ),
    ),
    CryptoPurpose.ENCRYPTION: (
        RiskLevel.HIGH,
        Weakness.HARVEST_NOW_DECRYPT_LATER,
        "Data encrypted to this public key can be recorded today and decrypted later.",
    ),
    CryptoPurpose.DIGITAL_SIGNATURE: (
        RiskLevel.MEDIUM,
        Weakness.QUANTUM_VULNERABLE_SIGNATURE,
        (
            "A signature can only be forged once an attacker has a quantum computer, so the "
            "deadline is the lifetime of what it signs rather than today."
        ),
    ),
}

QUANTUM_RISK_UNKNOWN_PURPOSE = (
    RiskLevel.MEDIUM,
    Weakness.QUANTUM_VULNERABLE_UNKNOWN_PURPOSE,
    (
        "This key is quantum-vulnerable, but its purpose could not be determined, so the "
        "urgency cannot be settled from the source alone."
    ),
)

NEEDS_REVIEW_RISK = (
    RiskLevel.LOW,
    Weakness.UNIDENTIFIED_ALGORITHM,
    "The algorithm could not be identified well enough to rule on its quantum exposure.",
)
