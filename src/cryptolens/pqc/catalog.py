from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from cryptolens.model import (
    CryptoFinding,
    CryptoPrimitive,
    CryptoPurpose,
    MigrationStatus,
)


class StandardStatus(str, Enum):
    STANDARDISED = "standardised"
    DRAFT = "draft"
    SELECTED = "selected"


@dataclass(frozen=True)
class Mechanism:
    name: str
    family: str
    purpose: CryptoPurpose
    primitive: CryptoPrimitive
    nist_quantum_security_level: int
    classical_security_level: int
    standard: str
    standard_status: StandardStatus
    rationale: str
    liboqs_name: str | None = None


ML_KEM_512 = Mechanism(
    name="ML-KEM-512",
    family="ML-KEM",
    purpose=CryptoPurpose.KEY_ESTABLISHMENT,
    primitive=CryptoPrimitive.KEM,
    nist_quantum_security_level=1,
    classical_security_level=128,
    standard="FIPS 203",
    standard_status=StandardStatus.STANDARDISED,
    rationale="Lattice KEM, the smallest standardised parameter set.",
    liboqs_name="ML-KEM-512",
)

ML_KEM_768 = Mechanism(
    name="ML-KEM-768",
    family="ML-KEM",
    purpose=CryptoPurpose.KEY_ESTABLISHMENT,
    primitive=CryptoPrimitive.KEM,
    nist_quantum_security_level=3,
    classical_security_level=192,
    standard="FIPS 203",
    standard_status=StandardStatus.STANDARDISED,
    rationale=(
        "Lattice KEM standardised in FIPS 203 and the de facto default for TLS; "
        "deploy as the hybrid X25519MLKEM768 during the transition."
    ),
    liboqs_name="ML-KEM-768",
)

ML_KEM_1024 = Mechanism(
    name="ML-KEM-1024",
    family="ML-KEM",
    purpose=CryptoPurpose.KEY_ESTABLISHMENT,
    primitive=CryptoPrimitive.KEM,
    nist_quantum_security_level=5,
    classical_security_level=256,
    standard="FIPS 203",
    standard_status=StandardStatus.STANDARDISED,
    rationale=(
        "Lattice KEM at the highest standardised category; required by CNSA 2.0 for "
        "national security systems."
    ),
    liboqs_name="ML-KEM-1024",
)

ML_DSA_44 = Mechanism(
    name="ML-DSA-44",
    family="ML-DSA",
    purpose=CryptoPurpose.DIGITAL_SIGNATURE,
    primitive=CryptoPrimitive.SIGNATURE,
    nist_quantum_security_level=2,
    classical_security_level=128,
    standard="FIPS 204",
    standard_status=StandardStatus.STANDARDISED,
    rationale="Lattice signature, the smallest standardised parameter set.",
    liboqs_name="ML-DSA-44",
)

ML_DSA_65 = Mechanism(
    name="ML-DSA-65",
    family="ML-DSA",
    purpose=CryptoPurpose.DIGITAL_SIGNATURE,
    primitive=CryptoPrimitive.SIGNATURE,
    nist_quantum_security_level=3,
    classical_security_level=192,
    standard="FIPS 204",
    standard_status=StandardStatus.STANDARDISED,
    rationale=(
        "Lattice signature standardised in FIPS 204; the general-purpose default, with "
        "fast signing and verification."
    ),
    liboqs_name="ML-DSA-65",
)

ML_DSA_87 = Mechanism(
    name="ML-DSA-87",
    family="ML-DSA",
    purpose=CryptoPurpose.DIGITAL_SIGNATURE,
    primitive=CryptoPrimitive.SIGNATURE,
    nist_quantum_security_level=5,
    classical_security_level=256,
    standard="FIPS 204",
    standard_status=StandardStatus.STANDARDISED,
    rationale=(
        "Lattice signature at the highest standardised category; required by CNSA 2.0 for "
        "national security systems."
    ),
    liboqs_name="ML-DSA-87",
)

SLH_DSA_128S = Mechanism(
    name="SLH-DSA-SHA2-128s",
    family="SLH-DSA",
    purpose=CryptoPurpose.DIGITAL_SIGNATURE,
    primitive=CryptoPrimitive.SIGNATURE,
    nist_quantum_security_level=1,
    classical_security_level=128,
    standard="FIPS 205",
    standard_status=StandardStatus.STANDARDISED,
    rationale=(
        "Hash-based signature resting only on the security of SHA-2, not on lattice "
        "assumptions; the conservative choice where a long-lived root of trust is signed."
    ),
    liboqs_name="SLH_DSA_PURE_SHA2_128S",
)

SLH_DSA_192S = Mechanism(
    name="SLH-DSA-SHA2-192s",
    family="SLH-DSA",
    purpose=CryptoPurpose.DIGITAL_SIGNATURE,
    primitive=CryptoPrimitive.SIGNATURE,
    nist_quantum_security_level=3,
    classical_security_level=192,
    standard="FIPS 205",
    standard_status=StandardStatus.STANDARDISED,
    rationale=(
        "Hash-based signature with no lattice assumption; the conservative alternative to "
        "ML-DSA-65 where signature size is not the binding constraint."
    ),
    liboqs_name="SLH_DSA_PURE_SHA2_192S",
)

SLH_DSA_256S = Mechanism(
    name="SLH-DSA-SHA2-256s",
    family="SLH-DSA",
    purpose=CryptoPurpose.DIGITAL_SIGNATURE,
    primitive=CryptoPrimitive.SIGNATURE,
    nist_quantum_security_level=5,
    classical_security_level=256,
    standard="FIPS 205",
    standard_status=StandardStatus.STANDARDISED,
    rationale=(
        "Hash-based signature at the highest category; the conservative alternative to "
        "ML-DSA-87."
    ),
    liboqs_name="SLH_DSA_PURE_SHA2_256S",
)

FN_DSA_512 = Mechanism(
    name="FN-DSA-512",
    family="FN-DSA",
    purpose=CryptoPurpose.DIGITAL_SIGNATURE,
    primitive=CryptoPrimitive.SIGNATURE,
    nist_quantum_security_level=1,
    classical_security_level=128,
    standard="FIPS 206 (draft)",
    standard_status=StandardStatus.DRAFT,
    rationale=(
        "Lattice signature with the most compact signatures of any PQC candidate, but "
        "FIPS 206 is still a draft and signing needs constant-time floating point."
    ),
    liboqs_name="Falcon-512",
)

FN_DSA_1024 = Mechanism(
    name="FN-DSA-1024",
    family="FN-DSA",
    purpose=CryptoPurpose.DIGITAL_SIGNATURE,
    primitive=CryptoPrimitive.SIGNATURE,
    nist_quantum_security_level=5,
    classical_security_level=256,
    standard="FIPS 206 (draft)",
    standard_status=StandardStatus.DRAFT,
    rationale=(
        "Compact lattice signature at the highest category, but FIPS 206 is still a draft."
    ),
    liboqs_name="Falcon-1024",
)

HQC_128 = Mechanism(
    name="HQC-128",
    family="HQC",
    purpose=CryptoPurpose.KEY_ESTABLISHMENT,
    primitive=CryptoPrimitive.KEM,
    nist_quantum_security_level=1,
    classical_security_level=128,
    standard="NIST selection (March 2025)",
    standard_status=StandardStatus.SELECTED,
    rationale=(
        "Code-based KEM selected as a backup to ML-KEM in case lattice assumptions fall; "
        "larger keys and ciphertexts, and no final standard yet."
    ),
    liboqs_name="HQC-1",
)

HQC_192 = Mechanism(
    name="HQC-192",
    family="HQC",
    purpose=CryptoPurpose.KEY_ESTABLISHMENT,
    primitive=CryptoPrimitive.KEM,
    nist_quantum_security_level=3,
    classical_security_level=192,
    standard="NIST selection (March 2025)",
    standard_status=StandardStatus.SELECTED,
    rationale=(
        "Code-based KEM held in reserve against a lattice break; the hedge against "
        "ML-KEM-768 rather than a replacement for it, and no final standard yet."
    ),
    liboqs_name="HQC-3",
)

HQC_256 = Mechanism(
    name="HQC-256",
    family="HQC",
    purpose=CryptoPurpose.KEY_ESTABLISHMENT,
    primitive=CryptoPrimitive.KEM,
    nist_quantum_security_level=5,
    classical_security_level=256,
    standard="NIST selection (March 2025)",
    standard_status=StandardStatus.SELECTED,
    rationale=(
        "Code-based KEM at the highest category; the hedge against ML-KEM-1024, with no "
        "final standard yet."
    ),
    liboqs_name="HQC-5",
)

CATALOG: tuple[Mechanism, ...] = (
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024,
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
    SLH_DSA_128S,
    SLH_DSA_192S,
    SLH_DSA_256S,
    FN_DSA_512,
    FN_DSA_1024,
    HQC_128,
    HQC_192,
    HQC_256,
)

MINIMUM_CATEGORY = 3
MINIMUM_CLASSICAL_STRENGTH = 192

KEY_ESTABLISHMENT_LADDER: tuple[Mechanism, ...] = (ML_KEM_512, ML_KEM_768, ML_KEM_1024)
SIGNATURE_LADDER: tuple[Mechanism, ...] = (ML_DSA_44, ML_DSA_65, ML_DSA_87)
CONSERVATIVE_LADDER: tuple[Mechanism, ...] = (SLH_DSA_128S, SLH_DSA_192S, SLH_DSA_256S)
COMPACT_LADDER: tuple[Mechanism, ...] = (FN_DSA_512, FN_DSA_1024)
BACKUP_KEM_LADDER: tuple[Mechanism, ...] = (HQC_128, HQC_192, HQC_256)


@dataclass(frozen=True)
class Recommendation:
    mechanisms: tuple[Mechanism, ...]
    rationale: str
    details: dict[str, object]

    @property
    def ambiguous(self) -> bool:
        return len({m.purpose for m in self.mechanisms}) > 1

    @property
    def primary(self) -> Mechanism | None:
        return None if self.ambiguous else self.mechanisms[0]

    @property
    def alternatives(self) -> tuple[Mechanism, ...]:
        return () if self.ambiguous else self.mechanisms[1:]

    @property
    def hybrid_advised(self) -> bool:
        return any(m.primitive is CryptoPrimitive.KEM for m in self.mechanisms)


def _climb(ladder: tuple[Mechanism, ...], target: int) -> Mechanism:
    for mechanism in ladder:
        if mechanism.classical_security_level >= target:
            return mechanism
    return ladder[-1]


def _target_strength(finding: CryptoFinding) -> int:
    recorded = finding.classical_security_level
    if recorded is None:
        return MINIMUM_CLASSICAL_STRENGTH
    return max(recorded, MINIMUM_CLASSICAL_STRENGTH)


def recommend(finding: CryptoFinding) -> Recommendation | None:
    if finding.migration_status is not MigrationStatus.QUANTUM_VULNERABLE:
        return None

    target = _target_strength(finding)
    details = {"target_classical_security_level": target}

    if finding.purpose is CryptoPurpose.KEY_ESTABLISHMENT:
        return Recommendation(
            mechanisms=(
                _climb(KEY_ESTABLISHMENT_LADDER, target),
                _climb(BACKUP_KEM_LADDER, target),
            ),
            rationale=(
                "Key establishment is the urgent case: traffic recorded today can be "
                "decrypted once a quantum computer exists, so the exposure is already "
                "happening."
            ),
            details=details,
        )

    if finding.purpose is CryptoPurpose.DIGITAL_SIGNATURE:
        return Recommendation(
            mechanisms=(
                _climb(SIGNATURE_LADDER, target),
                _climb(CONSERVATIVE_LADDER, target),
                _climb(COMPACT_LADDER, target),
            ),
            rationale=(
                "A signature is forgeable only from the moment the attacker has a quantum "
                "computer, so the deadline is the lifetime of what it signs, not today."
            ),
            details=details,
        )

    if finding.purpose is CryptoPurpose.ENCRYPTION:
        return Recommendation(
            mechanisms=(_climb(KEY_ESTABLISHMENT_LADDER, target),),
            rationale=(
                "There is no post-quantum drop-in for public-key encryption. Replace it "
                "with a KEM establishing a symmetric key, then encrypt with AES-256-GCM "
                "(the KEM-DEM construction, as in HPKE)."
            ),
            details=details,
        )

    return Recommendation(
        mechanisms=(
            _climb(KEY_ESTABLISHMENT_LADDER, target),
            _climb(SIGNATURE_LADDER, target),
        ),
        rationale=(
            "The purpose of this key could not be determined from the source. Settle "
            "whether it establishes keys or signs before choosing: the two replacements "
            "are different kinds of primitive and are not interchangeable."
        ),
        details=details,
    )


def recommend_all(findings: list[CryptoFinding]) -> dict[str, Recommendation]:
    recommendations = {}
    for finding in findings:
        recommendation = recommend(finding)
        if recommendation is not None:
            recommendations[finding.finding_id] = recommendation
    return recommendations
