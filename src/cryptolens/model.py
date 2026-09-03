from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class CryptoPurpose(str, Enum):
    ENCRYPTION = "encryption"
    KEY_ESTABLISHMENT = "key_establishment"
    DIGITAL_SIGNATURE = "digital_signature"
    HASHING = "hashing"
    MAC = "mac"
    KEY_DERIVATION = "key_derivation"
    RANDOM = "random"
    UNKNOWN = "unknown"


class CryptoStatus(str, Enum):
    CLASSICAL = "classical"
    PQC = "pqc"
    HYBRID = "hybrid"
    UNKNOWN = "unknown"

class MigrationStatus(str, Enum):
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    QUANTUM_SAFE = "quantum_safe"
    NEEDS_REVIEW = "needs_review"
    NOT_APPLICABLE = "not_applicable"


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RISK_RANK[self]


_RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.INFO: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def max_risk(levels: list[RiskLevel] | tuple[RiskLevel, ...]) -> RiskLevel:
    if not levels:
        return RiskLevel.INFO
    return max(levels, key=lambda level: level.rank)


# CycloneDX vocabulary -- values must match cyclonedx-python-lib exactly
class AssetType(str, Enum):
    ALGORITHM = "algorithm"
    CERTIFICATE = "certificate"
    PROTOCOL = "protocol"
    RELATED_CRYPTO_MATERIAL = "related-crypto-material"


class CryptoPrimitive(str, Enum):
    AE = "ae"
    BLOCK_CIPHER = "block-cipher"
    COMBINER = "combiner"
    DRBG = "drbg"
    HASH = "hash"
    KDF = "kdf"
    KEM = "kem"
    KEY_AGREE = "key-agree"
    KEY_WRAP = "key-wrap"
    MAC = "mac"
    PKE = "pke"
    SIGNATURE = "signature"
    STREAM_CIPHER = "stream-cipher"
    XOF = "xof"
    OTHER = "other"
    UNKNOWN = "unknown"


class CryptoMode(str, Enum):
    CBC = "cbc"
    CCM = "ccm"
    CFB = "cfb"
    CTR = "ctr"
    ECB = "ecb"
    GCM = "gcm"
    OFB = "ofb"
    OTHER = "other"
    UNKNOWN = "unknown"


class CryptoPadding(str, Enum):
    PKCS5 = "pkcs5"
    PKCS7 = "pkcs7"
    PKCS1V15 = "pkcs1v15"
    OAEP = "oaep"
    RAW = "raw"
    OTHER = "other"
    UNKNOWN = "unknown"


class CryptoFunction(str, Enum):
    DECAPSULATE = "decapsulate"
    DECRYPT = "decrypt"
    DIGEST = "digest"
    ENCAPSULATE = "encapsulate"
    ENCRYPT = "encrypt"
    GENERATE = "generate"
    KEYDERIVE = "keyderive"
    KEYGEN = "keygen"
    SIGN = "sign"
    TAG = "tag"
    VERIFY = "verify"
    OTHER = "other"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SourceLocation:
    file: str
    line: int
    column: int | None = None

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass
class CryptoFinding:
    algorithm: str
    location: SourceLocation
    purpose: CryptoPurpose
    evidence: str
    asset_type: AssetType = AssetType.ALGORITHM
    primitive: CryptoPrimitive = CryptoPrimitive.UNKNOWN
    mode: CryptoMode = CryptoMode.UNKNOWN
    padding: CryptoPadding = CryptoPadding.UNKNOWN
    crypto_functions: list[CryptoFunction] = field(default_factory=list)
    parameter_set: str | None = None
    curve: str | None = None
    key_size: int | None = None
    oid: str | None = None
    status: CryptoStatus = CryptoStatus.UNKNOWN
    risk: RiskLevel = RiskLevel.INFO
    migration_status: MigrationStatus = MigrationStatus.NEEDS_REVIEW
    classical_security_level: int | None = None
    nist_quantum_security_level: int | None = None
    confidence: float = 1.0
    detector: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    finding_id: str = ""
    def __post_init__(self) -> None:
        if not self.finding_id:
            self.finding_id = self._compute_id()

    def _compute_id(self) -> str:
        seed = f"{self.location.file}:{self.location.line}:{self.algorithm}:{self.purpose.value}"
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
