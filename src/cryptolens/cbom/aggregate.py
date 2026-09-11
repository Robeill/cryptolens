from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from cryptolens.detectors.normalize import normalize_algorithm
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
    max_risk,
)
from cryptolens.risk import Assessment, Priority, priority_rank

INSTANCE_ASSET_TYPES = frozenset({AssetType.CERTIFICATE, AssetType.RELATED_CRYPTO_MATERIAL})


@dataclass(frozen=True)
class Occurrence:
    file: str
    line: int
    evidence: str
    confidence: float
    finding_id: str
    detector: str | None = None

    def __str__(self) -> str:
        return f"{self.file}:{self.line}"


@dataclass(frozen=True)
class AssetKey:
    asset_type: AssetType
    algorithm: str
    primitive: CryptoPrimitive
    mode: CryptoMode
    padding: CryptoPadding
    parameter_set: str | None
    key_size: int | None
    purpose: CryptoPurpose
    oid: str | None
    identity: tuple[str, ...] = ()

    def digest(self) -> str:
        seed = "|".join(
            [
                self.asset_type.value,
                self.algorithm,
                self.primitive.value,
                self.mode.value,
                self.padding.value,
                self.parameter_set or "",
                str(self.key_size or ""),
                self.purpose.value,
                self.oid or "",
                *self.identity,
            ]
        )
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


@dataclass
class CryptoAsset:
    key: AssetKey
    status: CryptoStatus
    curve: str | None = None
    crypto_functions: list[CryptoFunction] = field(default_factory=list)
    classical_security_level: int | None = None
    nist_quantum_security_level: int | None = None
    details: dict[str, Any] = field(default_factory=dict)
    occurrences: list[Occurrence] = field(default_factory=list)

    @property
    def asset_id(self) -> str:
        return self.key.digest()

    @property
    def asset_type(self) -> AssetType:
        return self.key.asset_type

    @property
    def algorithm(self) -> str:
        return self.key.algorithm

    @property
    def primitive(self) -> CryptoPrimitive:
        return self.key.primitive

    @property
    def mode(self) -> CryptoMode:
        return self.key.mode

    @property
    def padding(self) -> CryptoPadding:
        return self.key.padding

    @property
    def parameter_set(self) -> str | None:
        return self.key.parameter_set

    @property
    def key_size(self) -> int | None:
        return self.key.key_size

    @property
    def purpose(self) -> CryptoPurpose:
        return self.key.purpose

    @property
    def oid(self) -> str | None:
        return self.key.oid

    @property
    def confidence(self) -> float:
        return max(occurrence.confidence for occurrence in self.occurrences)

    @property
    def occurrence_count(self) -> int:
        return len(self.occurrences)

    @property
    def files(self) -> list[str]:
        return sorted({occurrence.file for occurrence in self.occurrences})

    def risk(self, assessments: Mapping[str, Assessment]) -> RiskLevel:
        return max_risk(self._assessed(assessments, lambda a: a.risk))

    def classical_risk(self, assessments: Mapping[str, Assessment]) -> RiskLevel:
        return max_risk(self._assessed(assessments, lambda a: a.classical_risk))

    def quantum_risk(self, assessments: Mapping[str, Assessment]) -> RiskLevel:
        return max_risk(self._assessed(assessments, lambda a: a.quantum_risk))

    def migration_status(
        self, findings: Mapping[str, CryptoFinding]
    ) -> MigrationStatus:
        statuses = {
            findings[o.finding_id].migration_status
            for o in self.occurrences
            if o.finding_id in findings
        }
        if len(statuses) == 1:
            return next(iter(statuses))
        return MigrationStatus.NEEDS_REVIEW

    def priority(self, assessments: Mapping[str, Assessment]) -> Priority:
        priorities = [
            assessments[o.finding_id].priority
            for o in self.occurrences
            if o.finding_id in assessments
        ]
        if not priorities:
            return Priority.NONE
        return max(priorities, key=priority_rank)

    def _assessed(self, assessments, pick) -> list[RiskLevel]:
        return [
            pick(assessments[o.finding_id])
            for o in self.occurrences
            if o.finding_id in assessments
        ]


def asset_key(finding: CryptoFinding) -> AssetKey:
    return AssetKey(
        asset_type=finding.asset_type,
        algorithm=normalize_algorithm(finding.algorithm),
        primitive=finding.primitive,
        mode=finding.mode,
        padding=finding.padding,
        parameter_set=finding.parameter_set or finding.curve,
        key_size=finding.key_size,
        purpose=finding.purpose,
        oid=finding.oid,
        identity=_identity(finding),
    )


def _identity(finding: CryptoFinding) -> tuple[str, ...]:
    """Algorithms are classes; certificates and keys are instances.

    Two `sha256()` calls in different files are one algorithm. Two RSA-2048 certificates are
    two certificates, and merging them would discard the subject of one.

    A certificate's identity is its subject, issuer and serial -- the X.509 definition -- not
    the file it was read from. The same certificate stored as PEM, as DER and inside a bundle
    is one certificate in three places, which is what `occurrences` is for. A key file has no
    such identity inside it, so the path is all there is to go on.
    """
    if finding.asset_type is AssetType.CERTIFICATE:
        return (
            str(finding.extra.get("subject", "")),
            str(finding.extra.get("issuer", "")),
            str(finding.extra.get("serial_number", "")),
        )
    if finding.asset_type is AssetType.RELATED_CRYPTO_MATERIAL:
        return (finding.location.file, str(finding.extra.get("artifact", "")))
    return ()


def aggregate(findings: list[CryptoFinding]) -> list[CryptoAsset]:
    assets: dict[AssetKey, CryptoAsset] = {}

    for finding in findings:
        key = asset_key(finding)
        asset = assets.get(key)
        if asset is None:
            asset = CryptoAsset(
                key=key,
                status=finding.status,
                curve=finding.curve,
                classical_security_level=finding.classical_security_level,
                nist_quantum_security_level=finding.nist_quantum_security_level,
                details=dict(finding.extra),
            )
            assets[key] = asset
        else:
            _merge(asset, finding)

        asset.occurrences.append(
            Occurrence(
                file=finding.location.file,
                line=finding.location.line,
                evidence=finding.evidence,
                confidence=finding.confidence,
                finding_id=finding.finding_id,
                detector=finding.detector,
            )
        )
        for function in finding.crypto_functions:
            if function not in asset.crypto_functions:
                asset.crypto_functions.append(function)

    for asset in assets.values():
        asset.crypto_functions.sort(key=lambda function: function.value)
        asset.occurrences.sort(key=lambda occurrence: (occurrence.file, occurrence.line))

    return sorted(assets.values(), key=lambda asset: (asset.asset_type.value, asset.algorithm,
                                                      asset.asset_id))


def _merge(asset: CryptoAsset, finding: CryptoFinding) -> None:
    if asset.status is CryptoStatus.UNKNOWN:
        asset.status = finding.status
    if asset.curve is None:
        asset.curve = finding.curve
    if asset.classical_security_level is None:
        asset.classical_security_level = finding.classical_security_level
    if asset.nist_quantum_security_level is None:
        asset.nist_quantum_security_level = finding.nist_quantum_security_level
    for name, value in finding.extra.items():
        asset.details.setdefault(name, value)
