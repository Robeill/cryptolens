from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from cryptolens.model import (
    AssetType,
    CryptoFinding,
    CryptoPurpose,
    MigrationStatus,
    RiskLevel,
    max_risk,
)
from cryptolens.risk.rules import (
    BROKEN_ALGORITHMS,
    DISABLED_VERIFICATION_DETECTORS,
    INSECURE_MODES,
    MINIMUM_CURVE_STRENGTH,
    NEEDS_REVIEW_RISK,
    QUANTUM_RISK,
    QUANTUM_RISK_UNKNOWN_PURPOSE,
    RSA_KEY_SIZE_THRESHOLDS,
    SIGNATURE_COMPOSITE_PREFIXES,
    VULNERABLE_PADDINGS,
    Weakness,
)

logger = logging.getLogger(__name__)

QUANTUM_DEPRECATION = datetime(2030, 1, 1, tzinfo=UTC)
QUANTUM_PROHIBITION = datetime(2035, 1, 1, tzinfo=UTC)
EXPIRY_WARNING_DAYS = 90


class Priority(str, Enum):
    IMMEDIATE = "immediate"
    URGENT = "urgent"
    SCHEDULED = "scheduled"
    MONITOR = "monitor"
    NONE = "none"


_PRIORITY_RANK: dict[Priority, int] = {
    Priority.NONE: 0,
    Priority.MONITOR: 1,
    Priority.SCHEDULED: 2,
    Priority.URGENT: 3,
    Priority.IMMEDIATE: 4,
}


@dataclass(frozen=True)
class Reason:
    weakness: Weakness
    level: RiskLevel
    explanation: str


@dataclass(frozen=True)
class Assessment:
    finding_id: str
    classical_risk: RiskLevel
    quantum_risk: RiskLevel
    priority: Priority
    reasons: tuple[Reason, ...] = field(default_factory=tuple)

    @property
    def risk(self) -> RiskLevel:
        return max_risk([self.classical_risk, self.quantum_risk])

    @property
    def weaknesses(self) -> tuple[Weakness, ...]:
        return tuple(reason.weakness for reason in self.reasons)

    @property
    def broken_today(self) -> bool:
        return self.classical_risk.rank >= RiskLevel.HIGH.rank

    @property
    def rationale(self) -> str:
        return " ".join(reason.explanation for reason in self.reasons)


def assess(finding: CryptoFinding, now: datetime | None = None) -> Assessment:
    moment = now or datetime.now(UTC)
    classical = _classical_reasons(finding, moment)
    quantum = _quantum_reasons(finding, moment)

    classical_risk = max_risk([reason.level for reason in classical])
    quantum_risk = max_risk([reason.level for reason in quantum])

    return Assessment(
        finding_id=finding.finding_id,
        classical_risk=classical_risk,
        quantum_risk=quantum_risk,
        priority=_priority(classical_risk, quantum, finding),
        reasons=tuple(classical + quantum),
    )


def assess_all(
    findings: list[CryptoFinding], now: datetime | None = None
) -> dict[str, Assessment]:
    moment = now or datetime.now(UTC)
    return {finding.finding_id: assess(finding, moment) for finding in findings}


def priority_rank(priority: Priority) -> int:
    return _PRIORITY_RANK[priority]


# ------------------------------------------------------------------ axis 1: broken today


def _classical_reasons(finding: CryptoFinding, now: datetime) -> list[Reason]:
    reasons: list[Reason] = []

    if finding.detector in DISABLED_VERIFICATION_DETECTORS:
        reasons.append(
            Reason(
                Weakness.VERIFICATION_DISABLED,
                RiskLevel.CRITICAL,
                "Signature or certificate verification is switched off here, which removes "
                "the guarantee the algorithm was chosen to provide.",
            )
        )

    broken = BROKEN_ALGORITHMS.get(finding.algorithm) or _broken_composite(finding.algorithm)
    if broken is not None:
        level, weakness, explanation = broken
        if weakness is Weakness.BROKEN_ALGORITHM and _is_security_critical(finding):
            level = _escalate(level)
        reasons.append(Reason(weakness, level, explanation))

    mode = INSECURE_MODES.get(finding.mode)
    if mode is not None:
        reasons.append(Reason(Weakness.INSECURE_MODE, mode[0], mode[1]))

    padding = VULNERABLE_PADDINGS.get(finding.padding)
    if padding is not None and finding.purpose in padding[1]:
        reasons.append(Reason(Weakness.VULNERABLE_PADDING, padding[0], padding[2]))

    reasons.extend(_key_size_reasons(finding))
    reasons.extend(_expiry_reasons(finding, now))
    return reasons


def _broken_composite(algorithm: str) -> tuple[RiskLevel, Weakness, str] | None:
    """`RSA-SHA-1` is as broken as `SHA-1`; `HMAC-MD5` is not as broken as `MD5`.

    A signature composite inherits its hash's weakness because a collision forges the
    signature. A MAC or KDF composite does not, because neither rests on collision
    resistance.
    """
    head, _, tail = algorithm.partition("-")
    if head not in SIGNATURE_COMPOSITE_PREFIXES:
        return None
    return BROKEN_ALGORITHMS.get(tail)


def _is_security_critical(finding: CryptoFinding) -> bool:
    """A broken hash matters most where a forgery is the consequence."""
    return finding.purpose in {
        CryptoPurpose.DIGITAL_SIGNATURE,
        CryptoPurpose.MAC,
        CryptoPurpose.KEY_DERIVATION,
    } or finding.asset_type is AssetType.CERTIFICATE


def _escalate(level: RiskLevel) -> RiskLevel:
    order = [RiskLevel.INFO, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    return order[min(level.rank + 1, len(order) - 1)]


def _key_size_reasons(finding: CryptoFinding) -> list[Reason]:
    if finding.key_size is not None and finding.algorithm.startswith("RSA"):
        for threshold, level, explanation in RSA_KEY_SIZE_THRESHOLDS:
            if finding.key_size < threshold:
                if level is RiskLevel.INFO:
                    return []
                return [Reason(Weakness.WEAK_KEY_SIZE, level, explanation)]

    strength = finding.classical_security_level
    if finding.curve is not None and strength is not None and strength < MINIMUM_CURVE_STRENGTH:
        return [
            Reason(
                Weakness.WEAK_CURVE,
                RiskLevel.HIGH,
                f"{finding.curve} offers {strength}-bit classical security, below the "
                f"{MINIMUM_CURVE_STRENGTH}-bit minimum.",
            )
        ]
    return []


def _expiry_reasons(finding: CryptoFinding, now: datetime) -> list[Reason]:
    not_after = _timestamp(finding, "not_after")
    if not_after is None:
        return []
    if not_after < now:
        return [
            Reason(
                Weakness.EXPIRED_CERTIFICATE,
                RiskLevel.HIGH,
                f"The certificate expired on {not_after.date().isoformat()}.",
            )
        ]
    remaining = (not_after - now).days
    if remaining <= EXPIRY_WARNING_DAYS:
        return [
            Reason(
                Weakness.EXPIRING_CERTIFICATE,
                RiskLevel.MEDIUM,
                f"The certificate expires in {remaining} days, on "
                f"{not_after.date().isoformat()}.",
            )
        ]
    return []


def _timestamp(finding: CryptoFinding, key: str) -> datetime | None:
    raw = finding.extra.get(key)
    if not isinstance(raw, str):
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        logger.debug("unparseable %s on %s", key, finding.finding_id, exc_info=True)
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


# -------------------------------------------------------------- axis 2: quantum exposure


def _quantum_reasons(finding: CryptoFinding, now: datetime) -> list[Reason]:
    status = finding.migration_status
    if status is MigrationStatus.NEEDS_REVIEW:
        level, weakness, explanation = NEEDS_REVIEW_RISK
        return [Reason(weakness, level, explanation)]
    if status is not MigrationStatus.QUANTUM_VULNERABLE:
        return []

    level, weakness, explanation = QUANTUM_RISK.get(
        finding.purpose, QUANTUM_RISK_UNKNOWN_PURPOSE
    )
    reasons = [Reason(weakness, level, explanation)]

    deadline = _outlived_deadline(finding, now)
    if deadline is not None:
        reasons.append(deadline)
    return reasons


def _outlived_deadline(finding: CryptoFinding, now: datetime) -> Reason | None:
    not_after = _timestamp(finding, "not_after")
    if not_after is None or not_after < now:
        return None
    if not_after >= QUANTUM_PROHIBITION:
        return Reason(
            Weakness.OUTLIVES_QUANTUM_DEADLINE,
            RiskLevel.HIGH,
            f"This certificate is valid until {not_after.date().isoformat()}, past the 2035 "
            "date after which NIST disallows RSA and elliptic-curve cryptography.",
        )
    if not_after >= QUANTUM_DEPRECATION:
        return Reason(
            Weakness.OUTLIVES_QUANTUM_DEADLINE,
            RiskLevel.MEDIUM,
            f"This certificate is valid until {not_after.date().isoformat()}, past the 2030 "
            "date after which NIST deprecates RSA and elliptic-curve cryptography.",
        )
    return None


# ------------------------------------------------------------------------- priority


def _priority(
    classical_risk: RiskLevel, quantum: list[Reason], finding: CryptoFinding
) -> Priority:
    if classical_risk.rank >= RiskLevel.HIGH.rank:
        return Priority.IMMEDIATE

    weaknesses = {reason.weakness for reason in quantum}
    if Weakness.OUTLIVES_QUANTUM_DEADLINE in weaknesses:
        outlives = next(
            r for r in quantum if r.weakness is Weakness.OUTLIVES_QUANTUM_DEADLINE
        )
        return Priority.IMMEDIATE if outlives.level is RiskLevel.HIGH else Priority.URGENT

    if Weakness.HARVEST_NOW_DECRYPT_LATER in weaknesses:
        return Priority.URGENT
    if Weakness.QUANTUM_VULNERABLE_UNKNOWN_PURPOSE in weaknesses:
        return Priority.URGENT
    if Weakness.QUANTUM_VULNERABLE_SIGNATURE in weaknesses:
        return Priority.SCHEDULED
    if Weakness.UNIDENTIFIED_ALGORITHM in weaknesses:
        return Priority.MONITOR
    if classical_risk.rank >= RiskLevel.LOW.rank:
        return Priority.MONITOR
    return Priority.NONE
