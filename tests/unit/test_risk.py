"""The two risk axes and the migration priority they combine into.

`assess` takes an explicit `now` throughout. That is the whole reason certificate expiry was
kept out of `CryptoFinding` in Step 8: the clock enters the pipeline in exactly one place.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cryptolens.model import (
    AssetType,
    CryptoFinding,
    CryptoMode,
    CryptoPadding,
    CryptoPrimitive,
    CryptoPurpose,
    CryptoStatus,
    RiskLevel,
    SourceLocation,
)
from cryptolens.risk import Priority, Weakness, assess, assess_all, priority_rank
from cryptolens.risk.engine import QUANTUM_DEPRECATION, QUANTUM_PROHIBITION

NOW = datetime(2026, 9, 10, tzinfo=UTC)


def finding(**overrides) -> CryptoFinding:
    kwargs = {
        "algorithm": "AES-256",
        "location": SourceLocation("pkg/crypto.py", 12),
        "purpose": CryptoPurpose.ENCRYPTION,
        "evidence": "Cipher(algorithms.AES256(key), modes.GCM(iv))",
        "primitive": CryptoPrimitive.BLOCK_CIPHER,
        "mode": CryptoMode.GCM,
        "status": CryptoStatus.CLASSICAL,
        "classical_security_level": 256,
    }
    kwargs.update(overrides)
    return CryptoFinding(**kwargs)


def certificate(**overrides) -> CryptoFinding:
    kwargs = {
        "algorithm": "RSA",
        "location": SourceLocation("certs/server.pem", 0),
        "purpose": CryptoPurpose.DIGITAL_SIGNATURE,
        "evidence": "X.509 certificate (CN=server) with an RSA public key",
        "asset_type": AssetType.CERTIFICATE,
        "primitive": CryptoPrimitive.SIGNATURE,
        "status": CryptoStatus.CLASSICAL,
        "key_size": 2048,
        "classical_security_level": 112,
        "extra": {"not_after": "2028-01-01T00:00:00+00:00"},
    }
    kwargs.update(overrides)
    return CryptoFinding(**kwargs)


# ------------------------------------------------------------- the two axes are separate


def test_a_strong_algorithm_can_still_be_quantum_vulnerable():
    """P-384 is beyond reproach classically and doomed quantum-wise. The axes disagree, and
    that disagreement is the information."""
    assessment = assess(
        finding(
            algorithm="ECDH",
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            primitive=CryptoPrimitive.KEY_AGREE,
            curve="SECP384R1",
            classical_security_level=192,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert assessment.classical_risk is RiskLevel.INFO
    assert assessment.quantum_risk is RiskLevel.HIGH
    assert assessment.risk is RiskLevel.HIGH


def test_a_broken_algorithm_can_be_quantum_irrelevant():
    """MD5 is a catastrophe today and Shor does nothing to it."""
    assessment = assess(
        finding(
            algorithm="MD5",
            purpose=CryptoPurpose.HASHING,
            primitive=CryptoPrimitive.HASH,
            mode=CryptoMode.UNKNOWN,
            classical_security_level=None,
        ),
        NOW,
    )
    assert assessment.classical_risk is RiskLevel.HIGH
    assert assessment.quantum_risk is RiskLevel.LOW
    assert assessment.broken_today is True


def test_overall_risk_is_the_higher_of_the_two_axes():
    for classical, quantum in [
        ("MD5", CryptoPurpose.HASHING),
        ("ECDH", CryptoPurpose.KEY_ESTABLISHMENT),
    ]:
        assessment = assess(
            finding(algorithm=classical, purpose=quantum, mode=CryptoMode.UNKNOWN), NOW
        )
        assert assessment.risk.rank == max(
            assessment.classical_risk.rank, assessment.quantum_risk.rank
        )


# ---------------------------------------------------------------- axis 1: broken today


@pytest.mark.parametrize(
    ("algorithm", "level"),
    [
        ("MD5", RiskLevel.HIGH),
        ("SHA-1", RiskLevel.HIGH),
        ("RC4", RiskLevel.CRITICAL),
        ("DES", RiskLevel.CRITICAL),
        ("3DES", RiskLevel.MEDIUM),
        ("Blowfish", RiskLevel.MEDIUM),
        ("none", RiskLevel.CRITICAL),
        ("AES-256", RiskLevel.INFO),
        ("SHA-256", RiskLevel.INFO),
    ],
)
def test_the_broken_algorithm_table(algorithm, level):
    assessment = assess(
        finding(algorithm=algorithm, mode=CryptoMode.UNKNOWN, purpose=CryptoPurpose.ENCRYPTION),
        NOW,
    )
    assert assessment.classical_risk is level


def test_a_broken_hash_is_worse_where_a_forgery_is_the_consequence():
    """MD5 in a checksum and MD5 in a signature are not the same finding."""
    checksum = assess(
        finding(algorithm="MD5", purpose=CryptoPurpose.HASHING, mode=CryptoMode.UNKNOWN), NOW
    )
    signature = assess(
        finding(
            algorithm="MD5", purpose=CryptoPurpose.DIGITAL_SIGNATURE, mode=CryptoMode.UNKNOWN
        ),
        NOW,
    )
    assert checksum.classical_risk is RiskLevel.HIGH
    assert signature.classical_risk is RiskLevel.CRITICAL


@pytest.mark.parametrize(
    ("algorithm", "level"),
    [
        ("RSA-SHA-1", RiskLevel.CRITICAL),
        ("ECDSA-SHA-1", RiskLevel.CRITICAL),
        ("RSA-MD5", RiskLevel.CRITICAL),
        ("DSA-SHA-1", RiskLevel.CRITICAL),
        ("RSA-SHA-256", RiskLevel.INFO),
        ("RSASSA-PSS", RiskLevel.INFO),
    ],
)
def test_a_signature_composite_inherits_its_hashs_weakness(algorithm, level):
    """A certificate signed `RSA-SHA-1` is forgeable; the exact-name table alone misses it."""
    assessment = assess(
        finding(
            algorithm=algorithm,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            primitive=CryptoPrimitive.SIGNATURE,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert assessment.classical_risk is level


@pytest.mark.parametrize("algorithm", ["HMAC-MD5", "HMAC-SHA-1", "PBKDF2-SHA-1"])
def test_a_mac_or_kdf_composite_does_not(algorithm):
    """Neither rests on collision resistance, so the hash's break does not carry over."""
    assessment = assess(
        finding(
            algorithm=algorithm,
            purpose=CryptoPurpose.MAC,
            primitive=CryptoPrimitive.MAC,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert assessment.classical_risk is RiskLevel.INFO


def test_hmac_md5_is_not_treated_as_bare_md5():
    """HMAC's security does not rest on collision resistance, so the table must not match
    on a substring."""
    assessment = assess(
        finding(
            algorithm="HMAC-MD5",
            purpose=CryptoPurpose.MAC,
            primitive=CryptoPrimitive.MAC,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert Weakness.BROKEN_ALGORITHM not in assessment.weaknesses


def test_ecb_is_flagged_whatever_the_cipher():
    assessment = assess(finding(mode=CryptoMode.ECB), NOW)
    assert assessment.classical_risk is RiskLevel.HIGH
    assert Weakness.INSECURE_MODE in assessment.weaknesses
    assert "identical ciphertext blocks" in assessment.rationale


@pytest.mark.parametrize(
    ("key_size", "level"),
    [(512, RiskLevel.CRITICAL), (1024, RiskLevel.HIGH), (2048, RiskLevel.INFO),
     (4096, RiskLevel.INFO)],
)
def test_rsa_key_sizes(key_size, level):
    assessment = assess(
        finding(
            algorithm="RSA",
            primitive=CryptoPrimitive.PKE,
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            key_size=key_size,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert assessment.classical_risk is level


def test_a_curve_below_128_bits_is_flagged():
    assessment = assess(
        finding(
            algorithm="ECDSA",
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            curve="SECP192R1",
            classical_security_level=96,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert Weakness.WEAK_CURVE in assessment.weaknesses
    assert assessment.classical_risk is RiskLevel.HIGH


def test_pkcs1v15_is_only_a_problem_for_encryption():
    """Bleichenbacher attacks the encryption padding. PKCS#1 v1.5 *signatures* are fine."""
    encrypting = assess(
        finding(
            algorithm="RSA",
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            padding=CryptoPadding.PKCS1V15,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    signing = assess(
        finding(
            algorithm="RSA",
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            padding=CryptoPadding.PKCS1V15,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert Weakness.VULNERABLE_PADDING in encrypting.weaknesses
    assert Weakness.VULNERABLE_PADDING not in signing.weaknesses


def test_disabled_verification_is_critical_whatever_the_algorithm():
    assessment = assess(
        finding(
            algorithm="JWT",
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            detector="jwt.verification_disabled",
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert assessment.classical_risk is RiskLevel.CRITICAL
    assert assessment.priority is Priority.IMMEDIATE


def test_every_configured_detector_name_actually_exists():
    """Three of these four names were wrong and silently matched nothing. The rule table is
    the authority; this test is the cross-check."""
    from cryptolens.detectors.rules import RULES
    from cryptolens.risk.rules import DISABLED_VERIFICATION_DETECTORS

    known = {rule.detector or rule.match for rule in RULES}
    assert DISABLED_VERIFICATION_DETECTORS <= known


def test_tls_verification_disabled_is_critical():
    for detector in ("ssl.verification_disabled", "ssl.hostname_check_disabled",
                     "ssl.unverified_context"):
        assessment = assess(
            finding(
                algorithm="TLS",
                asset_type=AssetType.PROTOCOL,
                purpose=CryptoPurpose.KEY_ESTABLISHMENT,
                primitive=CryptoPrimitive.OTHER,
                detector=detector,
                mode=CryptoMode.UNKNOWN,
                classical_security_level=None,
            ),
            NOW,
        )
        assert assessment.classical_risk is RiskLevel.CRITICAL, detector
        assert assessment.priority is Priority.IMMEDIATE, detector


# ------------------------------------------------------------------- certificate dates


def test_an_expired_certificate_is_immediate():
    assessment = assess(certificate(extra={"not_after": "2025-01-01T00:00:00+00:00"}), NOW)
    assert Weakness.EXPIRED_CERTIFICATE in assessment.weaknesses
    assert assessment.classical_risk is RiskLevel.HIGH
    assert assessment.priority is Priority.IMMEDIATE
    assert "expired on 2025-01-01" in assessment.rationale


def test_a_certificate_expiring_within_ninety_days_is_flagged():
    assessment = assess(certificate(extra={"not_after": "2026-10-01T00:00:00+00:00"}), NOW)
    assert Weakness.EXPIRING_CERTIFICATE in assessment.weaknesses
    assert assessment.classical_risk is RiskLevel.MEDIUM


def test_a_healthy_certificate_raises_nothing_classical():
    assessment = assess(certificate(), NOW)
    assert Weakness.EXPIRED_CERTIFICATE not in assessment.weaknesses
    assert Weakness.EXPIRING_CERTIFICATE not in assessment.weaknesses
    assert assessment.classical_risk is RiskLevel.INFO


def test_expiry_depends_on_the_clock_and_nothing_else():
    """The same finding, two different dates, two different answers -- and it is explicit."""
    cert = certificate(extra={"not_after": "2027-01-01T00:00:00+00:00"})
    assert assess(cert, datetime(2026, 1, 1, tzinfo=UTC)).classical_risk is RiskLevel.INFO
    assert assess(cert, datetime(2026, 12, 1, tzinfo=UTC)).classical_risk is RiskLevel.MEDIUM
    assert assess(cert, datetime(2028, 1, 1, tzinfo=UTC)).classical_risk is RiskLevel.HIGH


def test_a_certificate_outliving_the_2035_prohibition_is_immediate():
    """A signing certificate would normally be 'scheduled'. Its validity window overrules
    that: it will still be trusted after RSA and ECC are disallowed."""
    assessment = assess(certificate(extra={"not_after": "2040-01-01T00:00:00+00:00"}), NOW)
    assert Weakness.OUTLIVES_QUANTUM_DEADLINE in assessment.weaknesses
    assert assessment.priority is Priority.IMMEDIATE
    assert "2035" in assessment.rationale


def test_a_certificate_outliving_the_2030_deprecation_is_urgent():
    assessment = assess(certificate(extra={"not_after": "2032-01-01T00:00:00+00:00"}), NOW)
    assert assessment.priority is Priority.URGENT
    assert "2030" in assessment.rationale


def test_the_deadlines_are_the_nist_ones():
    assert QUANTUM_DEPRECATION.year == 2030
    assert QUANTUM_PROHIBITION.year == 2035


def test_an_expired_certificate_is_not_also_a_future_quantum_problem():
    """Nothing trusts it any more, so its validity window cannot outlive a deadline."""
    assessment = assess(certificate(extra={"not_after": "2025-01-01T00:00:00+00:00"}), NOW)
    assert Weakness.OUTLIVES_QUANTUM_DEADLINE not in assessment.weaknesses


def test_an_unparseable_date_is_ignored_rather_than_fatal():
    assessment = assess(certificate(extra={"not_after": "sometime next year"}), NOW)
    assert Weakness.EXPIRED_CERTIFICATE not in assessment.weaknesses
    assert assessment.classical_risk is RiskLevel.INFO


# --------------------------------------------------------- axis 2 and the priority split


def test_key_establishment_outranks_signing_for_the_same_maths():
    """The distinction the project is judged on, at the level of one function call."""
    exchange = assess(
        finding(
            algorithm="ECDH",
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            primitive=CryptoPrimitive.KEY_AGREE,
            curve="SECP256R1",
            classical_security_level=128,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    signing = assess(
        finding(
            algorithm="ECDSA",
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            primitive=CryptoPrimitive.SIGNATURE,
            curve="SECP256R1",
            classical_security_level=128,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )

    assert exchange.quantum_risk is RiskLevel.HIGH
    assert signing.quantum_risk is RiskLevel.MEDIUM
    assert exchange.priority is Priority.URGENT
    assert signing.priority is Priority.SCHEDULED
    assert priority_rank(exchange.priority) > priority_rank(signing.priority)
    assert Weakness.HARVEST_NOW_DECRYPT_LATER in exchange.weaknesses
    assert "recorded today" in exchange.rationale


def test_an_undetermined_purpose_is_treated_as_urgent():
    """We cannot rule out that it establishes keys, so we do not get to relax."""
    assessment = assess(
        finding(
            algorithm="RSA",
            purpose=CryptoPurpose.UNKNOWN,
            primitive=CryptoPrimitive.PKE,
            key_size=2048,
            classical_security_level=112,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert assessment.priority is Priority.URGENT
    assert Weakness.QUANTUM_VULNERABLE_UNKNOWN_PURPOSE in assessment.weaknesses


def test_quantum_safe_findings_carry_no_quantum_risk():
    assessment = assess(
        finding(
            algorithm="HMAC-SHA-256",
            purpose=CryptoPurpose.MAC,
            primitive=CryptoPrimitive.MAC,
            classical_security_level=128,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert assessment.quantum_risk is RiskLevel.INFO
    assert assessment.priority is Priority.NONE


def test_an_unidentified_algorithm_is_monitored_not_ignored():
    assessment = assess(
        finding(
            algorithm="unknown",
            purpose=CryptoPurpose.UNKNOWN,
            primitive=CryptoPrimitive.UNKNOWN,
            status=CryptoStatus.UNKNOWN,
            classical_security_level=None,
            mode=CryptoMode.UNKNOWN,
        ),
        NOW,
    )
    assert assessment.quantum_risk is RiskLevel.LOW
    assert assessment.priority is Priority.MONITOR


def test_broken_today_always_beats_a_quantum_deadline():
    """RC4 is being exploited now; ECDH is being recorded for later. Now wins."""
    rc4 = assess(finding(algorithm="RC4", mode=CryptoMode.UNKNOWN), NOW)
    assert rc4.priority is Priority.IMMEDIATE


# --------------------------------------------------------------------------- mechanics


def test_confidence_is_not_folded_into_risk():
    """Certainty and severity are different questions; the report shows both columns."""
    certain = assess(finding(algorithm="RC4", mode=CryptoMode.UNKNOWN, confidence=1.0), NOW)
    unsure = assess(finding(algorithm="RC4", mode=CryptoMode.UNKNOWN, confidence=0.2), NOW)
    assert certain.classical_risk is unsure.classical_risk
    assert certain.priority is unsure.priority


def test_every_reason_explains_itself_in_a_sentence():
    assessment = assess(
        finding(algorithm="MD5", purpose=CryptoPurpose.DIGITAL_SIGNATURE, mode=CryptoMode.ECB),
        NOW,
    )
    assert len(assessment.reasons) >= 2
    for reason in assessment.reasons:
        assert reason.explanation.endswith(".")
        assert len(reason.explanation) > 30


def test_assess_all_is_keyed_by_finding_id():
    findings = [finding(algorithm="RC4", mode=CryptoMode.UNKNOWN), certificate()]
    assessments = assess_all(findings, NOW)
    assert set(assessments) == {f.finding_id for f in findings}


def test_assess_defaults_to_the_current_clock():
    assessment = assess(certificate(extra={"not_after": "2019-01-01T00:00:00+00:00"}))
    assert Weakness.EXPIRED_CERTIFICATE in assessment.weaknesses


def test_a_naive_timestamp_is_read_as_utc():
    assessment = assess(certificate(extra={"not_after": "2025-01-01T00:00:00"}), NOW)
    assert Weakness.EXPIRED_CERTIFICATE in assessment.weaknesses
