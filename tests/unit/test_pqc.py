"""The PQC catalog, the purpose-keyed mapping, and the optional liboqs bridge.

Every test that touches a recommendation is parametrised over `OQS_AVAILABLE`, because the
bridge is allowed to *add* detail and never to change advice.
"""

from __future__ import annotations

import pytest

from cryptolens.model import (
    CryptoFinding,
    CryptoPrimitive,
    CryptoPurpose,
    CryptoStatus,
    MigrationStatus,
    SourceLocation,
)
from cryptolens.pqc import catalog, liboqs_bridge
from cryptolens.pqc.catalog import (
    CATALOG,
    MINIMUM_CLASSICAL_STRENGTH,
    StandardStatus,
    recommend,
    recommend_all,
)


@pytest.fixture(params=[True, False], ids=["liboqs", "no-liboqs"])
def both_liboqs_states(request, monkeypatch):
    """Run a test twice: once as installed, once as if liboqs were absent."""
    if not request.param:
        monkeypatch.setattr(liboqs_bridge, "OQS_AVAILABLE", False)
    elif not liboqs_bridge.OQS_AVAILABLE:
        pytest.skip("liboqs is not installed in this environment")
    return request.param


def finding(**overrides) -> CryptoFinding:
    kwargs = {
        "algorithm": "RSA",
        "location": SourceLocation("pkg/keys.py", 3),
        "purpose": CryptoPurpose.DIGITAL_SIGNATURE,
        "evidence": "private_key.sign(message, padding, hashes.SHA256())",
        "primitive": CryptoPrimitive.SIGNATURE,
        "status": CryptoStatus.CLASSICAL,
        "classical_security_level": 112,
    }
    kwargs.update(overrides)
    return CryptoFinding(**kwargs)


# ------------------------------------------------------------------------- the catalog


def test_the_catalog_covers_both_jobs_rsa_does():
    purposes = {m.purpose for m in CATALOG}
    assert CryptoPurpose.KEY_ESTABLISHMENT in purposes
    assert CryptoPurpose.DIGITAL_SIGNATURE in purposes


def test_every_mechanism_has_a_report_ready_rationale():
    for mechanism in CATALOG:
        assert mechanism.rationale.endswith("."), mechanism.name
        assert len(mechanism.rationale) > 40, mechanism.name
        assert "\n" not in mechanism.rationale, mechanism.name


def test_kems_and_signatures_are_not_mixed_up():
    for mechanism in CATALOG:
        if mechanism.purpose is CryptoPurpose.KEY_ESTABLISHMENT:
            assert mechanism.primitive is CryptoPrimitive.KEM, mechanism.name
        else:
            assert mechanism.primitive is CryptoPrimitive.SIGNATURE, mechanism.name


def test_draft_mechanisms_say_so_in_their_rationale():
    for mechanism in CATALOG:
        if mechanism.standard_status is not StandardStatus.STANDARDISED:
            assert "draft" in mechanism.rationale or "no final standard" in mechanism.rationale


def test_catalog_names_are_unique():
    assert len({m.name for m in CATALOG}) == len(CATALOG)


# ------------------------------------------------------------ purpose drives the mapping


def test_the_same_algorithm_maps_differently_depending_on_its_purpose(both_liboqs_states):
    """The thesis of the project in one assertion."""
    signing = recommend(
        finding(purpose=CryptoPurpose.DIGITAL_SIGNATURE, primitive=CryptoPrimitive.SIGNATURE)
    )
    establishing = recommend(
        finding(purpose=CryptoPurpose.KEY_ESTABLISHMENT, primitive=CryptoPrimitive.PKE)
    )

    assert signing.primary.name == "ML-DSA-65"
    assert signing.primary.primitive is CryptoPrimitive.SIGNATURE
    assert establishing.primary.name == "ML-KEM-768"
    assert establishing.primary.primitive is CryptoPrimitive.KEM
    assert signing.primary != establishing.primary


def test_key_establishment_advises_a_hybrid_and_signing_does_not(both_liboqs_states):
    establishing = recommend(
        finding(purpose=CryptoPurpose.KEY_ESTABLISHMENT, primitive=CryptoPrimitive.KEY_AGREE)
    )
    signing = recommend(finding(purpose=CryptoPurpose.DIGITAL_SIGNATURE))
    assert establishing.hybrid_advised is True
    assert signing.hybrid_advised is False


def test_key_establishment_rationale_names_the_harvest_now_problem(both_liboqs_states):
    recommendation = recommend(
        finding(purpose=CryptoPurpose.KEY_ESTABLISHMENT, primitive=CryptoPrimitive.KEY_AGREE)
    )
    assert "recorded today" in recommendation.rationale


def test_the_backup_kem_is_offered_as_an_alternative(both_liboqs_states):
    recommendation = recommend(
        finding(purpose=CryptoPurpose.KEY_ESTABLISHMENT, primitive=CryptoPrimitive.KEY_AGREE)
    )
    assert [m.name for m in recommendation.alternatives] == ["HQC-192"]


def test_signatures_offer_a_conservative_and_a_compact_alternative(both_liboqs_states):
    recommendation = recommend(finding(purpose=CryptoPurpose.DIGITAL_SIGNATURE))
    families = [m.family for m in recommendation.mechanisms]
    assert families == ["ML-DSA", "SLH-DSA", "FN-DSA"]


def test_asymmetric_encryption_is_told_to_use_a_kem_and_a_symmetric_cipher(both_liboqs_states):
    """RSA-OAEP has no post-quantum drop-in; the answer is a different construction."""
    recommendation = recommend(
        finding(purpose=CryptoPurpose.ENCRYPTION, primitive=CryptoPrimitive.PKE)
    )
    assert recommendation.primary.primitive is CryptoPrimitive.KEM
    assert "KEM-DEM" in recommendation.rationale
    assert "AES-256-GCM" in recommendation.rationale


# ------------------------------------------------------------------- ambiguous purposes


def test_an_undetermined_purpose_offers_both_and_refuses_to_pick(both_liboqs_states):
    """A bare `rsa.generate_private_key` does not say what the key is for, so neither do we."""
    recommendation = recommend(
        finding(purpose=CryptoPurpose.UNKNOWN, primitive=CryptoPrimitive.PKE)
    )
    assert recommendation.ambiguous is True
    assert recommendation.primary is None
    assert recommendation.alternatives == ()
    assert [m.name for m in recommendation.mechanisms] == ["ML-KEM-768", "ML-DSA-65"]
    assert "Settle" in recommendation.rationale


def test_an_unambiguous_recommendation_has_a_primary(both_liboqs_states):
    recommendation = recommend(finding(purpose=CryptoPurpose.DIGITAL_SIGNATURE))
    assert recommendation.ambiguous is False
    assert recommendation.primary is not None


# ---------------------------------------------------------------- what is not recommended


@pytest.mark.parametrize(
    ("overrides", "why"),
    [
        ({"status": CryptoStatus.PQC}, "already post-quantum"),
        (
            {
                "primitive": CryptoPrimitive.MAC,
                "purpose": CryptoPurpose.MAC,
                "classical_security_level": 128,
            },
            "a MAC is not a Shor target",
        ),
        (
            {
                "primitive": CryptoPrimitive.HASH,
                "purpose": CryptoPurpose.HASHING,
                "classical_security_level": 128,
            },
            "a hash is not a Shor target",
        ),
        ({"classical_security_level": 0}, "there is no algorithm to replace"),
        ({"status": CryptoStatus.UNKNOWN}, "unidentified, so a human decides"),
    ],
    ids=["pqc", "mac", "hash", "none", "unknown"],
)
def test_nothing_is_recommended_for_findings_that_do_not_need_migrating(
    overrides, why, both_liboqs_states
):
    assert recommend(finding(**overrides)) is None, why


def test_recommendations_follow_migration_status_exactly(both_liboqs_states):
    """One source of truth: if it is not quantum-vulnerable, there is nothing to recommend."""
    for status in CryptoStatus:
        for primitive in (CryptoPrimitive.SIGNATURE, CryptoPrimitive.MAC, CryptoPrimitive.HASH):
            candidate = finding(
                status=status, primitive=primitive, classical_security_level=128
            )
            expected = candidate.migration_status is MigrationStatus.QUANTUM_VULNERABLE
            assert (recommend(candidate) is not None) is expected


# ------------------------------------------------------------------- strength laddering


@pytest.mark.parametrize(
    ("strength", "kem", "signature"),
    [
        (None, "ML-KEM-768", "ML-DSA-65"),
        (112, "ML-KEM-768", "ML-DSA-65"),
        (128, "ML-KEM-768", "ML-DSA-65"),
        (192, "ML-KEM-768", "ML-DSA-65"),
        (256, "ML-KEM-1024", "ML-DSA-87"),
    ],
    ids=["unknown", "rsa-2048", "p-256", "p-384", "p-521"],
)
def test_the_recommendation_never_drops_below_what_it_replaces(
    strength, kem, signature, both_liboqs_states
):
    establishing = recommend(
        finding(
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            primitive=CryptoPrimitive.KEY_AGREE,
            classical_security_level=strength,
        )
    )
    signing = recommend(
        finding(purpose=CryptoPurpose.DIGITAL_SIGNATURE, classical_security_level=strength)
    )
    assert establishing.primary.name == kem
    assert signing.primary.name == signature


def test_the_floor_is_category_three(both_liboqs_states):
    """A migration done once should not be sized to the weakest thing it replaces."""
    weak = recommend(finding(classical_security_level=80))
    assert weak.primary.nist_quantum_security_level >= catalog.MINIMUM_CATEGORY
    assert weak.details["target_classical_security_level"] == MINIMUM_CLASSICAL_STRENGTH


def test_a_strength_above_every_mechanism_takes_the_strongest(both_liboqs_states):
    """No ladder covers 512-bit classical security. Returning the top rung beats returning
    nothing: the report says ML-KEM-1024, not silence."""
    recommendation = recommend(
        finding(
            purpose=CryptoPurpose.KEY_ESTABLISHMENT,
            primitive=CryptoPrimitive.KEY_AGREE,
            classical_security_level=512,
        )
    )
    assert recommendation.primary.name == "ML-KEM-1024"
    assert recommendation.primary.nist_quantum_security_level == 5


# --------------------------------------------------------------------------- bulk mapping


def test_recommend_all_is_keyed_by_finding_id(both_liboqs_states):
    vulnerable = finding()
    safe = finding(status=CryptoStatus.PQC)
    mapping = recommend_all([vulnerable, safe])
    assert set(mapping) == {vulnerable.finding_id}


# ------------------------------------------------------------------------ liboqs bridge


def test_the_bridge_never_changes_the_advice(monkeypatch):
    """The done-when condition from the plan, asserted directly."""
    candidates = [
        finding(purpose=CryptoPurpose.KEY_ESTABLISHMENT, primitive=CryptoPrimitive.KEY_AGREE),
        finding(purpose=CryptoPurpose.DIGITAL_SIGNATURE),
        finding(purpose=CryptoPurpose.UNKNOWN, primitive=CryptoPrimitive.PKE),
        finding(purpose=CryptoPurpose.ENCRYPTION, primitive=CryptoPrimitive.PKE),
        finding(classical_security_level=256),
    ]
    with_liboqs = [recommend(f) for f in candidates]
    monkeypatch.setattr(liboqs_bridge, "OQS_AVAILABLE", False)
    without_liboqs = [recommend(f) for f in candidates]
    assert with_liboqs == without_liboqs


def test_describe_says_unavailable_without_raising(monkeypatch):
    monkeypatch.setattr(liboqs_bridge, "OQS_AVAILABLE", False)
    for mechanism in CATALOG:
        assert liboqs_bridge.describe(mechanism) == {"liboqs": "unavailable"}
    assert liboqs_bridge.verify_catalog() == {}
    assert liboqs_bridge.enabled_mechanisms() == frozenset()
    assert liboqs_bridge.liboqs_version() is None


@pytest.mark.skipif(not liboqs_bridge.OQS_AVAILABLE, reason="liboqs is not installed")
def test_every_catalog_mechanism_exists_in_the_installed_liboqs():
    """The bridge's real job: catch a catalog name that no implementation answers to."""
    assert liboqs_bridge.verify_catalog() == {}


@pytest.mark.skipif(not liboqs_bridge.OQS_AVAILABLE, reason="liboqs is not installed")
def test_liboqs_agrees_with_our_claimed_nist_categories():
    assert liboqs_bridge.category_disagreements() == {}


@pytest.mark.skipif(not liboqs_bridge.OQS_AVAILABLE, reason="liboqs is not installed")
def test_describe_adds_sizes_that_are_the_real_migration_cost():
    signature = liboqs_bridge.describe(catalog.ML_DSA_65)
    assert signature["public_key_bytes"] == 1952
    assert signature["signature_bytes"] == 3309

    kem = liboqs_bridge.describe(catalog.ML_KEM_768)
    assert kem["public_key_bytes"] == 1184
    assert kem["ciphertext_bytes"] == 1088
    assert kem["shared_secret_bytes"] == 32

    conservative = liboqs_bridge.describe(catalog.SLH_DSA_128S)
    assert conservative["public_key_bytes"] == 32
    assert conservative["signature_bytes"] == 7856


@pytest.mark.skipif(not liboqs_bridge.OQS_AVAILABLE, reason="liboqs is not installed")
def test_a_mechanism_absent_from_the_build_is_reported_not_raised():
    missing = catalog.Mechanism(
        name="NOT-REAL-256",
        family="NOT-REAL",
        purpose=CryptoPurpose.DIGITAL_SIGNATURE,
        primitive=CryptoPrimitive.SIGNATURE,
        nist_quantum_security_level=5,
        classical_security_level=256,
        standard="none",
        standard_status=StandardStatus.DRAFT,
        rationale="Exists only to prove the bridge degrades instead of raising, in a draft.",
        liboqs_name="NOT-REAL-256",
    )
    assert liboqs_bridge.describe(missing) == {
        "liboqs": "missing_from_build",
        "liboqs_name": "NOT-REAL-256",
    }


def test_an_unmapped_mechanism_is_reported_not_raised():
    unmapped = catalog.Mechanism(
        name="UNMAPPED-256",
        family="UNMAPPED",
        purpose=CryptoPurpose.DIGITAL_SIGNATURE,
        primitive=CryptoPrimitive.SIGNATURE,
        nist_quantum_security_level=5,
        classical_security_level=256,
        standard="none",
        standard_status=StandardStatus.DRAFT,
        rationale="A catalog entry with no liboqs mapping at all, for a draft standard.",
    )
    if liboqs_bridge.OQS_AVAILABLE:
        assert liboqs_bridge.describe(unmapped) == {"liboqs": "not_mapped"}


# --------------------------------------------------- liboqs naming diverges from the specs


@pytest.mark.skipif(not liboqs_bridge.OQS_AVAILABLE, reason="liboqs is not installed")
def test_catalog_names_follow_the_standards_not_the_library():
    """liboqs calls these `SLH_DSA_PURE_SHA2_128S` and `Falcon-512`; the reports must not."""
    assert catalog.SLH_DSA_128S.name == "SLH-DSA-SHA2-128s"
    assert catalog.SLH_DSA_128S.liboqs_name == "SLH_DSA_PURE_SHA2_128S"
    assert catalog.FN_DSA_512.name == "FN-DSA-512"
    assert catalog.FN_DSA_512.liboqs_name == "Falcon-512"
    assert catalog.HQC_192.name == "HQC-192"
    assert catalog.HQC_192.liboqs_name == "HQC-3"
