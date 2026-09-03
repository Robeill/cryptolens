"""Discovery -> analyzer -> detectors over the whole development fixture repo.

This is the first point where the pipeline produces CryptoFinding objects, so it is also
where the shape of the eventual report can be sanity-checked.
"""

from pathlib import Path

import pytest

from cryptolens.analyzers.python_ast import analyze_file
from cryptolens.detectors.engine import detect
from cryptolens.discovery.source_files import discover_source_files
from cryptolens.model import CryptoFunction, CryptoMode, CryptoPrimitive, CryptoPurpose

EXAMPLE_REPO = Path(__file__).resolve().parent.parent / "fixtures" / "example_repo"


@pytest.fixture(scope="module")
def findings_by_module() -> dict[str, list]:
    return {
        path.name: detect(analyze_file(path, EXAMPLE_REPO))
        for path in discover_source_files(EXAMPLE_REPO)
    }


def algorithms(findings) -> set[str]:
    return {f.algorithm for f in findings}


# ------------------------------------------------------------------------------ shape


def test_every_module_produces_at_least_one_finding(findings_by_module):
    assert not [name for name, rows in findings_by_module.items() if not rows]


def test_findings_are_deterministic_across_runs():
    first = detect(analyze_file(EXAMPLE_REPO / "hash_sha256.py", EXAMPLE_REPO))
    second = detect(analyze_file(EXAMPLE_REPO / "hash_sha256.py", EXAMPLE_REPO))
    assert [f.finding_id for f in first] == [f.finding_id for f in second]


def test_every_finding_is_serialisable_and_located(findings_by_module):
    import json

    for module, rows in findings_by_module.items():
        for finding in rows:
            assert finding.location.file == module
            assert finding.location.line > 0
            assert json.dumps(finding.to_dict())


def test_finding_ids_are_unique_per_call_site(findings_by_module):
    """Two findings on one line must still differ -- they differ by algorithm."""
    rows = [f for module in findings_by_module.values() for f in module]
    assert len({f.finding_id for f in rows}) == len(rows)


# --------------------------------------------------------------------------- per module


def test_weak_and_strong_digests_are_both_detected(findings_by_module):
    found = algorithms(findings_by_module["hash_sha256.py"])
    assert {"SHA-256", "SHA-512", "SHA3-256"} <= found
    assert {"MD5", "SHA-1"} <= found
    assert "HMAC-SHA-256" in found
    assert "PBKDF2-SHA-256" in found


def test_cipher_modes_are_carried_onto_the_finding(findings_by_module):
    ciphers = [f for f in findings_by_module["aes_encrypt.py"] if f.algorithm in {"AES", "3DES"}]
    assert {f.mode for f in ciphers} == {CryptoMode.GCM, CryptoMode.CBC, CryptoMode.ECB}
    assert all(f.primitive is CryptoPrimitive.BLOCK_CIPHER for f in ciphers)


def test_rsa_key_sizes_survive_to_the_finding(findings_by_module):
    rsa = [f for f in findings_by_module["rsa_signing.py"] if f.algorithm == "RSA"]
    assert {1024, 2048} <= {f.key_size for f in rsa if f.key_size}


def test_the_ecdh_versus_ecdsa_distinction_is_visible(findings_by_module):
    """The whole purpose-based post-quantum urgency argument depends on this."""
    rows = findings_by_module["ecdsa_sign.py"]
    ecdh = [f for f in rows if f.algorithm == "ECDH"]
    ecdsa = [f for f in rows if f.algorithm == "ECDSA"]
    assert [f.purpose for f in ecdh] == [CryptoPurpose.KEY_ESTABLISHMENT]
    assert ecdsa and all(f.purpose is CryptoPurpose.DIGITAL_SIGNATURE for f in ecdsa)


def test_curves_are_recorded_on_key_generation(findings_by_module):
    curves = {f.parameter_set for f in findings_by_module["ecdsa_sign.py"] if f.parameter_set}
    assert {"SECP256R1", "SECP384R1", "Ed25519"} <= curves


def test_aliased_imports_produce_the_same_findings_as_direct_ones(findings_by_module):
    found = algorithms(findings_by_module["aliased_imports.py"])
    assert {"SHA-256", "HMAC-SHA-256", "EC"} <= found


def test_insecure_tls_configuration_is_detected(findings_by_module):
    """Attribute assignment, not a call -- the pattern Bandit's B501 covers."""
    detectors = {f.detector for f in findings_by_module["tls_config.py"]}
    assert "ssl.verification_disabled" in detectors
    assert "ssl.hostname_check_disabled" in detectors
    assert "ssl.unverified_context" in detectors


def test_ambiguous_and_dynamic_cases_are_reported_at_reduced_confidence(findings_by_module):
    ambiguous = [f for f in findings_by_module["variable_algorithm.py"] if f.confidence < 1.0]
    assert {f.algorithm for f in ambiguous} == {"SHA-256", "MD5"}

    dynamic = findings_by_module["dynamic_case.py"]
    assert all(f.confidence < 1.0 for f in dynamic)
    assert "SHA-384" in algorithms(dynamic)


def test_secure_random_is_recorded_but_distinguishable_from_hashing(findings_by_module):
    csprng = [f for f in findings_by_module["hash_sha256.py"] if f.algorithm == "CSPRNG"]
    assert [f.purpose for f in csprng] == [CryptoPurpose.RANDOM]
    assert csprng[0].crypto_functions == [CryptoFunction.GENERATE]


def test_jwt_algorithms_are_resolved_from_their_jwa_names(findings_by_module):
    found = algorithms(findings_by_module["jwt_tokens.py"])
    assert {"HMAC-SHA-256", "RSA", "ECDSA", "Ed25519", "none"} <= found


def test_jwt_hmac_is_a_mac_and_rsa_is_a_signature(findings_by_module):
    rows = findings_by_module["jwt_tokens.py"]
    assert {f.purpose for f in rows if f.algorithm == "HMAC-SHA-256"} == {CryptoPurpose.MAC}
    assert {f.purpose for f in rows if f.algorithm == "RSA"} == {CryptoPurpose.DIGITAL_SIGNATURE}


def test_jwt_verification_disabled_is_detected_in_both_spellings(findings_by_module):
    disabled = [
        f for f in findings_by_module["jwt_tokens.py"] if f.detector == "jwt.verification_disabled"
    ]
    assert {f.location.line for f in disabled} == {45, 49}
