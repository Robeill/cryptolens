"""End-to-end pass over the development fixture repo: discovery -> analyzer.

This is the DEVELOPMENT fixture set. Detectors are built against it, so it must never be
used to measure precision or recall -- that is what the held-out `eval_repo` at Step 14 is
for, and its ground truth is written before the scanner is ever run on it.
"""

from pathlib import Path

import pytest

from cryptolens.analyzers.python_ast import analyze_file
from cryptolens.analyzers.symbol_table import CONFIDENCE_CONDITIONAL, CONFIDENCE_MULTIPLE
from cryptolens.discovery.source_files import discover_source_files

EXAMPLE_REPO = Path(__file__).resolve().parent.parent / "fixtures" / "example_repo"

EXPECTED_MODULES = {
    "aes_encrypt.py",
    "aliased_imports.py",
    "dynamic_case.py",
    "ecdsa_sign.py",
    "hash_sha256.py",
    "jwt_tokens.py",
    "rsa_signing.py",
    "tls_config.py",
    "variable_algorithm.py",
}

CRYPTOGRAPHY = "cryptography.hazmat.primitives"


@pytest.fixture(scope="module")
def usages_by_module() -> dict[str, list]:
    return {
        path.name: analyze_file(path, EXAMPLE_REPO)
        for path in discover_source_files(EXAMPLE_REPO)
    }


def names(usages) -> set[str]:
    return {u.resolved_name for u in usages if u.resolved_name}


# ------------------------------------------------------------------------------ shape


def test_discovery_finds_exactly_the_expected_modules():
    assert {p.name for p in discover_source_files(EXAMPLE_REPO)} == EXPECTED_MODULES


def test_every_module_yields_usages_and_none_of_them_crash(usages_by_module):
    assert set(usages_by_module) == EXPECTED_MODULES
    empty = [name for name, rows in usages_by_module.items() if not rows]
    assert empty == []


def test_locations_are_relative_to_the_scan_root(usages_by_module):
    for module, rows in usages_by_module.items():
        for usage in rows:
            assert usage.location.file == module
            assert usage.location.line > 0


def test_dynamic_usages_stay_a_small_minority(usages_by_module):
    rows = [u for module in usages_by_module.values() for u in module]
    dynamic = [u for u in rows if u.is_dynamic]
    assert len(dynamic) / len(rows) < 0.15


# --------------------------------------------------------------------------- per module


def test_rsa_signing_captures_key_sizes_and_padding(usages_by_module):
    rows = usages_by_module["rsa_signing.py"]
    keygen = [u for u in rows if u.resolved_name.endswith("rsa.generate_private_key")]
    assert sorted(u.kwargs["key_size"].value for u in keygen) == [1024, 2048]
    assert {
        f"{CRYPTOGRAPHY}.asymmetric.padding.PSS",
        f"{CRYPTOGRAPHY}.asymmetric.padding.PKCS1v15",
        f"{CRYPTOGRAPHY}.asymmetric.padding.OAEP",
    } <= names(rows)


def test_aes_encrypt_captures_every_mode_as_a_cipher_argument(usages_by_module):
    rows = usages_by_module["aes_encrypt.py"]
    ciphers = [u for u in rows if u.resolved_name.endswith("ciphers.Cipher")]
    modes = {u.args[1].resolved_name.rsplit(".", 1)[-1] for u in ciphers}
    assert modes == {"GCM", "CBC", "ECB"}
    algorithms = {u.args[0].resolved_name.rsplit(".", 1)[-1] for u in ciphers}
    assert algorithms == {"AES", "TripleDES"}


def test_hash_module_covers_strong_and_weak_digests(usages_by_module):
    found = names(usages_by_module["hash_sha256.py"])
    assert {"hashlib.sha256", "hashlib.sha512", "hashlib.sha3_256"} <= found
    assert {"hashlib.md5", "hashlib.sha1"} <= found
    assert {"hmac.new", "hashlib.pbkdf2_hmac", "secrets.token_hex"} <= found


def test_ecdsa_module_distinguishes_signature_from_key_establishment(usages_by_module):
    """ECDH and ECDSA are the pair the purpose-based PQC urgency argument rests on."""
    found = names(usages_by_module["ecdsa_sign.py"])
    assert f"{CRYPTOGRAPHY}.asymmetric.ec.ECDSA" in found
    assert f"{CRYPTOGRAPHY}.asymmetric.ec.ECDH" in found
    assert f"{CRYPTOGRAPHY}.asymmetric.ec.SECP256R1" in found
    assert f"{CRYPTOGRAPHY}.asymmetric.ed25519.Ed25519PrivateKey.generate" in found


def test_aliased_imports_all_collapse_to_canonical_names(usages_by_module):
    found = names(usages_by_module["aliased_imports.py"])
    assert "hashlib.sha256" in found
    assert "hmac.new" in found
    assert f"{CRYPTOGRAPHY}.hashes.SHA256" in found
    assert f"{CRYPTOGRAPHY}.asymmetric.ec.generate_private_key" in found
    assert not any(name.startswith(("hl.", "elliptic.", "digest_function")) for name in found)


def test_tls_config_reports_context_construction(usages_by_module):
    found = names(usages_by_module["tls_config.py"])
    assert {"ssl.SSLContext", "ssl.create_default_context", "ssl._create_unverified_context"} <= found


# --------------------------------------------------------------- ambiguity and confidence


def test_conditional_import_yields_both_backends(usages_by_module):
    rows = usages_by_module["variable_algorithm.py"]
    conditional = [u for u in rows if u.raw == "accelerated_sha256(payload)"]
    assert sorted(u.resolved_name for u in conditional) == [
        "fast_hashes.sha256",
        "hashlib.sha256",
    ]
    assert all(u.confidence == CONFIDENCE_CONDITIONAL for u in conditional)


def test_reassigned_algorithm_reports_both_candidates(usages_by_module):
    rows = usages_by_module["variable_algorithm.py"]
    ambiguous = [u for u in rows if u.raw == "algorithm(payload)" and u.confidence == CONFIDENCE_MULTIPLE]
    assert sorted(u.resolved_name for u in ambiguous) == ["hashlib.md5", "hashlib.sha256"]


def test_shadowed_name_is_not_reported_as_hashlib(usages_by_module):
    rows = usages_by_module["variable_algorithm.py"]
    assert not [u for u in rows if u.raw == "hashlib.sha256(payload)"]


def test_dynamic_module_reports_dispatch_and_builtins(usages_by_module):
    rows = usages_by_module["dynamic_case.py"]
    found = names(rows)
    assert {"getattr", "eval", "importlib.import_module"} <= found
    assert [u for u in rows if u.is_dynamic]
    assert "hashlib.sha384" in found
