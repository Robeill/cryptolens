"""Algorithm normalization.

Defined in one place because three separate things depend on it agreeing with itself:
CBOM component dedupe (Step 11), evaluation matching (Step 15) and report grouping.
"""

import pytest

from cryptolens.detectors.normalize import normalize_algorithm, normalize_composite


@pytest.mark.parametrize(
    "spelling",
    ["sha256", "SHA256", "SHA-256", "sha_256", "  sha256  ", "Sha.256"],
)
def test_every_spelling_of_a_digest_collapses(spelling):
    assert normalize_algorithm(spelling) == "SHA-256"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("md5", "MD5"),
        ("sha1", "SHA-1"),
        ("sha", "SHA-1"),
        ("sha3_256", "SHA3-256"),
        ("tripledes", "3DES"),
        ("des3", "3DES"),
        ("arc4", "RC4"),
        ("chacha20", "ChaCha20"),
        ("ml-kem", "ML-KEM"),
        ("ed25519", "Ed25519"),
    ],
)
def test_known_aliases(raw, expected):
    assert normalize_algorithm(raw) == expected


@pytest.mark.parametrize("value", [None, "", "   "])
def test_missing_names_become_the_unknown_sentinel(value):
    assert normalize_algorithm(value) == "unknown"


def test_unknown_algorithms_are_passed_through_unchanged():
    """Never invent a canonical name for something not in the table."""
    assert normalize_algorithm("Kyber768-Custom") == "Kyber768-Custom"


def test_hyphenated_compounds_normalize_both_halves():
    assert normalize_algorithm("hmac-sha256") == "HMAC-SHA-256"


def test_composite_joins_normalized_parts_and_skips_blanks():
    assert normalize_composite("hmac", "sha256") == "HMAC-SHA-256"
    assert normalize_composite("pbkdf2", None, "sha512") == "PBKDF2-SHA-512"


def test_normalization_is_idempotent():
    once = normalize_algorithm("sha_256")
    assert normalize_algorithm(once) == once
