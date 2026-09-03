"""Detector engine: RawSymbolUsage -> CryptoFinding.

The engine is deliberately dumb; all cryptographic knowledge lives in the rule table.
These tests use hand-built usages so they exercise the engine, not the analyzer.
"""

import pytest

from cryptolens.analyzers.python_ast import ArgKind, ArgValue, RawSymbolUsage
from cryptolens.detectors.engine import DetectorEngine, detect
from cryptolens.detectors.rules import PYCA, PYCA_ASYM, PYCA_CIPHERS, RULES
from cryptolens.model import (
    AssetType,
    CryptoFunction,
    CryptoMode,
    CryptoPrimitive,
    CryptoPurpose,
    SourceLocation,
)


def usage(name, *, args=(), kwargs=None, confidence=1.0, parent=None) -> RawSymbolUsage:
    return RawSymbolUsage(
        resolved_name=name,
        location=SourceLocation("mod.py", 1),
        raw=f"{name}(...)",
        args=list(args),
        kwargs=dict(kwargs or {}),
        confidence=confidence,
        parent_name=parent,
    )


def call_arg(resolved_name) -> ArgValue:
    return ArgValue(ArgKind.CALL, resolved_name, resolved_name=resolved_name)


def literal_arg(value) -> ArgValue:
    return ArgValue(ArgKind.LITERAL, repr(value), value=value)


def name_arg(resolved_name) -> ArgValue:
    return ArgValue(ArgKind.NAME, resolved_name, resolved_name=resolved_name)


# ---------------------------------------------------------------------------- matching


def test_matching_is_exact_on_the_qualified_name():
    assert detect([usage("hashlib.sha256")])[0].algorithm == "SHA-256"
    assert detect([usage("mypackage.sha256")]) == []
    assert detect([usage(None)]) == []


def test_rule_table_has_no_duplicate_match_keys():
    matches = [rule.match for rule in RULES]
    assert len(matches) == len(set(matches))


def test_finding_records_which_rule_produced_it():
    assert detect([usage("hashlib.md5")])[0].detector == "hashlib.md5"


# ------------------------------------------------------------------------- suppression


def test_an_argument_consumed_by_its_parent_is_not_reported_twice():
    """Cipher reads the mode out of its arguments, so modes.GCM must not also fire."""
    findings = detect(
        [
            usage(f"{PYCA_CIPHERS}.Cipher", args=[
                call_arg(f"{PYCA_CIPHERS}.algorithms.AES"),
                call_arg(f"{PYCA_CIPHERS}.modes.GCM"),
            ]),
            usage(f"{PYCA_CIPHERS}.algorithms.AES", parent=f"{PYCA_CIPHERS}.Cipher"),
        ]
    )
    assert [f.algorithm for f in findings] == ["AES"]


def test_a_bare_algorithm_with_no_parent_still_reports():
    findings = detect([usage(f"{PYCA_CIPHERS}.algorithms.AES")])
    assert [f.algorithm for f in findings] == ["AES"]


def test_a_non_emitting_rule_suppresses_its_child_without_producing_a_finding():
    """MGF1 exists only to stop its hash argument being counted as a separate digest."""
    findings = detect(
        [
            usage(f"{PYCA_ASYM}.padding.MGF1", args=[call_arg(f"{PYCA}.hashes.SHA256")]),
            usage(f"{PYCA}.hashes.SHA256", parent=f"{PYCA_ASYM}.padding.MGF1"),
        ]
    )
    assert findings == []


# -------------------------------------------------------------------- value predicates


def test_attribute_assignment_matches_only_the_insecure_value():
    disabled = detect([usage("<assign>.verify_mode", args=[name_arg("ssl.CERT_NONE")])])
    assert [f.detector for f in disabled] == ["ssl.verification_disabled"]
    assert disabled[0].asset_type is AssetType.PROTOCOL
    assert detect([usage("<assign>.verify_mode", args=[name_arg("ssl.CERT_REQUIRED")])]) == []


def test_literal_value_predicate():
    assert detect([usage("<assign>.check_hostname", args=[literal_arg(False)])])
    assert detect([usage("<assign>.check_hostname", args=[literal_arg(True)])]) == []


def test_value_predicate_with_no_arguments_does_not_match():
    assert detect([usage("<assign>.verify_mode")]) == []


# ------------------------------------------------------------------ argument extraction


@pytest.mark.parametrize(
    ("kwargs", "args", "expected"),
    [({"key_size": literal_arg(2048)}, (), 2048), ({}, (literal_arg(65537), literal_arg(4096)), 4096)],
    ids=["keyword", "positional"],
)
def test_rsa_key_size_from_either_position(kwargs, args, expected):
    finding = detect([usage(f"{PYCA_ASYM}.rsa.generate_private_key", args=args, kwargs=kwargs)])[0]
    assert finding.key_size == expected


@pytest.mark.parametrize(("bits", "strength"), [(1024, 80), (2048, 112), (4096, 152)])
def test_rsa_classical_strength_follows_the_key_size(bits, strength):
    finding = detect(
        [usage(f"{PYCA_ASYM}.rsa.generate_private_key", kwargs={"key_size": literal_arg(bits)})]
    )[0]
    assert finding.classical_security_level == strength


def test_cipher_takes_algorithm_and_mode_from_its_arguments():
    finding = detect(
        [
            usage(f"{PYCA_CIPHERS}.Cipher", args=[
                call_arg(f"{PYCA_CIPHERS}.algorithms.TripleDES"),
                call_arg(f"{PYCA_CIPHERS}.modes.ECB"),
            ])
        ]
    )[0]
    assert (finding.algorithm, finding.mode) == ("3DES", CryptoMode.ECB)
    assert finding.primitive is CryptoPrimitive.BLOCK_CIPHER
    assert finding.classical_security_level == 112


def test_unrecognised_cipher_arguments_leave_the_defaults_alone():
    finding = detect([usage(f"{PYCA_CIPHERS}.Cipher", args=[call_arg("mypkg.MyCipher")])])[0]
    assert finding.algorithm == "unknown"
    assert finding.mode is CryptoMode.UNKNOWN


def test_elliptic_curve_populates_parameter_set_and_strength():
    finding = detect(
        [usage(f"{PYCA_ASYM}.ec.generate_private_key", args=[call_arg(f"{PYCA_ASYM}.ec.SECP384R1")])]
    )[0]
    assert (finding.parameter_set, finding.curve) == ("SECP384R1", "SECP384R1")
    assert finding.classical_security_level == 192


def test_bare_ec_keygen_does_not_guess_between_signature_and_key_agreement():
    """Purpose must come from ECDSA/ECDH usage, never from the key generation call."""
    finding = detect([usage(f"{PYCA_ASYM}.ec.generate_private_key")])[0]
    assert finding.algorithm == "EC"
    assert finding.purpose is CryptoPurpose.UNKNOWN
    assert finding.primitive is CryptoPrimitive.UNKNOWN


def test_hmac_composes_its_algorithm_from_the_digest_argument():
    finding = detect([usage("hmac.new", args=[name_arg("key"), name_arg("msg"), call_arg("hashlib.sha512")])])[0]
    assert finding.algorithm == "HMAC-SHA-512"
    assert finding.purpose is CryptoPurpose.MAC


def test_hmac_reads_the_digest_from_a_keyword_too():
    finding = detect([usage("hmac.new", kwargs={"digestmod": call_arg("hashlib.sha256")})])[0]
    assert finding.algorithm == "HMAC-SHA-256"


def test_hashlib_new_takes_its_algorithm_from_the_string_literal():
    finding = detect([usage("hashlib.new", args=[literal_arg("md5")])])[0]
    assert finding.algorithm == "MD5"
    assert finding.crypto_functions == [CryptoFunction.DIGEST]


def test_pbkdf2_keeps_its_own_name_and_appends_the_digest():
    finding = detect([usage("hashlib.pbkdf2_hmac", args=[literal_arg("sha256")])])[0]
    assert finding.algorithm == "PBKDF2-SHA-256"
    assert finding.purpose is CryptoPurpose.KEY_DERIVATION


# ------------------------------------------------------------------------- confidence


def test_confidence_is_inherited_from_the_usage():
    assert detect([usage("hashlib.sha256", confidence=0.5)])[0].confidence == 0.5


def test_a_rule_can_cap_confidence_below_the_usage():
    finding = detect([usage("getattr", args=[name_arg("hashlib")], confidence=1.0)])[0]
    assert finding.confidence == 0.3


def test_the_lower_of_usage_and_rule_confidence_wins():
    finding = detect([usage("getattr", args=[name_arg("hashlib")], confidence=0.2)])[0]
    assert finding.confidence == 0.2


# ------------------------------------------------------------------------ substitution


def test_a_custom_rule_table_replaces_the_default():
    engine = DetectorEngine(rules=[])
    assert engine.detect([usage("hashlib.sha256")]) == []
