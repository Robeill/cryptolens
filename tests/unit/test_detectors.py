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


def test_several_rules_may_share_a_match_key_but_not_a_detector():
    """jwt.decode carries three rules: algorithms, verify=False, options={...}."""
    keys = [(rule.match, rule.detector, rule.value_kwarg) for rule in RULES]
    assert len(keys) == len(set(keys))
    assert sum(1 for rule in RULES if rule.match == "jwt.decode") == 3


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


# ------------------------------------------------------------------------------- JWT


@pytest.mark.parametrize(
    ("jwa", "algorithm", "purpose", "primitive"),
    [
        ("HS256", "HMAC-SHA-256", CryptoPurpose.MAC, CryptoPrimitive.MAC),
        ("HS512", "HMAC-SHA-512", CryptoPurpose.MAC, CryptoPrimitive.MAC),
        ("RS256", "RSA", CryptoPurpose.DIGITAL_SIGNATURE, CryptoPrimitive.SIGNATURE),
        ("PS384", "RSA", CryptoPurpose.DIGITAL_SIGNATURE, CryptoPrimitive.SIGNATURE),
        ("ES256", "ECDSA", CryptoPurpose.DIGITAL_SIGNATURE, CryptoPrimitive.SIGNATURE),
        ("EdDSA", "Ed25519", CryptoPurpose.DIGITAL_SIGNATURE, CryptoPrimitive.SIGNATURE),
        ("none", "none", CryptoPurpose.DIGITAL_SIGNATURE, CryptoPrimitive.OTHER),
    ],
)
def test_jwa_names_map_to_real_algorithms(jwa, algorithm, purpose, primitive):
    """HS256 is a MAC, not a signature -- the distinction matters for PQC urgency."""
    finding = detect([usage("jwt.encode", kwargs={"algorithm": literal_arg(jwa)})])[0]
    assert (finding.algorithm, finding.purpose, finding.primitive) == (algorithm, purpose, primitive)


def test_ec_jwt_algorithms_carry_their_implied_curve():
    finding = detect([usage("jwt.encode", kwargs={"algorithm": literal_arg("ES512")})])[0]
    assert finding.parameter_set == "SECP521R1"
    assert finding.classical_security_level == 256


def test_alg_none_is_recorded_with_zero_security():
    finding = detect([usage("jwt.encode", kwargs={"algorithm": literal_arg("none")})])[0]
    assert finding.classical_security_level == 0


def test_a_list_of_accepted_algorithms_yields_one_finding_each():
    findings = detect(
        [usage("jwt.decode", kwargs={"algorithms": literal_arg(["HS256", "none"])})]
    )
    assert sorted(f.algorithm for f in findings) == ["HMAC-SHA-256", "none"]


def test_an_undetermined_jwt_algorithm_still_produces_a_finding():
    """algorithm=chosen -- a variable. Recall matters more than precision here."""
    findings = detect([usage("jwt.encode", kwargs={"algorithm": name_arg("chosen")})])
    assert [f.algorithm for f in findings] == ["JWT"]


def test_unknown_jwa_names_fall_back_rather_than_being_invented():
    findings = detect([usage("jwt.encode", kwargs={"algorithm": literal_arg("XX999")})])
    assert [f.algorithm for f in findings] == ["JWT"]


@pytest.mark.parametrize(
    "kwargs",
    [
        {"verify": literal_arg(False)},
        {"options": literal_arg({"verify_signature": False})},
    ],
    ids=["legacy-verify-flag", "options-dict"],
)
def test_disabled_signature_verification_is_detected(kwargs):
    detectors = {f.detector for f in detect([usage("jwt.decode", kwargs=kwargs)])}
    assert "jwt.verification_disabled" in detectors


@pytest.mark.parametrize(
    "kwargs",
    [
        {"verify": literal_arg(True)},
        {"options": literal_arg({"verify_signature": True})},
        {"options": literal_arg({"verify_exp": False})},
    ],
    ids=["verify-true", "signature-verified", "unrelated-option"],
)
def test_verification_left_on_is_not_reported(kwargs):
    detectors = {f.detector for f in detect([usage("jwt.decode", kwargs=kwargs)])}
    assert "jwt.verification_disabled" not in detectors


def test_two_rules_firing_at_one_call_site_produce_distinct_findings():
    """Both are true at once, so both are reported -- and their ids must differ."""
    findings = detect([usage("jwt.decode", kwargs={"verify": literal_arg(False)})])
    assert len(findings) == 2
    assert len({f.finding_id for f in findings}) == 2


def test_jose_is_recognised_as_well_as_pyjwt():
    finding = detect([usage("jose.jwt.encode", kwargs={"algorithm": literal_arg("HS256")})])[0]
    assert finding.algorithm == "HMAC-SHA-256"
