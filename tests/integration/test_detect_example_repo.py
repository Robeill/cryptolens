"""Discovery -> analyzer -> detectors over the whole development fixture repo.

This is the first point where the pipeline produces CryptoFinding objects, so it is also
where the shape of the eventual report can be sanity-checked.
"""

from pathlib import Path

import pytest

from cryptolens.analyzers.python_ast import analyze_file
from cryptolens.detectors.engine import detect
from cryptolens.detectors.normalize import normalize_algorithm
from cryptolens.discovery.source_files import discover_source_files
from cryptolens.model import (
    AssetType,
    CryptoFunction,
    CryptoMode,
    CryptoPrimitive,
    CryptoPurpose,
    MigrationStatus,
)

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
    ecdsa = [f for f in rows if f.algorithm.startswith("ECDSA")]
    assert [f.purpose for f in ecdh] == [CryptoPurpose.KEY_ESTABLISHMENT]
    assert ecdsa and all(f.purpose is CryptoPurpose.DIGITAL_SIGNATURE for f in ecdsa)
    assert {f.algorithm for f in ecdsa} == {"ECDSA-SHA-256"}, "the digest belongs in the name"


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


def test_one_algorithm_never_gets_two_different_migration_statuses(findings_by_module):
    """`migration_status` is derived, so it cannot disagree with itself across call sites."""
    by_algorithm: dict[str, set] = {}
    for rows in findings_by_module.values():
        for f in rows:
            by_algorithm.setdefault(f.algorithm, set()).add(f.migration_status)
    contradictory = {name: s for name, s in by_algorithm.items() if len(s) > 1}
    assert contradictory == {}


def test_migration_status_splits_the_fixture_repo_the_way_the_thesis_argues(findings_by_module):
    status_of = {}
    for rows in findings_by_module.values():
        for f in rows:
            status_of.setdefault(f.algorithm, f.migration_status)

    assert status_of["RSA"] is MigrationStatus.QUANTUM_VULNERABLE
    assert status_of["ECDSA"] is MigrationStatus.QUANTUM_VULNERABLE
    assert status_of["ECDH"] is MigrationStatus.QUANTUM_VULNERABLE
    assert status_of["Ed25519"] is MigrationStatus.QUANTUM_VULNERABLE
    assert status_of["EC"] is MigrationStatus.QUANTUM_VULNERABLE

    assert status_of["HMAC-SHA-256"] is MigrationStatus.QUANTUM_SAFE
    assert status_of["SHA-256"] is MigrationStatus.QUANTUM_SAFE
    assert status_of["PBKDF2-SHA-256"] is MigrationStatus.QUANTUM_SAFE

    assert status_of["MD5"] is MigrationStatus.NEEDS_REVIEW
    assert status_of["SHA-1"] is MigrationStatus.NEEDS_REVIEW
    assert status_of["3DES"] is MigrationStatus.NEEDS_REVIEW

    assert status_of["none"] is MigrationStatus.NOT_APPLICABLE


def test_a_bare_ec_keygen_is_vulnerable_even_though_its_purpose_is_undetermined(
    findings_by_module,
):
    """We refuse to guess ECDSA vs ECDH, but the named curve is enough to know Shor breaks it."""
    ec = [f for f in findings_by_module["ecdsa_sign.py"] if f.algorithm == "EC"]
    assert ec
    assert {f.purpose for f in ec} == {CryptoPurpose.UNKNOWN}
    assert {f.migration_status for f in ec} == {MigrationStatus.QUANTUM_VULNERABLE}


# ------------------------------------------------------------------ identity invariants


def collisions(findings) -> dict:
    """Group by the triple the Day 23 evaluation matches ground truth on."""
    grouped: dict[tuple, list] = {}
    for finding in findings:
        key = (
            finding.location.file,
            finding.location.line,
            normalize_algorithm(finding.algorithm),
        )
        grouped.setdefault(key, []).append(finding)
    return {key: rows for key, rows in grouped.items() if len(rows) > 1}


def test_no_two_findings_share_a_file_line_and_algorithm(findings_by_module):
    """The evaluation matches on `(relative_path, line, normalized_algorithm)`. Two findings
    against one ground-truth entry is a guaranteed false positive that says nothing about
    detection quality, so rule collisions have to be caught here rather than measured later.

    Deliberately general: any future rule that collides fails this, not just the JWT pair
    that prompted it.
    """
    everything = [f for rows in findings_by_module.values() for f in rows]
    assert collisions(everything) == {}


def test_a_configuration_weakness_is_a_different_finding_from_the_call_it_weakens():
    """`jwt.decode(token, verify=False)` is two facts about one line: a JWT is verified here,
    and it is not really. They must not share an identity."""
    from cryptolens.analyzers.python_ast import analyze_source

    source = "import jwt\n\n\ndef read(token):\n    return jwt.decode(token, verify=False)\n"
    findings = detect(analyze_source(source, "one_line.py"))
    assert collisions(findings) == {}
    assert {f.algorithm for f in findings} == {"JWT", "JWT-unverified"}
    assert {f.location.line for f in findings} == {5}


def test_the_same_holds_when_tls_is_configured_on_one_line():
    """The TLS rules had the identical latent collision; it was hidden only because the
    fixture puts each assignment on its own line."""
    from cryptolens.analyzers.python_ast import analyze_source

    source = (
        "import ssl\n\n\n"
        "def context():\n"
        "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.verify_mode = ssl.CERT_NONE\n"
        "    return ctx\n"
    )
    findings = detect(analyze_source(source, "one_line.py"))
    assert collisions(findings) == {}
    assert {f.algorithm for f in findings} == {"TLS", "TLS-unverified"}


def test_hostname_checking_and_certificate_verification_are_distinct_weaknesses():
    from cryptolens.analyzers.python_ast import analyze_source

    source = (
        "import ssl\n\n\n"
        "def context():\n"
        "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n"
        "    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE\n"
        "    return ctx\n"
    )
    findings = detect(analyze_source(source, "one_line.py"))
    assert collisions(findings) == {}
    assert "TLS-unverified" in {f.algorithm for f in findings}
    assert "TLS-unverified-hostname" in {f.algorithm for f in findings}


def test_the_verification_disabled_signal_survives_aggregation(findings_by_module):
    """The consequence that made this worth fixing: a CRITICAL finding was being buried
    inside the component for the algorithm it weakens."""
    from cryptolens.cbom.aggregate import aggregate

    everything = [f for rows in findings_by_module.values() for f in rows]
    assets = {a.algorithm: a for a in aggregate(everything)}
    assert "JWT-unverified" in assets
    assert "JWT" in assets
    assert assets["JWT-unverified"].asset_id != assets["JWT"].asset_id


# --------------------------------------------------------- what is left undetermined


UNDETERMINED_PURPOSE_SITES = {
    ("aliased_imports.py", 26),
    ("dynamic_case.py", 8),
    ("dynamic_case.py", 13),
    ("ecdsa_sign.py", 6),
    ("ecdsa_sign.py", 10),
    ("rsa_signing.py", 6),
    ("rsa_signing.py", 10),
    ("rsa_signing.py", 22),
    ("rsa_signing.py", 46),
}


def test_the_undetermined_purposes_are_exactly_the_unknowable_ones(findings_by_module):
    """Pinned so the count cannot silently grow. Every entry here is a key that arrives as a
    function parameter, a `getattr` on a variable, or a PEM whose contents are not known
    until run time -- none of them resolvable without interprocedural data flow, which is a
    stated limitation."""
    everything = [f for rows in findings_by_module.values() for f in rows]
    undetermined = {
        (f.location.file, f.location.line)
        for f in everything
        if f.purpose is CryptoPurpose.UNKNOWN
    }
    assert undetermined == UNDETERMINED_PURPOSE_SITES


def test_nothing_claims_full_confidence_in_an_undetermined_purpose(findings_by_module):
    """Reporting a rank without the field that justifies it, at full confidence, is the
    combination design principle 5 forbids."""
    everything = [f for rows in findings_by_module.values() for f in rows]
    for finding in everything:
        if finding.purpose is CryptoPurpose.UNKNOWN:
            assert finding.confidence < 0.9, f"{finding.location} {finding.algorithm}"


def test_nothing_claims_full_confidence_in_an_unidentified_algorithm(findings_by_module):
    everything = [f for rows in findings_by_module.values() for f in rows]
    for finding in everything:
        if finding.algorithm == "unknown":
            assert finding.confidence < 0.9, str(finding.location)


def test_an_opaque_private_key_load_is_classified_as_key_material(findings_by_module):
    """`load_pem_private_key` cannot know the algorithm until run time, but it does know it
    is looking at a private key. That is worth recording; full confidence in `unknown` is
    not."""
    loaded = [
        f for f in findings_by_module["rsa_signing.py"] if f.detector == "pyca.load_private_key"
    ]
    assert len(loaded) == 1
    assert loaded[0].algorithm == "unknown"
    assert loaded[0].asset_type is AssetType.RELATED_CRYPTO_MATERIAL
    assert loaded[0].extra["artifact"] == "private-key"
    assert loaded[0].confidence == 0.3


# ------------------------------------------------- purpose recovered from how a key is used


def findings_for(source: str) -> list:
    from cryptolens.analyzers.python_ast import analyze_source

    return detect(analyze_source(source, "local.py"))


SIGNING_KEY = """\
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sign(message):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.sign(message, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                    hashes.SHA256())
"""

AGREEMENT_KEY = """\
from cryptography.hazmat.primitives.asymmetric import ec


def agree(peer):
    key = ec.generate_private_key(ec.SECP256R1())
    return key.exchange(ec.ECDH(), peer)
"""

BOTH_IN_ONE_FILE = """\
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


def sign(message):
    key = ec.generate_private_key(ec.SECP256R1())
    return key.sign(message, ec.ECDSA(hashes.SHA256()))


def agree(peer):
    key = ec.generate_private_key(ec.SECP256R1())
    return key.exchange(ec.ECDH(), peer)
"""


def test_a_key_used_to_sign_is_a_signing_key():
    keygen = next(f for f in findings_for(SIGNING_KEY) if f.detector == "pyca.rsa.keygen")
    assert keygen.purpose is CryptoPurpose.DIGITAL_SIGNATURE
    assert keygen.primitive is CryptoPrimitive.SIGNATURE


def test_a_key_used_to_agree_is_a_key_agreement_key():
    keygen = next(f for f in findings_for(AGREEMENT_KEY) if f.detector == "pyca.ec.keygen")
    assert keygen.purpose is CryptoPurpose.KEY_ESTABLISHMENT
    assert keygen.primitive is CryptoPrimitive.KEY_AGREE


def test_a_recovered_purpose_is_reported_at_reduced_confidence():
    """The index is file-scoped, not binding-scoped, so it is an inference and says so."""
    keygen = next(f for f in findings_for(SIGNING_KEY) if f.detector == "pyca.rsa.keygen")
    assert keygen.confidence == 0.6


def test_two_keys_used_differently_in_one_file_stay_undetermined():
    """The index cannot tell the two `key` variables apart, so it must not pick one."""
    keygens = [f for f in findings_for(BOTH_IN_ONE_FILE) if f.detector == "pyca.ec.keygen"]
    assert len(keygens) == 2
    for keygen in keygens:
        assert keygen.purpose is CryptoPurpose.UNKNOWN
        assert keygen.confidence == 0.5


def test_a_key_passed_in_as_a_parameter_stays_undetermined():
    """The accepted limitation, pinned: no interprocedural data flow."""
    source = """\
from cryptography.hazmat.primitives.asymmetric import rsa


def make():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)
"""
    keygen = next(f for f in findings_for(source) if f.detector == "pyca.rsa.keygen")
    assert keygen.purpose is CryptoPurpose.UNKNOWN
    assert keygen.confidence == 0.5


WRAPPING_KEY = """\
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def wrap(secret):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().encrypt(
        secret,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                     label=None),
    )
"""


def test_resolution_sees_through_public_key():
    """`key.public_key().encrypt(...)` is still a use of the key generated two lines up."""
    keygen = next(f for f in findings_for(WRAPPING_KEY) if f.detector == "pyca.rsa.keygen")
    assert keygen.purpose is CryptoPurpose.KEY_ESTABLISHMENT
    assert keygen.primitive is CryptoPrimitive.PKE


def test_an_rsa_keygen_is_never_assumed_to_be_a_signing_key():
    """The case that rules out defaulting RSA keygen to `digital_signature`: this key is for
    key transport, so assuming signature would move it from URGENT to SCHEDULED and
    recommend ML-DSA where ML-KEM is needed. Guessing here fails toward *less* urgency,
    which is the wrong direction."""
    from datetime import UTC, datetime

    from cryptolens.pqc import recommend
    from cryptolens.risk import Priority, assess

    keygen = next(f for f in findings_for(WRAPPING_KEY) if f.detector == "pyca.rsa.keygen")
    assert assess(keygen, datetime(2026, 9, 12, tzinfo=UTC)).priority is Priority.URGENT
    assert recommend(keygen).primary.name.startswith("ML-KEM")


def test_recovering_a_purpose_never_creates_a_second_finding():
    """The identity invariant from the previous fix still holds under resolution."""
    for source in (SIGNING_KEY, AGREEMENT_KEY, BOTH_IN_ONE_FILE, WRAPPING_KEY):
        assert collisions(findings_for(source)) == {}
