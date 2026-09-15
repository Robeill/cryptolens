from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from asn1crypto import core, keys, pem
from asn1crypto import x509 as asn1_x509
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa, x448, x25519

from cryptolens.certs.oids import (
    CURVE_STRENGTH,
    OidEntry,
    lookup_curve,
    lookup_public_key,
    lookup_signature,
)
from cryptolens.detectors.normalize import normalize_algorithm
from cryptolens.discovery.artifact_files import discover_artifact_files
from cryptolens.model import (
    AssetType,
    CryptoFinding,
    CryptoFunction,
    CryptoPrimitive,
    CryptoPurpose,
    CryptoStatus,
    SourceLocation,
)

logger = logging.getLogger(__name__)

MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
ARTIFACT_LINE = 0

CONFIDENCE_PARSED = 1.0
CONFIDENCE_OID_TABLE = 0.8
CONFIDENCE_UNKNOWN_OID = 0.3

RSA_STRENGTH = {1024: 80, 2048: 112, 3072: 128, 4096: 152, 7680: 192, 15360: 256}

SIGNING_KEY_USAGES = frozenset(
    {"digital_signature", "content_commitment", "key_cert_sign", "crl_sign"}
)
ESTABLISHMENT_KEY_USAGES = frozenset(
    {"key_encipherment", "key_agreement", "encipher_only", "decipher_only"}
)

KEY_USAGE_FLAGS = (
    "digital_signature",
    "content_commitment",
    "key_encipherment",
    "data_encipherment",
    "key_agreement",
    "key_cert_sign",
    "crl_sign",
    "encipher_only",
    "decipher_only",
)

CERTIFICATE_LABELS = frozenset({"CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"})
REQUEST_LABELS = frozenset({"CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"})
PUBLIC_KEY_LABELS = frozenset({"PUBLIC KEY", "RSA PUBLIC KEY"})
PRIVATE_KEY_LABELS = frozenset(
    {"PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY"}
)
ENCRYPTED_LABELS = frozenset({"ENCRYPTED PRIVATE KEY"})


class AlgorithmIdentifier(core.Sequence):
    _fields: ClassVar = [
        ("algorithm", core.ObjectIdentifier),
        ("parameters", core.Any, {"optional": True}),
    ]


class SubjectPublicKeyInfo(core.Sequence):
    _fields: ClassVar = [
        ("algorithm", AlgorithmIdentifier),
        ("public_key", core.OctetBitString),
    ]


class PrivateKeyInfo(core.Sequence):
    _fields: ClassVar = [
        ("version", core.Integer),
        ("private_key_algorithm", AlgorithmIdentifier),
        ("private_key", core.OctetString),
        ("attributes", core.Any, {"implicit": 0, "optional": True}),
    ]


@dataclass(frozen=True)
class Block:
    label: str | None
    data: bytes


@dataclass(frozen=True)
class KeyFacts:
    entry: OidEntry
    oid: str | None = None
    key_size: int | None = None
    curve: str | None = None
    parameter_set: str | None = None
    classical_security_level: int | None = None


def parse_artifact(path: str | Path, root: str | Path | None = None) -> list[CryptoFinding]:
    path = Path(path)
    location = _location(path, root)
    data = _read(path)
    if not data:
        return []

    findings: list[CryptoFinding] = []
    for block in _blocks(data):
        try:
            findings.extend(_parse_block(block, location))
        except Exception:
            logger.debug("unreadable block in %s", location.file, exc_info=True)
    return findings


def scan_artifacts(root: str | Path) -> list[CryptoFinding]:
    findings: list[CryptoFinding] = []
    for path in discover_artifact_files(root):
        findings.extend(parse_artifact(path, root))
    return findings


def _location(path: Path, root: str | Path | None) -> SourceLocation:
    if root is not None:
        try:
            return SourceLocation(str(path.resolve().relative_to(Path(root).resolve())),
                                  ARTIFACT_LINE)
        except ValueError:
            pass
    return SourceLocation(str(path), ARTIFACT_LINE)


def _read(path: Path) -> bytes | None:
    try:
        if path.stat().st_size > MAX_ARTIFACT_BYTES:
            logger.debug("skipping oversized artifact %s", path)
            return None
        return path.read_bytes()
    except OSError:
        logger.debug("unreadable artifact %s", path, exc_info=True)
        return None


def _blocks(data: bytes) -> list[Block]:
    if not pem.detect(data):
        return [Block(None, data)]
    blocks = []
    try:
        for label, _headers, der in pem.unarmor(data, multiple=True):
            blocks.append(Block(label.upper(), der))
    except Exception:
        logger.debug("malformed PEM armour", exc_info=True)
    return blocks


def _parse_block(block: Block, location: SourceLocation) -> list[CryptoFinding]:
    label = block.label
    if label in ENCRYPTED_LABELS:
        return [_opaque_finding(location, "encrypted private key")]
    if label in PRIVATE_KEY_LABELS:
        return _parse_key(block, location, private=True)
    if label in PUBLIC_KEY_LABELS:
        return _parse_key(block, location, private=False)
    if label in CERTIFICATE_LABELS or label in REQUEST_LABELS or label is None:
        findings = _parse_certificate(block, location)
        if findings or label is not None:
            return findings
        return _parse_key(block, location, private=False) or _parse_key(
            block, location, private=True
        )
    return []


# ------------------------------------------------------------------- certificates


def _parse_certificate(block: Block, location: SourceLocation) -> list[CryptoFinding]:
    parsed = _certificate_via_cryptography(block.data)
    confidence = CONFIDENCE_PARSED
    if parsed is None or parsed[1] is None:
        fallback = _certificate_via_asn1crypto(block.data)
        if fallback is not None and (parsed is None or fallback[1] is not None):
            parsed = fallback
            confidence = CONFIDENCE_OID_TABLE
    if parsed is None:
        return []

    signature_oid, public_key, metadata = parsed
    findings = [_certificate_finding(public_key, location, metadata, confidence)]
    findings.append(_signature_finding(signature_oid, location, metadata, confidence))
    return findings


def _certificate_via_cryptography(
    der: bytes,
) -> tuple[str | None, KeyFacts | None, dict[str, Any]] | None:
    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    metadata: dict[str, Any] = {"artifact": "x509_certificate"}
    for name, getter in (
        ("subject", lambda: cert.subject.rfc4514_string()),
        ("issuer", lambda: cert.issuer.rfc4514_string()),
        ("serial_number", lambda: format(cert.serial_number, "x")),
        ("not_before", lambda: cert.not_valid_before_utc.isoformat()),
        ("not_after", lambda: cert.not_valid_after_utc.isoformat()),
    ):
        try:
            metadata[name] = getter()
        except Exception:
            logger.debug("could not read %s", name, exc_info=True)

    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        metadata["is_ca"] = constraints.value.ca
    except Exception:
        metadata["is_ca"] = False

    usage = _key_usage_via_cryptography(cert)
    if usage is not None:
        metadata["key_usage"] = sorted(usage)

    try:
        signature_oid = cert.signature_algorithm_oid.dotted_string
    except Exception:
        signature_oid = None

    return signature_oid, _key_facts_from_object(_public_key(cert)), metadata


def _key_usage_via_cryptography(cert: Any) -> set[str] | None:
    try:
        extension = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except Exception:
        logger.debug("certificate has no key usage extension", exc_info=True)
        return None
    flags = set()
    for flag in KEY_USAGE_FLAGS:
        try:
            if getattr(extension, flag):
                flags.add(flag)
        except ValueError:
            logger.debug("key usage flag %s is not decodable here", flag, exc_info=True)
    return flags


def _key_usage_via_asn1crypto(cert: Any) -> set[str] | None:
    try:
        value = cert.key_usage_value
    except Exception:
        logger.debug("unreadable key usage extension", exc_info=True)
        return None
    if value is None:
        return None
    try:
        return set(value.native)
    except Exception:
        logger.debug("undecodable key usage bits", exc_info=True)
        return None


def _public_key(cert: Any) -> Any | None:
    try:
        return cert.public_key()
    except Exception:
        logger.debug("unsupported public key", exc_info=True)
        return None


def _certificate_via_asn1crypto(
    der: bytes,
) -> tuple[str | None, KeyFacts | None, dict[str, Any]] | None:
    try:
        cert = asn1_x509.Certificate.load(der)
        tbs = cert["tbs_certificate"]
        signature_oid = cert["signature_algorithm"]["algorithm"].dotted
    except Exception:
        return None

    metadata: dict[str, Any] = {"artifact": "x509_certificate", "parser": "asn1crypto"}
    usage = _key_usage_via_asn1crypto(cert)
    if usage is not None:
        metadata["key_usage"] = sorted(usage)
    for name in ("subject", "issuer"):
        try:
            metadata[name] = tbs[name].human_friendly
        except Exception:
            logger.debug("could not read %s", name, exc_info=True)
    for name in ("not_before", "not_after"):
        try:
            metadata[name] = tbs["validity"][name].native.isoformat()
        except Exception:
            logger.debug("could not read %s", name, exc_info=True)

    return signature_oid, _key_facts_from_spki(_raw_spki(tbs)), metadata


def _raw_spki(tbs: Any) -> SubjectPublicKeyInfo | None:
    """Re-read the SubjectPublicKeyInfo through a spec that knows no algorithms.

    `asn1crypto.keys.PublicKeyInfo` raises `KeyError` on an algorithm OID missing from its
    own table, which is precisely the case this fallback exists to survive.
    """
    try:
        return SubjectPublicKeyInfo.load(tbs["subject_public_key_info"].dump())
    except Exception:
        logger.debug("unreadable subject public key info", exc_info=True)
        return None


# ----------------------------------------------------------------- standalone keys


def _parse_key(block: Block, location: SourceLocation, private: bool) -> list[CryptoFinding]:
    facts = _key_via_cryptography(block.data, private=private)
    confidence = CONFIDENCE_PARSED
    if facts is None:
        facts = _key_via_asn1crypto(block.data, private=private)
        confidence = CONFIDENCE_OID_TABLE
    if facts is None:
        return []

    material = "private-key" if private else "public-key"
    return [
        _finding_from_facts(
            facts,
            location,
            asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
            evidence=f"{material} ({facts.entry.algorithm})",
            confidence=confidence,
            functions=[CryptoFunction.KEYGEN],
            extra={"artifact": material},
        )
    ]


def _key_via_cryptography(der: bytes, private: bool) -> KeyFacts | None:
    loader = (
        (lambda: serialization.load_der_private_key(der, password=None))
        if private
        else (lambda: serialization.load_der_public_key(der))
    )
    try:
        key = loader()
    except Exception:
        return None
    if private:
        try:
            key = key.public_key()
        except Exception:
            logger.debug("private key without extractable public half", exc_info=True)
            return None
    return _key_facts_from_object(key)


def _key_via_asn1crypto(der: bytes, private: bool) -> KeyFacts | None:
    if not private:
        try:
            return _key_facts_from_spki(SubjectPublicKeyInfo.load(der))
        except Exception:
            logger.debug("unreadable public key", exc_info=True)
            return None
    try:
        info = PrivateKeyInfo.load(der)
        algorithm = info["private_key_algorithm"]
    except Exception:
        logger.debug("unreadable private key", exc_info=True)
        return None
    return _key_facts_from_algorithm(algorithm, public_key=None)


# ------------------------------------------------------------------- key inspection


def _key_facts_from_object(key: Any) -> KeyFacts | None:
    if key is None:
        return None
    if isinstance(key, rsa.RSAPublicKey):
        size = key.key_size
        return KeyFacts(
            entry=OidEntry("RSA", CryptoPrimitive.PKE, CryptoPurpose.UNKNOWN),
            key_size=size,
            classical_security_level=RSA_STRENGTH.get(size),
        )
    if isinstance(key, ec.EllipticCurvePublicKey):
        curve = _normalize_curve(key.curve.name)
        return KeyFacts(
            entry=OidEntry("EC", CryptoPrimitive.UNKNOWN, CryptoPurpose.UNKNOWN),
            key_size=key.key_size,
            curve=curve,
            parameter_set=curve,
            classical_security_level=CURVE_STRENGTH.get(curve),
        )
    if isinstance(key, dsa.DSAPublicKey):
        return KeyFacts(
            entry=OidEntry("DSA", CryptoPrimitive.SIGNATURE, CryptoPurpose.DIGITAL_SIGNATURE),
            key_size=key.key_size,
        )
    for key_type, oid in (
        (ed25519.Ed25519PublicKey, "1.3.101.112"),
        (ed448.Ed448PublicKey, "1.3.101.113"),
        (x25519.X25519PublicKey, "1.3.101.110"),
        (x448.X448PublicKey, "1.3.101.111"),
    ):
        if isinstance(key, key_type):
            entry = lookup_public_key(oid)
            if entry is not None:
                return KeyFacts(
                    entry=entry,
                    parameter_set=entry.parameter_set,
                    classical_security_level=entry.classical_security_level,
                )
    return _key_facts_from_module(key)


_PQC_CLASS = re.compile(r"^ML(DSA|KEM)(\d+)(?:Public|Private)Key$")


def _key_facts_from_module(key: Any) -> KeyFacts | None:
    from cryptolens.certs.oids import PUBLIC_KEY_OIDS

    matched = _PQC_CLASS.match(type(key).__name__)
    if matched is None:
        return None
    parameter_set = f"ML-{matched.group(1)}-{matched.group(2)}"
    for entry in PUBLIC_KEY_OIDS.values():
        if entry.parameter_set == parameter_set:
            return KeyFacts(
                entry=entry,
                parameter_set=entry.parameter_set,
                classical_security_level=entry.classical_security_level,
            )
    return None


def _key_facts_from_spki(spki: SubjectPublicKeyInfo | None) -> KeyFacts | None:
    if spki is None:
        return None
    try:
        return _key_facts_from_algorithm(spki["algorithm"], spki["public_key"].native)
    except Exception:
        logger.debug("unreadable public key algorithm", exc_info=True)
        return None


def _key_facts_from_algorithm(
    algorithm: AlgorithmIdentifier, public_key: bytes | None
) -> KeyFacts:
    oid = algorithm["algorithm"].dotted
    entry = lookup_public_key(oid)
    if entry is None:
        return KeyFacts(entry=_unknown_entry(), oid=oid)

    curve = None
    parameter_set = entry.parameter_set
    strength = entry.classical_security_level
    key_size = None

    if entry.algorithm == "EC":
        named = _named_curve(algorithm)
        if named is not None:
            curve, strength = named
            parameter_set = curve
    elif entry.algorithm == "RSA" and public_key is not None:
        key_size = _rsa_modulus_bits(public_key)
        strength = RSA_STRENGTH.get(key_size or 0, strength)

    return KeyFacts(
        entry=entry,
        oid=oid,
        key_size=key_size,
        curve=curve,
        parameter_set=parameter_set,
        classical_security_level=strength,
    )


def _named_curve(algorithm: AlgorithmIdentifier) -> tuple[str, int] | None:
    try:
        parameters = algorithm["parameters"]
        return lookup_curve(core.ObjectIdentifier.load(parameters.dump()).dotted)
    except Exception:
        logger.debug("no named curve in key parameters", exc_info=True)
        return None


def _rsa_modulus_bits(public_key: bytes) -> int | None:
    try:
        return int(keys.RSAPublicKey.load(public_key)["modulus"].native.bit_length())
    except Exception:
        logger.debug("could not size RSA modulus", exc_info=True)
        return None


def _normalize_curve(name: str) -> str:
    text = name.strip()
    if text.lower().startswith("secp"):
        return text.upper()
    return text


def _unknown_entry() -> OidEntry:
    return OidEntry(
        algorithm="unknown",
        primitive=CryptoPrimitive.UNKNOWN,
        purpose=CryptoPurpose.UNKNOWN,
        status=CryptoStatus.UNKNOWN,
    )


# ------------------------------------------------------------------------- findings


def _certificate_finding(
    facts: KeyFacts | None,
    location: SourceLocation,
    metadata: dict[str, Any],
    confidence: float,
) -> CryptoFinding:
    subject = metadata.get("subject", "unknown subject")
    if facts is None:
        return CryptoFinding(
            algorithm="unknown",
            location=location,
            purpose=CryptoPurpose.UNKNOWN,
            evidence=f"X.509 certificate ({subject}) with an unreadable public key",
            asset_type=AssetType.CERTIFICATE,
            status=CryptoStatus.UNKNOWN,
            confidence=CONFIDENCE_UNKNOWN_OID,
            detector="certs.certificate",
            extra=dict(metadata),
        )
    entry = facts.entry
    purpose, primitive = _refine_from_key_usage(entry, metadata.get("key_usage"))
    return CryptoFinding(
        algorithm=normalize_algorithm(entry.algorithm),
        location=location,
        purpose=purpose,
        evidence=f"X.509 certificate ({subject}) with a {entry.algorithm} public key",
        asset_type=AssetType.CERTIFICATE,
        primitive=primitive,
        parameter_set=facts.parameter_set,
        curve=facts.curve,
        key_size=facts.key_size,
        oid=facts.oid,
        status=entry.status,
        classical_security_level=facts.classical_security_level,
        nist_quantum_security_level=entry.nist_quantum_security_level,
        confidence=confidence if entry.algorithm != "unknown" else CONFIDENCE_UNKNOWN_OID,
        detector="certs.certificate",
        extra=dict(metadata),
    )


def _refine_from_key_usage(
    entry: OidEntry, key_usage: list[str] | None
) -> tuple[CryptoPurpose, CryptoPrimitive]:
    """A certificate states what its key is for. Use it only when it says one thing."""
    if entry.purpose is not CryptoPurpose.UNKNOWN or not key_usage:
        return entry.purpose, entry.primitive

    flags = set(key_usage)
    signs = bool(flags & SIGNING_KEY_USAGES)
    establishes = bool(flags & ESTABLISHMENT_KEY_USAGES)
    if signs == establishes:
        return entry.purpose, entry.primitive

    if signs:
        return CryptoPurpose.DIGITAL_SIGNATURE, CryptoPrimitive.SIGNATURE
    if entry.algorithm == "EC":
        return CryptoPurpose.KEY_ESTABLISHMENT, CryptoPrimitive.KEY_AGREE
    return CryptoPurpose.KEY_ESTABLISHMENT, entry.primitive


def _signature_finding(
    oid: str | None,
    location: SourceLocation,
    metadata: dict[str, Any],
    confidence: float,
) -> CryptoFinding:
    entry = lookup_signature(oid)
    subject = metadata.get("subject", "unknown subject")
    extra = {"artifact": "x509_signature", "signature_algorithm_oid": oid}
    if entry is None:
        return CryptoFinding(
            algorithm="unknown",
            location=location,
            purpose=CryptoPurpose.DIGITAL_SIGNATURE,
            evidence=f"X.509 certificate ({subject}) signed with unrecognised OID {oid}",
            primitive=CryptoPrimitive.SIGNATURE,
            oid=oid,
            status=CryptoStatus.UNKNOWN,
            confidence=CONFIDENCE_UNKNOWN_OID,
            detector="certs.signature_algorithm",
            extra=extra,
        )
    return CryptoFinding(
        algorithm=normalize_algorithm(entry.algorithm),
        location=location,
        purpose=entry.purpose,
        evidence=f"X.509 certificate ({subject}) signed with {entry.algorithm}",
        primitive=entry.primitive,
        crypto_functions=[CryptoFunction.SIGN],
        parameter_set=entry.parameter_set,
        oid=oid,
        status=entry.status,
        classical_security_level=entry.classical_security_level,
        nist_quantum_security_level=entry.nist_quantum_security_level,
        confidence=confidence,
        detector="certs.signature_algorithm",
        extra=extra,
    )


def _finding_from_facts(
    facts: KeyFacts,
    location: SourceLocation,
    asset_type: AssetType,
    evidence: str,
    confidence: float,
    functions: list[CryptoFunction],
    extra: dict[str, Any],
) -> CryptoFinding:
    entry = facts.entry
    return CryptoFinding(
        algorithm=normalize_algorithm(entry.algorithm),
        location=location,
        purpose=entry.purpose,
        evidence=evidence,
        asset_type=asset_type,
        primitive=entry.primitive,
        crypto_functions=functions,
        parameter_set=facts.parameter_set,
        curve=facts.curve,
        key_size=facts.key_size,
        oid=facts.oid,
        status=entry.status,
        classical_security_level=facts.classical_security_level,
        nist_quantum_security_level=entry.nist_quantum_security_level,
        confidence=confidence if entry.algorithm != "unknown" else CONFIDENCE_UNKNOWN_OID,
        detector="certs.key",
        extra=extra,
    )


def _opaque_finding(location: SourceLocation, description: str) -> CryptoFinding:
    return CryptoFinding(
        algorithm="unknown",
        location=location,
        purpose=CryptoPurpose.UNKNOWN,
        evidence=description,
        asset_type=AssetType.RELATED_CRYPTO_MATERIAL,
        status=CryptoStatus.UNKNOWN,
        confidence=CONFIDENCE_UNKNOWN_OID,
        detector="certs.opaque",
        extra={"artifact": description.replace(" ", "-")},
    )
