from __future__ import annotations

import contextlib
import io
import logging
from typing import Any

from cryptolens.model import CryptoPrimitive
from cryptolens.pqc.catalog import CATALOG, Mechanism

logger = logging.getLogger(__name__)

UNAVAILABLE = "unavailable"

_IMPORT_CHATTER = io.StringIO()

try:
    with contextlib.redirect_stdout(_IMPORT_CHATTER):
        import oqs

    OQS_AVAILABLE = True
except Exception:
    oqs = None
    OQS_AVAILABLE = False

if _IMPORT_CHATTER.getvalue():
    logger.debug("liboqs said on import: %s", _IMPORT_CHATTER.getvalue().strip())

_SIZE_FIELDS = (
    ("public_key_bytes", "length_public_key"),
    ("secret_key_bytes", "length_secret_key"),
    ("ciphertext_bytes", "length_ciphertext"),
    ("shared_secret_bytes", "length_shared_secret"),
    ("signature_bytes", "length_signature"),
)


def available() -> bool:
    return OQS_AVAILABLE


def liboqs_version() -> str | None:
    if not OQS_AVAILABLE:
        return None
    try:
        return str(oqs.oqs_version())
    except Exception:
        logger.debug("liboqs loaded but would not report a version", exc_info=True)
        return None


def enabled_mechanisms() -> frozenset[str]:
    if not OQS_AVAILABLE:
        return frozenset()
    names: set[str] = set()
    for getter in ("get_enabled_kem_mechanisms", "get_enabled_sig_mechanisms"):
        try:
            names.update(getattr(oqs, getter)())
        except Exception:
            logger.debug("liboqs would not enumerate via %s", getter, exc_info=True)
    return frozenset(names)


def describe(mechanism: Mechanism) -> dict[str, Any]:
    if not OQS_AVAILABLE:
        logger.info("liboqs unavailable; reporting catalog values only")
        return {"liboqs": UNAVAILABLE}
    if mechanism.liboqs_name is None:
        return {"liboqs": "not_mapped"}

    details = _raw_details(mechanism)
    if details is None:
        return {"liboqs": "missing_from_build", "liboqs_name": mechanism.liboqs_name}

    described: dict[str, Any] = {
        "liboqs": liboqs_version() or "present",
        "liboqs_name": mechanism.liboqs_name,
    }
    for field, key in _SIZE_FIELDS:
        value = details.get(key)
        if isinstance(value, int):
            described[field] = value
    claimed = details.get("claimed_nist_level")
    if isinstance(claimed, int):
        described["liboqs_claimed_nist_level"] = claimed
    return described


def _raw_details(mechanism: Mechanism) -> dict[str, Any] | None:
    factory = (
        oqs.KeyEncapsulation
        if mechanism.primitive is CryptoPrimitive.KEM
        else oqs.Signature
    )
    try:
        with factory(mechanism.liboqs_name) as handle:
            return dict(handle.details)
    except Exception:
        logger.debug(
            "liboqs has no mechanism named %s", mechanism.liboqs_name, exc_info=True
        )
        return None


def verify_catalog() -> dict[str, str]:
    if not OQS_AVAILABLE:
        return {}
    enabled = enabled_mechanisms()
    problems: dict[str, str] = {}
    for mechanism in CATALOG:
        if mechanism.liboqs_name is None:
            problems[mechanism.name] = "not_mapped"
        elif mechanism.liboqs_name not in enabled:
            problems[mechanism.name] = f"missing: {mechanism.liboqs_name}"
    return problems


def category_disagreements() -> dict[str, tuple[int, int]]:
    if not OQS_AVAILABLE:
        return {}
    disagreements: dict[str, tuple[int, int]] = {}
    for mechanism in CATALOG:
        if mechanism.liboqs_name is None:
            continue
        details = _raw_details(mechanism)
        if details is None:
            continue
        claimed = details.get("claimed_nist_level")
        if isinstance(claimed, int) and claimed != mechanism.nist_quantum_security_level:
            disagreements[mechanism.name] = (mechanism.nist_quantum_security_level, claimed)
    return disagreements
