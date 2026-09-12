from __future__ import annotations

import contextlib
import logging
import os
import sys
import tempfile
from typing import Any

from cryptolens.model import CryptoPrimitive
from cryptolens.pqc.catalog import CATALOG, Mechanism

logger = logging.getLogger(__name__)

UNAVAILABLE = "unavailable"
NOT_MAPPED = "not_mapped"
MISSING_FROM_BUILD = "missing_from_build"

_SIZE_FIELDS = (
    ("public_key_bytes", "length_public_key"),
    ("secret_key_bytes", "length_secret_key"),
    ("ciphertext_bytes", "length_ciphertext"),
    ("shared_secret_bytes", "length_shared_secret"),
    ("signature_bytes", "length_signature"),
)

_probe: tuple[Any | None] | None = None


def _guarded_import() -> tuple[Any | None, str]:
    """Import `oqs` once, swallowing anything it does on the way in.

    `except Exception` is NOT sufficient here and must not be narrowed back to it.
    `oqs/oqs.py` raises `SystemExit` in two places when it cannot find or build the native
    library, and `SystemExit` derives from `BaseException`. At module scope an uncaught one
    kills the interpreter, which took down `pytest` itself with `INTERNALERROR` and no tests
    run. `KeyboardInterrupt` is deliberately still allowed through.
    """
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8") as sink:
        saved = _silence(sink)
        module: Any | None
        try:
            with contextlib.redirect_stdout(sink), contextlib.redirect_stderr(sink):
                import oqs

            module = oqs
        except (Exception, SystemExit):
            module = None
        finally:
            _restore(saved)
        sink.seek(0)
        return module, sink.read().strip()


def _silence(sink: Any) -> tuple[int, int]:
    """Redirect at file-descriptor level, not just `sys.stdout`.

    `oqs` shells out to `git clone` and `cmake` through `subprocess.call(..., shell=True)`.
    Those children write to file descriptors 1 and 2 directly, so `redirect_stdout` alone
    leaves several minutes of build output on the user's terminal.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    saved = (os.dup(1), os.dup(2))
    os.dup2(sink.fileno(), 1)
    os.dup2(sink.fileno(), 2)
    return saved


def _restore(saved: tuple[int, int]) -> None:
    sys.stdout.flush()
    sys.stderr.flush()
    for descriptor, original in zip((1, 2), saved, strict=True):
        os.dup2(original, descriptor)
        os.close(original)


def _oqs() -> Any | None:
    """The `oqs` module, imported on first use, or None if it will not load.

    Lazy on purpose. Importing `oqs` can trigger a `git clone` of liboqs and a multi-minute
    native build, which must never happen as a side effect of importing `cryptolens.pqc` or
    of running a scan. Nothing in the scan pipeline calls this.
    """
    global _probe
    if _probe is None:
        module, chatter = _guarded_import()
        if chatter:
            logger.debug("liboqs said on import: %s", chatter)
        if module is None:
            logger.info("liboqs unavailable; reporting catalog values only")
        _probe = (module,)
    return _probe[0]


def available() -> bool:
    """True when liboqs can be loaded. Probes once, then answers from the cache.

    To simulate an absent liboqs without paying for the import, set `_probe` to `(None,)` --
    that is the state the probe itself reaches when the import fails, so the simulation and
    the real thing take identical paths from here on.
    """
    return _oqs() is not None


def __getattr__(name: str) -> Any:
    """`OQS_AVAILABLE` is kept as a readable name for callers that predate `available()`."""
    if name == "OQS_AVAILABLE":
        return available()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def liboqs_version() -> str | None:
    module = _oqs()
    if module is None:
        return None
    try:
        return str(module.oqs_version())
    except Exception:
        logger.debug("liboqs loaded but would not report a version", exc_info=True)
        return None


def enabled_mechanisms() -> frozenset[str]:
    module = _oqs()
    if module is None:
        return frozenset()
    names: set[str] = set()
    for getter in ("get_enabled_kem_mechanisms", "get_enabled_sig_mechanisms"):
        try:
            names.update(getattr(module, getter)())
        except Exception:
            logger.debug("liboqs would not enumerate via %s", getter, exc_info=True)
    return frozenset(names)


def describe(mechanism: Mechanism) -> dict[str, Any]:
    if _oqs() is None:
        return {"liboqs": UNAVAILABLE}
    if mechanism.liboqs_name is None:
        return {"liboqs": NOT_MAPPED}

    details = _raw_details(mechanism)
    if details is None:
        return {"liboqs": MISSING_FROM_BUILD, "liboqs_name": mechanism.liboqs_name}

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


def verify_catalog() -> dict[str, str]:
    if _oqs() is None:
        return {}
    enabled = enabled_mechanisms()
    problems: dict[str, str] = {}
    for mechanism in CATALOG:
        if mechanism.liboqs_name is None:
            problems[mechanism.name] = NOT_MAPPED
        elif mechanism.liboqs_name not in enabled:
            problems[mechanism.name] = f"missing: {mechanism.liboqs_name}"
    return problems


def category_disagreements() -> dict[str, tuple[int, int]]:
    if _oqs() is None:
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


def _raw_details(mechanism: Mechanism) -> dict[str, Any] | None:
    module = _oqs()
    if module is None:
        return None
    factory = (
        module.KeyEncapsulation
        if mechanism.primitive is CryptoPrimitive.KEM
        else module.Signature
    )
    try:
        with factory(mechanism.liboqs_name) as handle:
            return dict(handle.details)
    except Exception:
        logger.debug(
            "liboqs has no mechanism named %s", mechanism.liboqs_name, exc_info=True
        )
        return None
