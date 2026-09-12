from typing import Any

from cryptolens.pqc.catalog import CATALOG, Mechanism, Recommendation, recommend, recommend_all
from cryptolens.pqc.liboqs_bridge import available, describe, verify_catalog

__all__ = [
    "CATALOG",
    "OQS_AVAILABLE",
    "Mechanism",
    "Recommendation",
    "available",
    "describe",
    "recommend",
    "recommend_all",
    "verify_catalog",
]


def __getattr__(name: str) -> Any:
    """`OQS_AVAILABLE` stays importable without probing at package-import time."""
    if name == "OQS_AVAILABLE":
        return available()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
