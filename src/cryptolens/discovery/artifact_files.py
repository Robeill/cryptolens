from __future__ import annotations

import logging
from pathlib import Path

from cryptolens.discovery.walk import walk_files

logger = logging.getLogger(__name__)

ARTIFACT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p12", ".pfx"}
SKIP_EXTENSIONS = {".py", ".md", ".txt", ".json", ".toml", ".yaml", ".yml"}
SNIFF_BYTES = 4096
PEM_MARKER = b"-----BEGIN"


def _looks_like_pem(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return PEM_MARKER in handle.read(SNIFF_BYTES)
    except OSError:
        logger.debug("cannot sniff %s", path, exc_info=True)
        return False


def discover_artifact_files(
    root: str | Path, extra_ignore: list[str] | None = None
) -> list[Path]:
    found: list[Path] = []
    for path in walk_files(root, extra_ignore):
        if path.suffix in ARTIFACT_EXTENSIONS or (
            path.suffix not in SKIP_EXTENSIONS and _looks_like_pem(path)
        ):
            found.append(path)
    return sorted(set(found))
