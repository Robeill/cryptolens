from __future__ import annotations

from pathlib import Path

from cryptolens.discovery.walk import walk_files

SOURCE_EXTENSIONS = {".py"}


def discover_source_files(
    root: str | Path, extra_ignore: list[str] | None = None
) -> list[Path]:
    return sorted(
        path for path in walk_files(root, extra_ignore) if path.suffix in SOURCE_EXTENSIONS
    )
