from __future__ import annotations

from pathlib import Path

from cryptolens.discovery.source_files import DEFAULT_IGNORE_DIRS, _is_ignored

ARTIFACT_EXTENSIONS = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".p12", ".pfx"}
SNIFF_BYTES = 4096
PEM_MARKER = b"-----BEGIN"

def _looks_like_pem(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            head = f.read(SNIFF_BYTES)
        return PEM_MARKER in head
    except (OSError, PermissionError):
        return False

def discover_artifact_files(root: str | Path,extra_ignore: list[str] | None = None,) -> list[Path]:
    root = Path(root).resolve()
    ignore_dirs = set(DEFAULT_IGNORE_DIRS)
    if extra_ignore:
        ignore_dirs.update(extra_ignore)
    found: list[Path] = []
    for path in root.rglob("*"):
        if path.is_dir():
            continue
        if _is_ignored(path.relative_to(root), ignore_dirs):
            continue
        if path.suffix in ARTIFACT_EXTENSIONS:
            found.append(path)
        elif path.suffix not in {".py", ".md", ".txt", ".json", ".toml", ".yaml", ".yml"}:
            if _looks_like_pem(path):
                found.append(path)
    return sorted(set(found))