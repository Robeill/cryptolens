from __future__ import annotations
from pathlib import Path

DEFAULT_IGNORE_DIRS = {
    ".git", "__pycache__", ".venv", "venv", "env",
    "build", "dist", "node_modules", ".pytest_cache",
    ".mypy_cache", ".tox", "site-packages", "egg-info",
}

SOURCE_EXTENSIONS = {".py"}
def _is_ignored(path: Path, ignore_dirs: set[str]) -> bool:
    for part in path.parts:
        if part in ignore_dirs:
            return True
        if part.endswith(".egg-info"):
            return True
    return False


def discover_source_files(root: str | Path,extra_ignore: list[str] | None = None,):
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
        if path.suffix in SOURCE_EXTENSIONS:
            found.append(path)
    return sorted(found)