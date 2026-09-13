from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_IGNORE_DIRS = {
    ".git", "__pycache__", ".venv", "venv", "env",
    "build", "dist", "node_modules", ".pytest_cache",
    ".mypy_cache", ".tox", "site-packages", "egg-info",
}


def ignore_set(extra_ignore: list[str] | None = None) -> set[str]:
    ignore_dirs = set(DEFAULT_IGNORE_DIRS)
    if extra_ignore:
        ignore_dirs.update(extra_ignore)
    return ignore_dirs


def is_ignored(path: Path, ignore_dirs: set[str]) -> bool:
    for part in path.parts:
        if part in ignore_dirs or part.endswith(".egg-info"):
            return True
    return False


def walk_files(root: str | Path, extra_ignore: list[str] | None = None) -> Iterator[Path]:
    """Yield every **regular** file under `root`, skipping ignored directories.

    Three things this does that `Path.rglob` does not:

    * **Only regular files.** A named pipe called `server.pem` blocks the reader forever --
      no error, no traceback, a scan that simply never returns. Sockets, device nodes and
      dangling symlinks are excluded for the same reason.
    * **Reports what it could not read.** `rglob` swallows a `PermissionError` on a directory
      silently, so an unreadable subtree would vanish from the inventory without a word.
    * **Prunes ignored directories** instead of walking into them and discarding the results,
      which matters on a repository with a populated `.venv`.

    Symlinked directories are not followed, so a symlink loop terminates.
    """
    root = Path(root).resolve()
    ignore_dirs = ignore_set(extra_ignore)

    for parent, directories, names in os.walk(root, onerror=_report, followlinks=False):
        here = Path(parent)
        directories[:] = [d for d in directories if not is_ignored(Path(d), ignore_dirs)]
        for name in names:
            path = here / name
            if is_ignored(path.relative_to(root), ignore_dirs):
                continue
            if not _is_regular(path):
                continue
            yield path


def _report(error: OSError) -> None:
    logger.warning("cryptolens: cannot list %s: %s", error.filename, error.strerror)


def _is_regular(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError:
        logger.debug("cannot stat %s", path, exc_info=True)
        return False
