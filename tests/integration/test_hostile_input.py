"""Step 13: deliberately bad input across the whole pipeline.

A scanner that crashes on one file in a ten-thousand-file repository is useless, and one that
*hangs* on it is worse -- there is no traceback to read and no exit code to act on. Every
input here must produce a warning and a continued scan.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cryptolens.cli import EXIT_ERROR, EXIT_OK, app
from cryptolens.discovery.artifact_files import discover_artifact_files
from cryptolens.discovery.source_files import discover_source_files
from cryptolens.scan import ScanError, scan

runner = CliRunner()

REAL_CRYPTO = "import hashlib\n\n\ndef digest(payload):\n    return hashlib.md5(payload).hexdigest()\n"


@pytest.fixture
def hostile(tmp_path) -> Path:
    """Every input the plan lists, plus the ones that turned out to matter more."""
    root = tmp_path / "repo"
    root.mkdir()

    (root / "good.py").write_text(REAL_CRYPTO)
    (root / "syntax_error.py").write_text("def (((:\n")
    (root / "empty.py").write_bytes(b"")
    (root / "latin1_no_cookie.py").write_bytes(b"# caf\xe9\nimport hashlib\nhashlib.sha1(b'x')\n")
    (root / "latin1_with_cookie.py").write_bytes(
        b"# -*- coding: latin-1 -*-\n# caf\xe9\nimport hashlib\nhashlib.sha256(b'x')\n"
    )
    (root / "utf16.py").write_bytes("import hashlib\n".encode("utf-16"))
    (root / "nul_bytes.py").write_bytes(b"import hashlib\x00\n")

    (root / "empty.pem").write_bytes(b"")
    (root / "random.der").write_bytes(bytes(range(256)) * 16)
    (root / "truncated.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nMIIB")
    (root / "not_base64.pem").write_bytes(
        b"-----BEGIN CERTIFICATE-----\nnot base64 !!\n-----END CERTIFICATE-----\n"
    )

    deep = root
    for level in range(25):
        deep = deep / f"d{level}"
    deep.mkdir(parents=True)
    (deep / "nested.py").write_text("import hashlib\nhashlib.sha512(b'x')\n")

    os.symlink("loop_b", root / "loop_a")
    os.symlink("loop_a", root / "loop_b")
    os.symlink("nowhere.py", root / "dangling.py")
    (root / "selfdir").mkdir()
    os.symlink("..", root / "selfdir" / "up")

    return root


@pytest.fixture
def unreadable_directory(hostile) -> Path:
    blocked = hostile / "blocked"
    blocked.mkdir()
    (blocked / "hidden.py").write_text(REAL_CRYPTO)
    blocked.chmod(0o000)
    if os.access(blocked, os.R_OK):
        pytest.skip("cannot make a directory unreadable as this user")
    try:
        yield hostile
    finally:
        blocked.chmod(0o755)


# ------------------------------------------------------------------ the whole hostile tree


def test_a_hostile_directory_scans_without_raising(hostile):
    result = scan(hostile)
    assert result.findings, "the good files must still be scanned"
    assert {f.algorithm for f in result.findings} >= {"MD5", "SHA-1", "SHA-256", "SHA-512"}


def test_one_bad_file_does_not_cost_the_others(hostile):
    """The property the whole step exists for."""
    result = scan(hostile)
    files = {f.location.file for f in result.findings}
    assert "good.py" in files
    assert any(name.endswith("nested.py") for name in files)


def test_the_cli_reports_rather_than_dying(hostile):
    outcome = runner.invoke(app, ["scan", str(hostile), "--format", "json"])
    assert outcome.exit_code == EXIT_OK
    assert json.loads(outcome.stdout)["findings"]


# ----------------------------------------------------------------------- unreadable source


@pytest.mark.parametrize(
    "name",
    ["syntax_error.py", "empty.py", "utf16.py", "nul_bytes.py"],
)
def test_unparseable_source_is_skipped_not_fatal(hostile, name):
    from cryptolens.analyzers.python_ast import analyze_file

    assert analyze_file(hostile / name, hostile) == []


def test_a_non_utf8_file_with_a_coding_cookie_is_still_read(hostile):
    """PEP 263: `ast.parse` honours the cookie when handed bytes, which is why the analyzer
    passes bytes rather than decoding first."""
    result = scan(hostile)
    files = {f.location.file for f in result.findings if f.algorithm == "SHA-256"}
    assert "latin1_with_cookie.py" in files


# --------------------------------------------------------------------- unreadable artifacts


@pytest.mark.parametrize(
    "name", ["empty.pem", "random.der", "truncated.pem", "not_base64.pem"]
)
def test_unreadable_artifacts_are_skipped_not_fatal(hostile, name):
    from cryptolens.certs.parser import parse_artifact

    assert parse_artifact(hostile / name, hostile) == []


# ------------------------------------------------------------------------------- symlinks


def test_a_symlink_loop_terminates(hostile):
    """`loop_a -> loop_b -> loop_a`. Following symlinked directories would not."""
    assert discover_source_files(hostile)
    assert scan(hostile).findings


def test_a_directory_symlink_pointing_upwards_does_not_recurse(hostile):
    files = discover_source_files(hostile)
    assert not any("selfdir" in p.parts for p in files)


def test_a_dangling_symlink_is_not_offered_as_a_file(hostile):
    """It is not a regular file, so discovery must not hand it to the analyzer at all."""
    assert not any(p.name == "dangling.py" for p in discover_source_files(hostile))


# ------------------------------------------------------------- things that are not files


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX only")
def test_a_named_pipe_is_never_opened(hostile):
    os.mkfifo(hostile / "pipe.pem")
    assert not any(p.name == "pipe.pem" for p in discover_artifact_files(hostile))
    assert not any(p.name == "pipe.py" for p in discover_source_files(hostile))


PIPE_PROBE = textwrap.dedent(
    """
    import os
    import sys
    from cryptolens.scan import scan

    root = sys.argv[1]
    os.mkfifo(os.path.join(root, "server.pem"))
    os.mkfifo(os.path.join(root, "module.py"))
    result = scan(root)
    print(len(result.findings))
    """
)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="POSIX only")
def test_a_named_pipe_does_not_hang_the_scan(hostile):
    """Opening a FIFO for reading blocks until a writer appears. A repository containing one
    called `server.pem` used to stop the scan forever -- no error, no traceback, no exit.

    Run out of process with a timeout, so a regression fails this test instead of hanging
    the whole suite.
    """
    completed = subprocess.run(
        [sys.executable, "-c", PIPE_PROBE, str(hostile)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    assert int(completed.stdout.strip()) > 0


def test_a_file_whose_name_is_an_ignored_directory_is_skipped(tmp_path):
    """`env` as a *file* name is unusual but legal, and the ignore list is checked against
    every path segment including the last."""
    (tmp_path / "keep.py").write_text(REAL_CRYPTO)
    (tmp_path / "env").write_text(REAL_CRYPTO)
    names = {p.name for p in discover_source_files(tmp_path)}
    assert names == {"keep.py"}


def test_a_file_that_cannot_be_stat_ed_is_skipped(tmp_path, monkeypatch):
    """A file can vanish between listing a directory and asking about it."""
    from pathlib import Path as RealPath

    from cryptolens.discovery import walk

    (tmp_path / "a.py").write_text(REAL_CRYPTO)

    def refuse(self):
        raise OSError("gone")

    monkeypatch.setattr(RealPath, "is_file", refuse)
    assert list(walk.walk_files(tmp_path)) == []


def test_an_unsniffable_file_is_not_treated_as_a_certificate(tmp_path, monkeypatch):
    from cryptolens.discovery import artifact_files

    (tmp_path / "mystery.bin").write_bytes(b"-----BEGIN CERTIFICATE-----\n")

    def refuse(*_args, **_kwargs):
        raise OSError("gone")

    monkeypatch.setattr(artifact_files, "open", refuse, raising=False)
    assert discover_artifact_files(tmp_path) == []


# ---------------------------------------------------------------------- unreadable directory


def test_an_unreadable_directory_warns_and_the_scan_continues(unreadable_directory, caplog):
    import logging

    with caplog.at_level(logging.WARNING):
        result = scan(unreadable_directory)

    assert result.findings, "the readable files must still be reported"
    assert any("cannot list" in record.message for record in caplog.records)


def test_an_unreadable_directory_is_not_silently_dropped(unreadable_directory):
    """`Path.rglob` swallows the `PermissionError`, so a whole subtree would vanish from the
    inventory without a word. `os.walk(onerror=...)` is the reason this is reportable."""
    files = {p.name for p in discover_source_files(unreadable_directory)}
    assert "hidden.py" not in files
    assert "good.py" in files


# ------------------------------------------------------------------------- the scan target


def test_a_missing_scan_root_is_an_error_not_a_traceback(tmp_path):
    with pytest.raises(ScanError):
        scan(tmp_path / "nope")


def test_an_empty_scan_root_is_not_an_error(tmp_path):
    result = scan(tmp_path)
    assert result.findings == []
    assert result.assets == []


def test_a_file_as_the_scan_root_is_refused_cleanly(tmp_path):
    target = tmp_path / "a.py"
    target.write_text(REAL_CRYPTO)
    outcome = runner.invoke(app, ["scan", str(target)])
    assert outcome.exit_code == EXIT_ERROR
    assert "not a directory" in outcome.stderr
