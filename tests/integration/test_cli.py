"""The command line, driven through Typer's runner.

Exit codes are the only reason a scanner is usable in automation, so they are tested as
carefully as the output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cryptolens.cbom import validate
from cryptolens.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app

EXAMPLE_REPO = Path(__file__).resolve().parent.parent / "fixtures" / "example_repo"
runner = CliRunner()


def run(*args):
    return runner.invoke(app, list(args))


# ------------------------------------------------------------------ the Typer arrangement


def test_the_app_stays_in_multi_command_mode():
    """With one registered command Typer collapses into single-command mode and rejects the
    subcommand name. The second command is load-bearing -- see decisions.md."""
    result = run("version")
    assert result.exit_code == EXIT_OK
    assert "cryptolens" in result.stdout

    assert run("scan", str(EXAMPLE_REPO)).exit_code == EXIT_OK


def test_scan_is_the_command_name_the_plan_specifies():
    assert "scan" in run("--help").stdout


# ------------------------------------------------------------------------------ formats


def test_the_default_format_is_the_text_report():
    result = run("scan", str(EXAMPLE_REPO))
    assert result.exit_code == EXIT_OK
    assert "CryptoLens" in result.stdout
    assert "WHAT TO DO FIRST" in result.stdout


def test_the_json_format_is_machine_readable():
    """Nothing may print to stdout except the document -- an optional dependency once did."""
    result = run("scan", str(EXAMPLE_REPO), "--format", "json")
    payload = json.loads(result.stdout)
    assert payload["schema"] == "cryptolens/report/1"
    assert payload["findings"]


def test_the_cbom_format_validates_against_the_schema():
    result = run("scan", str(EXAMPLE_REPO), "--format", "cbom")
    assert validate(result.stdout) is None
    assert json.loads(result.stdout)["specVersion"] == "1.6"


def test_an_unknown_format_is_refused():
    assert run("scan", str(EXAMPLE_REPO), "--format", "yaml").exit_code != EXIT_OK


# -------------------------------------------------------------------------- exit codes


@pytest.mark.parametrize(
    ("fail_on", "expected"),
    [
        ("never", EXIT_OK),
        ("critical", EXIT_FINDINGS),
        ("high", EXIT_FINDINGS),
        ("info", EXIT_FINDINGS),
    ],
)
def test_fail_on_decides_the_exit_code(fail_on, expected):
    assert run("scan", str(EXAMPLE_REPO), "--fail-on", fail_on).exit_code == expected


def test_a_clean_directory_exits_zero_at_any_threshold(tmp_path):
    (tmp_path / "plain.py").write_text("def add(a, b):\n    return a + b\n")
    for level in ("critical", "high", "medium", "low", "info"):
        assert run("scan", str(tmp_path), "--fail-on", level).exit_code == EXIT_OK


def test_a_directory_with_only_sound_cryptography_passes_a_high_threshold(tmp_path):
    (tmp_path / "good.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    assert run("scan", str(tmp_path), "--fail-on", "high").exit_code == EXIT_OK
    assert run("scan", str(tmp_path), "--fail-on", "info").exit_code == EXIT_FINDINGS


def test_scanning_nothing_is_an_error_not_a_crash(tmp_path):
    result = run("scan", str(tmp_path / "does-not-exist"))
    assert result.exit_code == EXIT_ERROR
    assert "no such path" in result.stderr


def test_scanning_a_file_rather_than_a_directory_is_an_error(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("import hashlib\n")
    result = run("scan", str(target))
    assert result.exit_code == EXIT_ERROR
    assert "not a directory" in result.stderr


def test_an_unwritable_output_path_is_an_error(tmp_path):
    result = run(
        "scan", str(EXAMPLE_REPO), "--output", str(tmp_path / "missing" / "out.txt")
    )
    assert result.exit_code == EXIT_ERROR
    assert "cannot write" in result.stderr


# ----------------------------------------------------------------------------- options


def test_output_writes_the_document_to_a_file(tmp_path):
    target = tmp_path / "report.json"
    result = run("scan", str(EXAMPLE_REPO), "--format", "json", "--output", str(target))
    assert result.exit_code == EXIT_OK
    assert result.stdout == ""
    assert json.loads(target.read_text())["findings"]


def test_ignore_is_repeatable(tmp_path):
    for name, algorithm in (("kept", "md5"), ("one", "sha1"), ("two", "sha1")):
        directory = tmp_path / name
        directory.mkdir()
        (directory / "m.py").write_text(f"import hashlib\nhashlib.{algorithm}(b'x')\n")

    everything = run("scan", str(tmp_path), "--format", "json")
    filtered = run(
        "scan", str(tmp_path), "--format", "json", "--ignore", "one", "--ignore", "two"
    )
    assert {f["algorithm"] for f in json.loads(everything.stdout)["findings"]} == {"MD5", "SHA-1"}
    assert {f["algorithm"] for f in json.loads(filtered.stdout)["findings"]} == {"MD5"}


def test_no_certs_skips_artifact_files(artifact_repo):
    with_certs = json.loads(run("scan", str(artifact_repo), "--format", "json").stdout)
    without = json.loads(
        run("scan", str(artifact_repo), "--format", "json", "--no-certs").stdout
    )
    assert with_certs["findings"]
    assert without["findings"] == []
    assert without["files"]["artifact"] == 0


def test_evidence_adds_the_source_snippet():
    plain = run("scan", str(EXAMPLE_REPO)).stdout
    detailed = run("scan", str(EXAMPLE_REPO), "--evidence").stdout
    assert "hashlib.md5(payload)" not in plain
    assert "hashlib.md5(payload)" in detailed


def test_the_default_path_is_the_working_directory(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    monkeypatch.chdir(tmp_path)
    payload = json.loads(run("scan", "--format", "json").stdout)
    assert [f["algorithm"] for f in payload["findings"]] == ["MD5"]


# ----------------------------------------------------------------------- whole pipeline


def test_a_scan_of_certificates_and_source_together(artifact_repo, tmp_path):
    combined = tmp_path / "app"
    combined.mkdir()
    (combined / "code.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    for artifact in ("rsa_cert.pem", "mldsa_cert.pem"):
        (combined / artifact).write_bytes((artifact_repo / artifact).read_bytes())

    payload = json.loads(run("scan", str(combined), "--format", "json").stdout)
    algorithms = {f["algorithm"] for f in payload["findings"]}
    assert {"SHA-256", "RSA", "ML-DSA-65"} <= algorithms
    assert payload["files"]["source"] == 1
    assert payload["files"]["artifact"] == 2
