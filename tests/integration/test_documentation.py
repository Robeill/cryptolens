"""The README describes the tool that exists.

Pasted terminal output and quoted numbers rot faster than anything else in a repository, and
this project removed its in-code comments on the understanding that the explanation lives in
prose instead. That trade is only honest if the prose is held to the same standard as the code.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cryptolens.cli import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, app

ROOT = Path(__file__).resolve().parent.parent.parent
EVAL_REPO = ROOT / "tests" / "fixtures" / "eval_repo"

runner = CliRunner()


@pytest.fixture(scope="module")
def readme() -> str:
    return (ROOT / "README.md").read_text()


@pytest.fixture(scope="module")
def report() -> str:
    outcome = runner.invoke(app, ["scan", str(EVAL_REPO)])
    assert outcome.exit_code == EXIT_OK
    return outcome.stdout


# --------------------------------------------------------------------------- what ships


def test_the_readme_exists_and_says_something(readme):
    assert len(readme.strip()) > 500


def test_the_evaluation_protocol_ships_with_the_repository():
    """`tools/evaluate.py` is only meaningful alongside the rules it implements, which were
    frozen before it was written."""
    assert (ROOT / "tools" / "PROTOCOL.md").is_file()


def test_every_link_resolves(readme):
    for target in re.findall(r"\]\(([^)#]+)\)", readme):
        assert (ROOT / target).exists(), target


def test_nothing_shipped_points_at_the_private_notes(readme):
    """`docs/` is the author's own working folder and is not part of the project."""
    assert "docs/" not in readme
    assert "docs/" not in (ROOT / "tools" / "PROTOCOL.md").read_text()


# ----------------------------------------------------------------- the claims are true


def test_every_command_in_the_readme_is_real(readme):
    help_text = " ".join(runner.invoke(app, ["scan", "--help"]).stdout.split())
    flags = set(re.findall(r"(--[a-z][a-z-]*)", readme)) - {"--help"}
    assert flags, "the readme shows no flags, so this proves nothing"
    for flag in sorted(flags):
        assert flag in help_text, flag


def test_the_documented_exit_codes_are_the_real_ones(readme, tmp_path):
    assert (EXIT_OK, EXIT_FINDINGS, EXIT_ERROR) == (0, 1, 2)
    assert "`0` clean, `1` findings at or above `--fail-on`, `2`" in readme
    assert runner.invoke(app, ["scan", str(EVAL_REPO)]).exit_code == EXIT_OK
    assert runner.invoke(
        app, ["scan", str(EVAL_REPO), "--fail-on", "critical"]
    ).exit_code == EXIT_FINDINGS
    assert runner.invoke(app, ["scan", str(tmp_path / "nope")]).exit_code == EXIT_ERROR


def test_the_example_output_is_real_output(readme, report):
    for line in (
        "auth/passwords.py:24               SHA-1 (hashing)",
        "transport/handshake.py:21          ECDH (key_establishment)",
        "line 19    TLS-unverified (key_establishment)  [immediate, confidence 1.00]",
    ):
        assert line in report, line
        assert line.strip() in readme, line


def test_the_summary_counts_are_a_real_scan(readme, report):
    for section in ("risk      critical=", "priority  immediate=", "totals    51 findings"):
        quoted = next(line for line in readme.splitlines() if section in line)
        assert quoted.strip() in report


def test_the_readme_leads_with_the_argument(readme):
    """The ECDH-versus-ECDSA contrast is the project's contribution, not a feature."""
    assert readme.index("ECDSA") < readme.index("## Install")
    assert "ML-DSA-65" in readme and "ML-KEM-768" in readme


# ------------------------------------------------------------------- the honest parts


def test_the_limitations_are_stated(readme):
    limitations = readme[readme.index("## Limitations"):]
    for topic in ("interprocedural", "purpose awareness", "onfidence", "getattr", "Python only"):
        assert topic in limitations, topic


def test_the_measured_failures_are_admitted_not_softened(readme):
    """The MD5-as-ETag failure and the confidence result are the two findings least
    flattering to the tool, and both belong in the README rather than in a footnote."""
    limitations = readme[readme.index("## Limitations"):]
    assert "graded HIGH" in limitations
    assert "Bandit gets this wrong too" in limitations
    assert "not a precision dial" in limitations
