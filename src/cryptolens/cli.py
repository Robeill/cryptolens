from __future__ import annotations

import logging
import sys
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer

from cryptolens.cbom import build_bom, to_json
from cryptolens.model import RiskLevel
from cryptolens.reports import json_report, text
from cryptolens.scan import ScanError, ScanOptions, ScanResult, scan

VERSION = "0.1.0"

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

app = typer.Typer(
    add_completion=False,
    help="Cryptographic inventory and post-quantum migration scanner.",
)


class Format(str, Enum):
    TEXT = "text"
    JSON = "json"
    CBOM = "cbom"


class FailOn(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    NEVER = "never"


@app.command()
def version() -> None:
    """Print the CryptoLens version."""
    typer.echo(f"cryptolens {VERSION}")


@app.command("scan")
def scan_path(
    path: Annotated[Path, typer.Argument(help="Directory to scan.")] = Path(),
    output_format: Annotated[
        Format, typer.Option("--format", "-f", help="Report format.")
    ] = Format.TEXT,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write to a file instead of stdout.")
    ] = None,
    fail_on: Annotated[
        FailOn,
        typer.Option("--fail-on", help="Exit 1 if any finding reaches this risk level."),
    ] = FailOn.NEVER,
    ignore: Annotated[
        list[str] | None,
        typer.Option("--ignore", help="Directory name to skip. Repeatable."),
    ] = None,
    no_certs: Annotated[
        bool, typer.Option("--no-certs", help="Skip certificate and key files.")
    ] = False,
    evidence: Annotated[
        bool, typer.Option("--evidence", help="Include the source snippet for each finding.")
    ] = False,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Log skipped files.")] = False,
) -> None:
    """Scan a directory and report on its cryptography."""
    logging.basicConfig(
        level=logging.INFO if verbose else logging.ERROR,
        format="cryptolens: %(message)s",
    )

    try:
        result = scan(
            path,
            ScanOptions(include_artifacts=not no_certs, ignore=tuple(ignore or ())),
        )
    except ScanError as error:
        typer.echo(f"cryptolens: {error}", err=True)
        raise typer.Exit(EXIT_ERROR) from error

    document = _render(result, output_format, evidence)
    _emit(document, output)
    raise typer.Exit(_exit_code(result, fail_on))


def _render(result: ScanResult, output_format: Format, evidence: bool) -> str:
    if output_format is Format.JSON:
        return json_report.render(result)
    if output_format is Format.CBOM:
        return (
            to_json(
                build_bom(
                    result.assets,
                    target_name=result.root.name or str(result.root),
                    timestamp=result.scanned_at,
                )
            )
            + "\n"
        )
    return text.render(result, show_evidence=evidence)


def _emit(document: str, output: Path | None) -> None:
    if output is None:
        sys.stdout.write(document)
        return
    try:
        output.write_text(document, encoding="utf-8")
    except OSError as error:
        typer.echo(f"cryptolens: cannot write {output}: {error}", err=True)
        raise typer.Exit(EXIT_ERROR) from error


def _exit_code(result: ScanResult, fail_on: FailOn) -> int:
    if fail_on is FailOn.NEVER:
        return EXIT_OK
    threshold = RiskLevel(fail_on.value)
    return EXIT_FINDINGS if result.findings_at_or_above(threshold) else EXIT_OK


if __name__ == "__main__":
    app()
