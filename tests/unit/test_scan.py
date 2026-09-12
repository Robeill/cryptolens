"""The scan orchestrator: the one place that joins discovery, analysis, detection, risk and
aggregation, and the one place a scan can fail."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from cryptolens.model import RiskLevel
from cryptolens.risk import Priority
from cryptolens.scan import ScanError, ScanOptions, scan

EXAMPLE_REPO = Path(__file__).resolve().parent.parent / "fixtures" / "example_repo"
NOW = datetime(2026, 9, 11, tzinfo=UTC)


@pytest.fixture(scope="module")
def result():
    return scan(EXAMPLE_REPO, now=NOW)


def test_a_scan_joins_every_stage(result):
    assert result.findings
    assert result.assets
    assert len(result.assessments) == len({f.finding_id for f in result.findings})
    assert result.recommendations


def test_every_finding_has_an_assessment(result):
    for finding in result.findings:
        assert result.assessment_for(finding) is not None


def test_only_quantum_vulnerable_findings_get_recommendations(result):
    for finding in result.findings:
        expected = finding.migration_status.value == "quantum_vulnerable"
        assert (result.recommendation_for(finding) is not None) is expected


def test_locations_are_relative_to_the_scan_root(result):
    for finding in result.findings:
        assert not finding.location.file.startswith("/")
        assert (EXAMPLE_REPO / finding.location.file).exists()


def test_file_counts_are_reported(result):
    assert result.source_files == 9
    assert result.artifact_files == 0
    assert result.files_scanned == 9


def test_the_scan_timestamp_is_injectable(result):
    assert result.scanned_at == NOW


# ---------------------------------------------------------------------------- ordering


def test_findings_are_ranked_worst_first(result):
    ranked = result.ranked_findings()
    risks = [result.assessment_for(f).risk.rank for f in ranked]
    assert risks == sorted(risks, reverse=True)


def test_ranking_is_stable_across_runs(result):
    first = [f.finding_id for f in result.ranked_findings()]
    second = [f.finding_id for f in result.ranked_findings()]
    assert first == second


def test_findings_are_grouped_by_risk_without_losing_any(result):
    grouped = result.findings_by_risk()
    assert sum(len(rows) for rows in grouped.values()) == len(result.findings)
    assert RiskLevel.CRITICAL in grouped


def test_assets_are_ranked_worst_first(result):
    ranked = result.ranked_assets()
    risks = [a.risk(result.assessments).rank for a in ranked]
    assert risks == sorted(risks, reverse=True)


# ----------------------------------------------------------------------------- summary


def test_counts_add_up_to_the_findings(result):
    assert sum(result.risk_counts().values()) == len(result.findings)
    assert sum(result.priority_counts().values()) == len(result.findings)
    assert sum(result.migration_counts().values()) == len(result.findings)


def test_the_worst_of_everything_is_reported(result):
    assert result.worst_risk is RiskLevel.CRITICAL
    assert result.worst_priority is Priority.IMMEDIATE


@pytest.mark.parametrize(
    ("level", "at_least"),
    [(RiskLevel.CRITICAL, 1), (RiskLevel.HIGH, 2), (RiskLevel.INFO, 68)],
    ids=["critical", "high", "info"],
)
def test_findings_at_or_above_a_level(result, level, at_least):
    assert len(result.findings_at_or_above(level)) >= at_least


def test_the_threshold_is_inclusive(result):
    critical = result.findings_at_or_above(RiskLevel.CRITICAL)
    assert all(result.assessment_for(f).risk is RiskLevel.CRITICAL for f in critical)


# ------------------------------------------------------------------------------ options


def test_artifacts_are_scanned_by_default(artifact_repo):
    result = scan(artifact_repo, now=NOW)
    assert result.artifact_files > 0
    assert result.findings


def test_no_certs_skips_artifact_files(artifact_repo):
    result = scan(artifact_repo, ScanOptions(include_artifacts=False), now=NOW)
    assert result.artifact_files == 0
    assert result.findings == []


def test_ignored_directories_are_skipped(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    vendored = tmp_path / "vendor"
    vendored.mkdir()
    (vendored / "b.py").write_text("import hashlib\nhashlib.sha1(b'x')\n")

    everything = scan(tmp_path, now=NOW)
    filtered = scan(tmp_path, ScanOptions(ignore=("vendor",)), now=NOW)

    assert {f.algorithm for f in everything.findings} == {"MD5", "SHA-1"}
    assert {f.algorithm for f in filtered.findings} == {"MD5"}


def test_a_scan_of_an_empty_directory_is_not_an_error(tmp_path):
    result = scan(tmp_path, now=NOW)
    assert result.findings == []
    assert result.assets == []
    assert result.worst_risk is RiskLevel.INFO
    assert result.worst_priority is Priority.NONE


# ------------------------------------------------------------------------------- errors


def test_a_missing_path_raises_a_scan_error(tmp_path):
    with pytest.raises(ScanError, match="no such path"):
        scan(tmp_path / "nope")


def test_a_file_is_not_a_scannable_target(tmp_path):
    target = tmp_path / "a.py"
    target.write_text("import hashlib\n")
    with pytest.raises(ScanError, match="not a directory"):
        scan(target)


def test_a_syntactically_broken_file_does_not_stop_the_scan(tmp_path):
    (tmp_path / "good.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / "broken.py").write_text("def (((:\n")
    result = scan(tmp_path, now=NOW)
    assert {f.algorithm for f in result.findings} == {"MD5"}
    assert result.source_files == 2


def test_an_unreadable_artifact_does_not_stop_the_scan(tmp_path):
    (tmp_path / "good.py").write_text("import hashlib\nhashlib.md5(b'x')\n")
    (tmp_path / "junk.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nnonsense\n")
    result = scan(tmp_path, now=NOW)
    assert {f.algorithm for f in result.findings} == {"MD5"}
    assert result.artifact_files == 1


def test_a_file_that_blows_up_the_analyzer_is_recorded_as_skipped(tmp_path, monkeypatch):
    """`analyze_file` swallows its own errors, so this handler is belt-and-braces. A scan must
    never crash -- that is a stated principle, not a nicety."""
    import cryptolens.scan as scan_module

    (tmp_path / "a.py").write_text("import hashlib\n")

    def explode(*_args, **_kwargs):
        raise RuntimeError("something no one anticipated")

    monkeypatch.setattr(scan_module, "analyze_file", explode)
    result = scan(tmp_path, now=NOW)
    assert result.findings == []
    assert result.skipped == ["a.py"]


def test_an_artifact_that_blows_up_the_parser_is_recorded_as_skipped(tmp_path, monkeypatch):
    import cryptolens.scan as scan_module

    (tmp_path / "a.pem").write_bytes(b"-----BEGIN CERTIFICATE-----\nx\n")

    def explode(*_args, **_kwargs):
        raise RuntimeError("something no one anticipated")

    monkeypatch.setattr(scan_module, "parse_artifact", explode)
    result = scan(tmp_path, now=NOW)
    assert result.findings == []
    assert result.skipped == ["a.pem"]


def test_a_path_outside_the_root_keeps_its_own_name(tmp_path):
    from cryptolens.scan import _relative

    assert _relative(Path("/elsewhere/a.py"), tmp_path) == Path("/elsewhere/a.py")


def test_a_scan_defaults_to_the_current_clock(tmp_path):
    result = scan(tmp_path)
    assert result.scanned_at.tzinfo is not None
