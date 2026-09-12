"""The two human- and machine-facing renderers.

The text report is the deliverable a developer reads; the JSON one is what another tool
consumes. Both must be stable byte-for-byte given the same scan.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from cryptolens.reports import json_report, text
from cryptolens.scan import scan

EXAMPLE_REPO = Path(__file__).resolve().parent.parent / "fixtures" / "example_repo"
NOW = datetime(2026, 9, 11, tzinfo=UTC)


@pytest.fixture(scope="module")
def result():
    return scan(EXAMPLE_REPO, now=NOW)


@pytest.fixture(scope="module")
def report(result):
    return text.render(result)


@pytest.fixture(scope="module")
def payload(result):
    return json.loads(json_report.render(result))


# --------------------------------------------------------------------------- text report


def test_the_report_names_the_target_and_the_moment(report):
    assert "example_repo" in report
    assert "2026-09-11T00:00:00+00:00" in report


def test_the_report_summarises_before_it_enumerates(report):
    assert report.index("SUMMARY") < report.index("FINDINGS")
    assert report.index("WHAT TO DO FIRST") < report.index("FINDINGS")


def test_the_worklist_leads_with_what_is_broken_today(report):
    worklist = report.split("WHAT TO DO FIRST")[1].split("FINDINGS")[0]
    assert worklist.index("IMMEDIATE") < worklist.index("URGENT")
    assert "broken today" in worklist
    assert "harvest now, decrypt later" in worklist


def test_findings_are_grouped_by_risk_worst_first(report):
    section = report.split("FINDINGS")[1]
    order = [section.index(level) for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
    assert order == sorted(order)


def test_each_finding_carries_a_location_an_algorithm_and_a_purpose(report):
    assert "line 21    MD5 (hashing)" in report
    assert "line 30    ECDH (key_establishment)" in report


def test_each_finding_says_why_it_is_listed(report):
    assert "MD5 collisions are computable in seconds" in report
    assert "anyone can forge one" in report


def test_the_pqc_recommendation_reaches_the_report(report):
    assert "replace with ML-KEM-768" in report
    assert "replace with ML-DSA-65" in report


def test_an_ambiguous_recommendation_offers_both_rather_than_picking(report):
    assert "replace with ML-KEM-768 or ML-DSA-65" in report


def test_the_inventory_distinguishes_rows_that_share_an_algorithm(report):
    inventory = report.split("INVENTORY")[1]
    assert "AES ECB" in inventory
    assert "AES GCM" in inventory
    assert "RSA 1024-bit" in inventory


def test_the_inventory_shows_the_collapse(report):
    inventory = report.split("INVENTORY")[1]
    sha256 = [line for line in inventory.splitlines() if line.startswith("  SHA-256 ")]
    assert len(sha256) == 1
    assert "11" in sha256[0]


def test_the_report_ends_with_the_worst_of_it(report):
    assert report.rstrip().endswith("worst risk critical, highest priority immediate.")


def test_no_line_overruns_the_report_width(report):
    assert max(len(line) for line in report.splitlines()) <= text.WIDTH


def test_evidence_is_off_by_default_and_available_on_request(result):
    assert "hashlib.md5(payload)" not in text.render(result)
    assert "hashlib.md5(payload)" in text.render(result, show_evidence=True)


def test_two_renders_of_one_scan_are_identical(result):
    assert text.render(result) == text.render(result)


def test_an_empty_scan_still_renders(tmp_path):
    report = text.render(scan(tmp_path, now=NOW))
    assert "No cryptographic usage found." in report
    assert "FINDINGS" not in report
    assert "worst risk info" in report


def test_a_worklist_with_nothing_broken_today_omits_that_block(tmp_path):
    """Only quantum exposure, nothing classically broken: the report must not print an empty
    IMMEDIATE heading."""
    (tmp_path / "exchange.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import ec\n\n\n"
        "def agree(private_key, peer):\n"
        "    return private_key.exchange(ec.ECDH(), peer)\n"
    )
    report = text.render(scan(tmp_path, now=NOW))
    worklist = report.split("WHAT TO DO FIRST")[1].split("FINDINGS")[0]
    assert "URGENT" in worklist
    assert "IMMEDIATE" not in worklist


def test_a_report_with_no_urgent_work_omits_the_worklist_entirely(tmp_path):
    (tmp_path / "good.py").write_text("import hashlib\nhashlib.sha256(b'x')\n")
    report = text.render(scan(tmp_path, now=NOW))
    assert "WHAT TO DO FIRST" not in report
    assert "FINDINGS" in report


def test_artifact_findings_are_shown_without_a_line_number(artifact_repo):
    """There is no line 12 in a DER file, so the report names the file and stops."""
    report = text.render(scan(artifact_repo, now=NOW))
    worklist = report.split("WHAT TO DO FIRST")[1].split("FINDINGS")[0]
    assert "expired_cert.pem " in worklist
    assert "expired_cert.pem:0" not in worklist


def test_skipped_files_are_counted_in_the_footer(tmp_path, monkeypatch):
    import cryptolens.scan as scan_module

    (tmp_path / "a.py").write_text("import hashlib\n")
    monkeypatch.setattr(
        scan_module, "analyze_file", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("x"))
    )
    report = text.render(scan(tmp_path, now=NOW))
    assert "1 file(s) could not be read and were skipped." in report


# --------------------------------------------------------------------------- json report


def test_the_json_report_declares_its_schema(payload):
    assert payload["schema"] == "cryptolens/report/1"
    assert payload["scanned_at"] == "2026-09-11T00:00:00+00:00"


def test_the_json_summary_matches_the_findings(payload):
    assert payload["summary"]["findings"] == len(payload["findings"])
    assert payload["summary"]["assets"] == len(payload["assets"])
    assert payload["summary"]["worst_risk"] == "critical"
    assert sum(payload["summary"]["by_risk"].values()) == len(payload["findings"])


def test_every_finding_carries_its_assessment(payload):
    for finding in payload["findings"]:
        assert set(finding["assessment"]) >= {"risk", "classical_risk", "quantum_risk",
                                              "priority", "reasons"}


def test_the_two_risk_axes_survive_into_json(payload):
    ecdh = next(f for f in payload["findings"] if f["algorithm"] == "ECDH")
    assert ecdh["assessment"]["classical_risk"] == "info"
    assert ecdh["assessment"]["quantum_risk"] == "high"


def test_recommendations_name_their_standard(payload):
    recommended = [f for f in payload["findings"] if "recommendation" in f]
    assert recommended
    mechanism = recommended[0]["recommendation"]["mechanisms"][0]
    assert mechanism["standard"].startswith("FIPS")
    assert mechanism["nist_quantum_security_level"] in {1, 2, 3, 5}


def test_assets_carry_their_occurrences(payload):
    sha256 = next(
        a for a in payload["assets"]
        if a["algorithm"] == "SHA-256" and a["asset_type"] == "algorithm"
    )
    assert len(sha256["occurrences"]) == 11
    assert {o["file"] for o in sha256["occurrences"]}


def test_the_occurrence_total_equals_the_finding_total(payload):
    total = sum(len(asset["occurrences"]) for asset in payload["assets"])
    assert total == len(payload["findings"])


def test_findings_are_ranked_in_the_json_too(payload):
    ranks = ["critical", "high", "medium", "low", "info"]
    positions = [ranks.index(f["assessment"]["risk"]) for f in payload["findings"]]
    assert positions == sorted(positions)


def test_the_json_is_deterministic(result):
    assert json_report.render(result) == json_report.render(result)


def test_the_json_report_is_json(result):
    json.loads(json_report.render(result))
