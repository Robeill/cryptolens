from __future__ import annotations

import textwrap

from cryptolens.model import CryptoFinding, RiskLevel
from cryptolens.risk import Priority
from cryptolens.scan import ScanResult

WIDTH = 96
RULE = "=" * WIDTH
THIN = "-" * WIDTH

RISK_ORDER = (
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.LOW,
    RiskLevel.INFO,
)

PRIORITY_ORDER = (
    Priority.IMMEDIATE,
    Priority.URGENT,
    Priority.SCHEDULED,
    Priority.MONITOR,
    Priority.NONE,
)

PRIORITY_BLURBS = {
    Priority.IMMEDIATE: "broken today, or will outlive the 2035 deadline",
    Priority.URGENT: "harvest now, decrypt later -- the exposure has already begun",
    Priority.SCHEDULED: "quantum-vulnerable signatures; plan the migration",
    Priority.MONITOR: "unidentified or low concern; keep an eye on it",
    Priority.NONE: "nothing to do",
}


def render(result: ScanResult, show_evidence: bool = False) -> str:
    lines: list[str] = []
    lines.extend(_header(result))
    lines.extend(_summary(result))
    lines.extend(_worklist(result))
    lines.extend(_findings(result, show_evidence))
    lines.extend(_inventory(result))
    lines.extend(_footer(result))
    return "\n".join(lines) + "\n"


def _header(result: ScanResult) -> list[str]:
    return [
        RULE,
        "CryptoLens -- cryptographic inventory and post-quantum migration report",
        RULE,
        f"target   {result.root}",
        f"scanned  {result.scanned_at.isoformat()}",
        f"files    {result.source_files} source, {result.artifact_files} artifact",
        "",
    ]


def _summary(result: ScanResult) -> list[str]:
    lines = ["SUMMARY", THIN]
    if not result.findings:
        return [*lines, "No cryptographic usage found.", ""]

    risks = result.risk_counts()
    priorities = result.priority_counts()
    lines.append(
        "  risk      " + "  ".join(f"{level.value}={risks[level]}" for level in RISK_ORDER)
    )
    lines.append(
        "  priority  "
        + "  ".join(f"{priority.value}={priorities[priority]}" for priority in PRIORITY_ORDER)
    )
    migration = result.migration_counts()
    lines.append(
        "  quantum   "
        + "  ".join(f"{status.value}={count}" for status, count in migration.items() if count)
    )
    lines.append(
        f"  totals    {len(result.findings)} findings in {len(result.assets)} distinct assets"
    )
    lines.append("")
    return lines


def _worklist(result: ScanResult) -> list[str]:
    ranked = [
        finding
        for finding in result.ranked_findings()
        if result.assessment_for(finding).priority
        in {Priority.IMMEDIATE, Priority.URGENT}
    ]
    if not ranked:
        return []

    lines = ["WHAT TO DO FIRST", THIN]
    for priority in (Priority.IMMEDIATE, Priority.URGENT):
        rows = sorted(
            (f for f in ranked if result.assessment_for(f).priority is priority),
            key=lambda f: (f.location.file, f.location.line, f.algorithm),
        )
        if not rows:
            continue
        lines.append(f"  {priority.value.upper()} ({len(rows)}) -- {PRIORITY_BLURBS[priority]}")
        for finding in rows:
            lines.append(f"    {_location(finding):<34} {_label(finding)}")
        lines.append("")
    return lines


def _findings(result: ScanResult, show_evidence: bool) -> list[str]:
    grouped = result.findings_by_risk()
    if not grouped:
        return []

    lines = ["FINDINGS", THIN]
    for level in RISK_ORDER:
        rows = grouped.get(level)
        if not rows:
            continue
        lines.append(f"  {level.value.upper()} ({len(rows)})")
        current_file = None
        for finding in rows:
            if finding.location.file != current_file:
                current_file = finding.location.file
                lines.append(f"    {current_file}")
            lines.extend(_finding_block(result, finding, show_evidence))
        lines.append("")
    return lines


def _finding_block(
    result: ScanResult, finding: CryptoFinding, show_evidence: bool
) -> list[str]:
    assessment = result.assessment_for(finding)
    lines = [
        (
            f"      line {finding.location.line:<5} {_label(finding)}"
            f"  [{assessment.priority.value}, confidence {finding.confidence:.2f}]"
        )
    ]
    if show_evidence:
        lines.extend(_wrap(finding.evidence, "        ", "          "))
    for reason in assessment.reasons:
        lines.extend(_wrap(reason.explanation, "        - ", "          "))

    recommendation = result.recommendation_for(finding)
    if recommendation is not None:
        lines.extend(_wrap(_advice(recommendation), "        -> ", "           "))
    return lines


def _wrap(text: str, first_indent: str, later_indent: str) -> list[str]:
    return textwrap.wrap(
        text,
        width=WIDTH,
        initial_indent=first_indent,
        subsequent_indent=later_indent,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [first_indent.rstrip()]


def _advice(recommendation) -> str:
    if recommendation.primary is None:
        candidates = " or ".join(m.name for m in recommendation.mechanisms)
        return f"replace with {candidates} -- {recommendation.rationale}"
    alternatives = ", ".join(m.name for m in recommendation.alternatives)
    tail = f" (alternatives: {alternatives})" if alternatives else ""
    rationale = recommendation.primary.rationale
    hybrid = (
        " Deploy as a hybrid with the classical algorithm during the transition."
        if recommendation.hybrid_advised and "hybrid" not in rationale
        else ""
    )
    return f"replace with {recommendation.primary.name}{tail} -- {rationale}{hybrid}"


def _inventory(result: ScanResult) -> list[str]:
    if not result.assets:
        return []
    lines = [
        "INVENTORY",
        THIN,
        f"  {'asset':<26}{'type':<24}{'purpose':<19}{'uses':>5}  {'risk':<9}priority",
    ]
    for asset in result.ranked_assets():
        lines.append(
            f"  {_asset_name(asset):<26}{asset.asset_type.value:<24}"
            f"{asset.purpose.value:<19}{asset.occurrence_count:>5}  "
            f"{asset.risk(result.assessments).value:<9}"
            f"{asset.priority(result.assessments).value}"
        )
    lines.append("")
    return lines


def _footer(result: ScanResult) -> list[str]:
    lines = [THIN]
    if result.skipped:
        lines.append(f"{len(result.skipped)} file(s) could not be read and were skipped.")
    worst = result.worst_risk.value
    highest = result.worst_priority.value
    lines.append(f"worst risk {worst}, highest priority {highest}.")
    return lines


def _location(finding: CryptoFinding) -> str:
    if finding.location.line == 0:
        return finding.location.file
    return f"{finding.location.file}:{finding.location.line}"


def _label(finding: CryptoFinding) -> str:
    parts = [finding.algorithm]
    if finding.key_size:
        parts.append(f"{finding.key_size}-bit")
    if finding.mode.value not in {"unknown", "other"}:
        parts.append(finding.mode.value.upper())
    return f"{' '.join(parts)} ({finding.purpose.value})"


def _asset_name(asset) -> str:
    """Two `RSA` rows that differ only in padding must not read as duplicates."""
    parts = [asset.algorithm]
    if asset.key_size:
        parts.append(f"{asset.key_size}-bit")
    if asset.mode.value not in {"unknown", "other"}:
        parts.append(asset.mode.value.upper())
    if asset.parameter_set and asset.parameter_set != asset.algorithm:
        parts.append(asset.parameter_set)
    padding = asset.padding.value.upper()
    if padding not in {"UNKNOWN", "OTHER"} and padding != asset.algorithm.upper():
        parts.append(padding)
    return " ".join(parts)
