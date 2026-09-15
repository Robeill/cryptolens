from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptolens.analyzers.python_ast import analyze_file
from cryptolens.cbom.aggregate import CryptoAsset, aggregate
from cryptolens.certs.parser import parse_artifact
from cryptolens.detectors.engine import detect
from cryptolens.discovery.artifact_files import discover_artifact_files
from cryptolens.discovery.source_files import discover_source_files
from cryptolens.model import CryptoFinding, MigrationStatus, RiskLevel, max_risk
from cryptolens.pqc.catalog import Recommendation, recommend
from cryptolens.risk import Assessment, Priority, assess, priority_rank

logger = logging.getLogger(__name__)


class ScanError(Exception):
    pass


@dataclass(frozen=True)
class ScanOptions:
    include_artifacts: bool = True
    ignore: tuple[str, ...] = ()


@dataclass
class ScanResult:
    root: Path
    scanned_at: datetime
    findings: list[CryptoFinding] = field(default_factory=list)
    assets: list[CryptoAsset] = field(default_factory=list)
    assessments: dict[str, Assessment] = field(default_factory=dict)
    recommendations: dict[str, Recommendation] = field(default_factory=dict)
    source_files: int = 0
    artifact_files: int = 0
    skipped: list[str] = field(default_factory=list)

    @property
    def files_scanned(self) -> int:
        return self.source_files + self.artifact_files

    @property
    def worst_risk(self) -> RiskLevel:
        return max_risk([a.risk for a in self.assessments.values()])

    @property
    def worst_priority(self) -> Priority:
        if not self.assessments:
            return Priority.NONE
        return max((a.priority for a in self.assessments.values()), key=priority_rank)

    def risk_counts(self) -> dict[RiskLevel, int]:
        counted = Counter(a.risk for a in self.assessments.values())
        return {level: counted.get(level, 0) for level in RiskLevel}

    def priority_counts(self) -> dict[Priority, int]:
        counted = Counter(a.priority for a in self.assessments.values())
        return {priority: counted.get(priority, 0) for priority in Priority}

    def migration_counts(self) -> dict[MigrationStatus, int]:
        counted = Counter(f.migration_status for f in self.findings)
        return {status: counted.get(status, 0) for status in MigrationStatus}

    def assessment_for(self, finding: CryptoFinding) -> Assessment:
        return self.assessments[finding.finding_id]

    def recommendation_for(self, finding: CryptoFinding) -> Recommendation | None:
        return self.recommendations.get(finding.finding_id)

    def findings_at_or_above(self, level: RiskLevel) -> list[CryptoFinding]:
        return [
            finding
            for finding in self.findings
            if self.assessments[finding.finding_id].risk.rank >= level.rank
        ]

    def ranked_findings(self) -> list[CryptoFinding]:
        """Worst first, then by location. Stable across runs by construction."""
        return sorted(
            self.findings,
            key=lambda f: (
                -self.assessments[f.finding_id].risk.rank,
                -priority_rank(self.assessments[f.finding_id].priority),
                f.location.file,
                f.location.line,
                f.algorithm,
                f.finding_id,
            ),
        )

    def findings_by_risk(self) -> dict[RiskLevel, list[CryptoFinding]]:
        grouped: dict[RiskLevel, list[CryptoFinding]] = {level: [] for level in RiskLevel}
        for finding in self.ranked_findings():
            grouped[self.assessments[finding.finding_id].risk].append(finding)
        return {level: rows for level, rows in grouped.items() if rows}

    def ranked_assets(self) -> list[CryptoAsset]:
        return sorted(
            self.assets,
            key=lambda a: (
                -a.risk(self.assessments).rank,
                -priority_rank(a.priority(self.assessments)),
                a.asset_type.value,
                a.algorithm,
                a.asset_id,
            ),
        )


def scan(
    path: str | Path,
    options: ScanOptions | None = None,
    now: datetime | None = None,
) -> ScanResult:
    options = options or ScanOptions()
    root = Path(path)
    if not root.exists():
        raise ScanError(f"no such path: {root}")
    if not root.is_dir():
        raise ScanError(f"not a directory: {root}")

    root = root.resolve()
    moment = now or datetime.now(UTC)
    result = ScanResult(root=root, scanned_at=moment)
    ignore = list(options.ignore) or None

    result.findings.extend(_scan_sources(root, ignore, result))
    if options.include_artifacts:
        result.findings.extend(_scan_artifacts(root, ignore, result))

    result.assets = aggregate(result.findings)
    for finding in result.findings:
        result.assessments[finding.finding_id] = assess(finding, moment)
        recommendation = recommend(finding)
        if recommendation is not None:
            result.recommendations[finding.finding_id] = recommendation
    return result


def _read_each(
    paths: Iterable[Path], root: Path, read: Callable[[Path, Path], list], result: ScanResult
) -> list:
    """Read every file, and let one unreadable file cost only itself.

    The handler is belt-and-braces -- `analyze_file` and `parse_artifact` already swallow
    their own errors -- but never crashing on bad input is a stated principle, and one
    unanticipated exception should not cost the other six hundred files.
    """
    collected = []
    for path in paths:
        try:
            collected.extend(read(path, root))
        except Exception:
            logger.debug("failed to read %s", path, exc_info=True)
            result.skipped.append(str(_relative(path, root)))
    return collected


def _scan_sources(root: Path, ignore: list[str] | None, result: ScanResult) -> list[CryptoFinding]:
    paths = discover_source_files(root, ignore)
    result.source_files = len(paths)
    return detect(_read_each(paths, root, analyze_file, result))


def _scan_artifacts(
    root: Path, ignore: list[str] | None, result: ScanResult
) -> list[CryptoFinding]:
    paths = discover_artifact_files(root, ignore)
    result.artifact_files = len(paths)
    return _read_each(paths, root, parse_artifact, result)


def _relative(path: Path, root: Path) -> Path:
    try:
        return path.resolve().relative_to(root)
    except ValueError:
        return path
