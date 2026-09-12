from __future__ import annotations

import json
from typing import Any

from cryptolens.cbom.aggregate import CryptoAsset
from cryptolens.model import CryptoFinding
from cryptolens.pqc.catalog import Recommendation
from cryptolens.risk import Assessment
from cryptolens.scan import ScanResult

SCHEMA = "cryptolens/report/1"


def render(result: ScanResult, indent: int = 2) -> str:
    return json.dumps(build(result), indent=indent, sort_keys=True) + "\n"


def build(result: ScanResult) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "target": str(result.root),
        "scanned_at": result.scanned_at.isoformat(),
        "files": {
            "source": result.source_files,
            "artifact": result.artifact_files,
            "skipped": sorted(result.skipped),
        },
        "summary": _summary(result),
        "findings": [_finding(result, finding) for finding in result.ranked_findings()],
        "assets": [_asset(result, asset) for asset in result.ranked_assets()],
    }


def _summary(result: ScanResult) -> dict[str, Any]:
    return {
        "findings": len(result.findings),
        "assets": len(result.assets),
        "worst_risk": result.worst_risk.value,
        "highest_priority": result.worst_priority.value,
        "by_risk": {level.value: count for level, count in result.risk_counts().items()},
        "by_priority": {
            priority.value: count for priority, count in result.priority_counts().items()
        },
        "by_migration_status": {
            status.value: count for status, count in result.migration_counts().items()
        },
    }


def _finding(result: ScanResult, finding: CryptoFinding) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": finding.finding_id,
        "algorithm": finding.algorithm,
        "asset_type": finding.asset_type.value,
        "primitive": finding.primitive.value,
        "purpose": finding.purpose.value,
        "mode": finding.mode.value,
        "padding": finding.padding.value,
        "parameter_set": finding.parameter_set,
        "curve": finding.curve,
        "key_size": finding.key_size,
        "oid": finding.oid,
        "status": finding.status.value,
        "migration_status": finding.migration_status.value,
        "classical_security_level": finding.classical_security_level,
        "nist_quantum_security_level": finding.nist_quantum_security_level,
        "crypto_functions": [function.value for function in finding.crypto_functions],
        "confidence": finding.confidence,
        "detector": finding.detector,
        "location": {"file": finding.location.file, "line": finding.location.line},
        "evidence": finding.evidence,
        "extra": finding.extra,
        "assessment": _assessment(result.assessment_for(finding)),
    }
    recommendation = result.recommendation_for(finding)
    if recommendation is not None:
        payload["recommendation"] = _recommendation(recommendation)
    return payload


def _assessment(assessment: Assessment) -> dict[str, Any]:
    return {
        "risk": assessment.risk.value,
        "classical_risk": assessment.classical_risk.value,
        "quantum_risk": assessment.quantum_risk.value,
        "priority": assessment.priority.value,
        "broken_today": assessment.broken_today,
        "reasons": [
            {
                "weakness": reason.weakness.value,
                "level": reason.level.value,
                "explanation": reason.explanation,
            }
            for reason in assessment.reasons
        ],
    }


def _recommendation(recommendation: Recommendation) -> dict[str, Any]:
    return {
        "ambiguous": recommendation.ambiguous,
        "hybrid_advised": recommendation.hybrid_advised,
        "rationale": recommendation.rationale,
        "primary": recommendation.primary.name if recommendation.primary else None,
        "mechanisms": [
            {
                "name": mechanism.name,
                "family": mechanism.family,
                "purpose": mechanism.purpose.value,
                "standard": mechanism.standard,
                "standard_status": mechanism.standard_status.value,
                "nist_quantum_security_level": mechanism.nist_quantum_security_level,
                "rationale": mechanism.rationale,
            }
            for mechanism in recommendation.mechanisms
        ],
        "details": dict(recommendation.details),
    }


def _asset(result: ScanResult, asset: CryptoAsset) -> dict[str, Any]:
    findings = {finding.finding_id: finding for finding in result.findings}
    return {
        "id": asset.asset_id,
        "asset_type": asset.asset_type.value,
        "algorithm": asset.algorithm,
        "primitive": asset.primitive.value,
        "purpose": asset.purpose.value,
        "mode": asset.mode.value,
        "padding": asset.padding.value,
        "parameter_set": asset.parameter_set,
        "curve": asset.curve,
        "key_size": asset.key_size,
        "oid": asset.oid,
        "status": asset.status.value,
        "migration_status": asset.migration_status(findings).value,
        "crypto_functions": [function.value for function in asset.crypto_functions],
        "classical_security_level": asset.classical_security_level,
        "nist_quantum_security_level": asset.nist_quantum_security_level,
        "confidence": asset.confidence,
        "risk": asset.risk(result.assessments).value,
        "priority": asset.priority(result.assessments).value,
        "details": asset.details,
        "occurrences": [
            {
                "file": occurrence.file,
                "line": occurrence.line,
                "evidence": occurrence.evidence,
                "confidence": occurrence.confidence,
                "detector": occurrence.detector,
                "finding_id": occurrence.finding_id,
            }
            for occurrence in asset.occurrences
        ],
    }
