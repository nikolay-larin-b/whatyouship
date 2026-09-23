# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Render versioned structured release reports as JSON."""

import json
from typing import Any

from whatyouship import __version__
from whatyouship.model import ArtifactFile, Finding, ReleaseArtifact
from whatyouship.report import CompareReport, InspectReport, LintReport, Report


SCHEMA_VERSION = 1


def _file_data(file: ArtifactFile) -> dict[str, Any]:
    """Convert every available file and binary metadata field to JSON data.

    :param file: Artifact file to describe.
    :returns: JSON-compatible file data.
    """
    binary = file.binary
    binary_data = None
    if binary is not None:
        signature = binary.signature
        binary_data = {
            "format": binary.format,
            "architecture": binary.architecture,
            "kind": binary.kind,
            "file_version": binary.file_version,
            "product_version": binary.product_version,
            "signature": None if signature is None else {
                "present": signature.present,
                "valid": signature.valid,
                "signer": signature.signer,
                "timestamp": signature.timestamp,
            },
        }
    return {
        "relative_path": file.relative_path.as_posix(),
        "size_bytes": file.size_bytes,
        "sha256": file.sha256,
        "binary": binary_data,
    }


def _artifact_data(artifact: ReleaseArtifact) -> dict[str, Any]:
    """Convert complete available artifact metadata to JSON data.

    :param artifact: Release artifact to describe.
    :returns: JSON-compatible artifact data.
    """
    scope = artifact.installation_scope
    return {
        "source_path": str(artifact.source_path),
        "file_count": len(artifact.files),
        "total_size_bytes": sum(file.size_bytes for file in artifact.files),
        "signature": {
            "status": artifact.signature.status,
            "signer": artifact.signature.signer,
            "timestamp": (
                artifact.signature.timestamp.isoformat()
                if artifact.signature.timestamp is not None else None
            ),
        },
        "installation_scope": None if scope is None else {
            "kind": scope.kind,
            "conflicts": [conflict.message for conflict in scope.conflicts],
        },
        "files": [_file_data(file) for file in artifact.files],
    }


def _finding_data(finding: Finding) -> dict[str, Any]:
    """Convert a lint finding to JSON data.

    :param finding: Finding to describe.
    :returns: JSON-compatible finding data.
    """
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity,
        "relative_path": finding.relative_path.as_posix(),
        "message": finding.message,
    }


def render_json(report: Report) -> str:
    """Render a complete versioned JSON report.

    :param report: Structured inspect, lint, or compare result.
    :returns: Indented JSON with a stable schema version.
    """
    data: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool_version": __version__,
    }
    if isinstance(report, InspectReport):
        data["report_type"] = "inspect"
        data["artifact"] = _artifact_data(report.artifact)
    elif isinstance(report, LintReport):
        data["report_type"] = "lint"
        data["artifact"] = {"source_path": str(report.artifact.source_path)}
        data["findings"] = [_finding_data(finding) for finding in report.findings]
        if report.baseline_comparison is not None and report.baseline_artifact is not None:
            comparison = report.baseline_comparison
            data["baseline"] = {
                "source_path": str(report.baseline_artifact.source_path),
                "new": [_finding_data(finding) for finding in comparison.new],
                "existing": [_finding_data(finding) for finding in comparison.existing],
                "resolved": [_finding_data(finding) for finding in comparison.resolved],
            }
        else:
            data["baseline"] = None
    else:
        comparison = report.comparison
        data["report_type"] = "compare"
        data["old_artifact"] = {"source_path": str(report.old_artifact.source_path)}
        data["new_artifact"] = {"source_path": str(report.new_artifact.source_path)}
        for category in ("added", "removed", "changed", "unchanged"):
            data[category] = [path.as_posix() for path in getattr(comparison, category)]
        data["semantic_differences"] = [
            {
                "relative_path": difference.relative_path.as_posix(),
                "field": difference.field,
                "old_value": difference.old_value,
                "new_value": difference.new_value,
                "potentially_dangerous": difference.potentially_dangerous,
                "severity": difference.severity,
                "warning_message": difference.warning_message,
            }
            for difference in comparison.semantic_differences
        ]
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"
