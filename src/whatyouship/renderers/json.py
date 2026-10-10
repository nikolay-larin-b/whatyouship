# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Render versioned structured release reports as JSON."""

import json
from typing import Any

from whatyouship import __version__
from whatyouship.model import AppBundleMetadata, ArtifactFile, Finding, ReleaseArtifact
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
            "minimum_os_version": binary.minimum_os_version,
            "dependencies": [
                {"path": dependency.path, "required": dependency.required}
                for dependency in binary.dependencies
            ],
            "runtime_search_paths": list(binary.runtime_search_paths),
            "signature": None if signature is None else {
                "present": signature.present,
                "valid": signature.valid,
                "trusted": signature.trusted,
                "signer": signature.signer,
                "timestamp": signature.timestamp,
                "team_id": signature.team_id,
                "type": signature.signature_type,
                "hardened_runtime": signature.hardened_runtime,
                "entitlements": [
                    {
                        "key": entitlement.key,
                        "value": json.loads(entitlement.value),
                    }
                    for entitlement in signature.entitlements
                ],
            },
        }
    return {
        "relative_path": file.relative_path.as_posix(),
        "size_bytes": file.size_bytes,
        "sha256": file.sha256,
        "binary": binary_data,
    }


def _bundle_data(bundle: AppBundleMetadata) -> dict[str, Any]:
    """Convert application bundle metadata to JSON data.

    :param bundle: Application bundle to describe.
    :returns: JSON-compatible bundle data.
    """
    return {
        "relative_path": bundle.relative_path.as_posix(),
        "identifier": bundle.identifier,
        "name": bundle.name,
        "short_version": bundle.short_version,
        "bundle_version": bundle.bundle_version,
        "executable": bundle.executable,
        "executable_path": (
            bundle.executable_path.as_posix()
            if bundle.executable_path is not None else None
        ),
        "minimum_system_version": bundle.minimum_system_version,
        "package_type": bundle.package_type,
        "signature": {
            "status": bundle.signature.status,
            "signer": bundle.signature.signer,
            "timestamp": (
                bundle.signature.timestamp.isoformat()
                if bundle.signature.timestamp is not None else None
            ),
            "team_id": bundle.signature.team_id,
            "verification_issue": bundle.signature.verification_issue,
        },
        "issues": [
            {"identity": issue.identity, "message": issue.message}
            for issue in bundle.issues
        ],
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
            "team_id": artifact.signature.team_id,
            "notarization_ticket": artifact.signature.notarization_ticket,
            "verification_issue": artifact.signature.verification_issue,
        },
        "installation_scope": None if scope is None else {
            "kind": scope.kind,
            "conflicts": [conflict.message for conflict in scope.conflicts],
        },
        "license_agreement_present": artifact.license_agreement_present,
        "bundles": [_bundle_data(bundle) for bundle in artifact.bundles],
        "symbolic_links": [
            {
                "relative_path": link.relative_path.as_posix(),
                "target": link.target,
                "external": link.external,
            }
            for link in artifact.symbolic_links
        ],
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


def _artifact_reference_data(artifact: ReleaseArtifact) -> dict[str, Any]:
    """Serialize an artifact reference and any environment-specific limitation.

    :param artifact: Artifact referenced by a lint or compare report.
    :returns: Source path and optional signature verification issue.
    """
    data: dict[str, Any] = {"source_path": str(artifact.source_path)}
    if artifact.signature.verification_issue is not None:
        data["signature_verification_issue"] = artifact.signature.verification_issue
    return data


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
        data["artifact"] = _artifact_reference_data(report.artifact)
        data["findings"] = [_finding_data(finding) for finding in report.findings]
        if report.baseline_comparison is not None and report.baseline_artifact is not None:
            comparison = report.baseline_comparison
            data["baseline"] = {
                **_artifact_reference_data(report.baseline_artifact),
                "new": [_finding_data(finding) for finding in comparison.new],
                "existing": [_finding_data(finding) for finding in comparison.existing],
                "resolved": [_finding_data(finding) for finding in comparison.resolved],
            }
        else:
            data["baseline"] = None
    else:
        comparison = report.comparison
        data["report_type"] = "compare"
        data["old_artifact"] = _artifact_reference_data(report.old_artifact)
        data["new_artifact"] = _artifact_reference_data(report.new_artifact)
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
