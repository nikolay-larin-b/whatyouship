# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Render human-readable release reports."""

from pathlib import Path

from whatyouship.model import Finding
from whatyouship.report import CompareReport, InspectReport, LintReport, Report


def _finding_line(finding: Finding) -> str:
    """Format one lint finding.

    :param finding: Finding to display.
    :returns: Existing pipe-separated finding line.
    """
    return (
        f"{finding.rule_id} | {finding.severity} | "
        f"{finding.relative_path} | {finding.message}"
    )


def _render_compare(report: CompareReport) -> str:
    """Render comparison counts and visible differences.

    :param report: Structured comparison result.
    :returns: Human-readable comparison text.
    """
    comparison = report.comparison
    lines = [
        f"Old: {report.old_artifact.source_path}",
        f"New: {report.new_artifact.source_path}",
        f"Added: {len(comparison.added)}",
        f"Removed: {len(comparison.removed)}",
        f"Changed: {len(comparison.changed)}",
        f"Unchanged: {len(comparison.unchanged)}",
        f"Semantic differences: {len(comparison.semantic_differences)}",
    ]
    for label, paths in (
        ("Added", comparison.added),
        ("Removed", comparison.removed),
        ("Changed", comparison.changed),
    ):
        if paths:
            lines.extend(["", f"{label} files:"])
            lines.extend(f"  {path}" for path in paths)
    if comparison.semantic_differences:
        lines.extend(["", "Semantic differences:"])
        for difference in comparison.semantic_differences:
            warning = (
                " [POTENTIALLY DANGEROUS: signed -> unsigned]"
                if difference.potentially_dangerous else ""
            )
            if difference.warning_message is not None:
                warning += f" [WARNING: {difference.warning_message}]"
            location = (
                "" if difference.relative_path == Path(".")
                else f"{difference.relative_path} | "
            )
            lines.append(
                f"  {location}{difference.field}: "
                f"{difference.old_value} -> {difference.new_value}{warning}"
            )
    return "\n".join(lines) + "\n"


def _render_inspect(report: InspectReport) -> str:
    """Render artifact metadata and its files.

    :param report: Structured inspection result.
    :returns: Human-readable inspection text.
    """
    artifact = report.artifact
    lines = [
        f"Source: {artifact.source_path}",
        f"Files: {len(artifact.files)}",
        f"Total size: {sum(file.size_bytes for file in artifact.files)} bytes",
        "Artifact signature:",
        f"  Status: {artifact.signature.status}",
    ]
    if artifact.signature.signer is not None:
        lines.append(f"  Signer: {artifact.signature.signer}")
    if artifact.signature.timestamp is not None:
        lines.append(f"  Timestamp: {artifact.signature.timestamp.isoformat()}")
    if artifact.installation_scope is not None:
        lines.append(f"Installation scope: {artifact.installation_scope.kind}")
    lines.extend(["", "Relative path | Size (bytes) | SHA-256"])
    for file in artifact.files:
        lines.append(f"{file.relative_path} | {file.size_bytes} | {file.sha256}")
        if file.binary is not None:
            details = [file.binary.kind, f"Architecture: {file.binary.architecture}"]
            if file.binary.file_version is not None:
                details.append(f"File version: {file.binary.file_version}")
            if file.binary.product_version is not None:
                details.append(f"Product version: {file.binary.product_version}")
            lines.append("  Binary: " + " | ".join(details))
            if file.binary.signature is not None:
                signature = file.binary.signature
                if signature.present is None:
                    lines.append("  Signature: unknown")
                elif not signature.present:
                    lines.append("  Signature: absent")
                else:
                    validity = (
                        "unknown" if signature.valid is None else
                        "valid" if signature.valid else "invalid"
                    )
                    details = [validity]
                    if signature.signer is not None:
                        details.append(f"Signer: {signature.signer}")
                    if signature.timestamp is not None:
                        details.append(
                            f"Timestamp: {'present' if signature.timestamp else 'absent'}"
                        )
                    lines.append("  Signature: " + " | ".join(details))
    return "\n".join(lines) + "\n"


def _render_lint(report: LintReport) -> str:
    """Render findings using the existing console layout.

    :param report: Structured lint result.
    :returns: Human-readable lint text.
    """
    comparison = report.baseline_comparison
    if comparison is None:
        return ("\n".join(_finding_line(finding) for finding in report.findings) + "\n"
                if report.findings else "No findings.\n")
    lines = [
        f"New: {len(comparison.new)}",
        f"Existing: {len(comparison.existing)}",
        f"Resolved: {len(comparison.resolved)}",
    ]
    if comparison.new:
        lines.extend(["", "New findings:"])
        lines.extend(_finding_line(finding) for finding in comparison.new)
    else:
        lines.append("No new findings.")
    if comparison.resolved:
        lines.extend(["", "Resolved findings:"])
        lines.extend(_finding_line(finding) for finding in comparison.resolved)
    return "\n".join(lines) + "\n"


def render_text(report: Report) -> str:
    """Render an inspect, lint, or compare report as console text.

    :param report: Structured report to render.
    :returns: Text matching the console output format.
    """
    if isinstance(report, InspectReport):
        return _render_inspect(report)
    if isinstance(report, LintReport):
        return _render_lint(report)
    return _render_compare(report)
