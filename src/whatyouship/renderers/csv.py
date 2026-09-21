# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Render file and finding rows as CSV."""

import csv
import io
from typing import Any

from whatyouship.model import Finding
from whatyouship.report import CompareReport, InspectReport, LintReport, Report


INSPECT_COLUMNS = (
    "source_path", "relative_path", "size_bytes", "sha256", "binary_format",
    "architecture", "binary_kind", "file_version", "product_version",
    "signature_present", "signature_valid", "signature_signer", "signature_timestamp",
)
LINT_COLUMNS = ("category", "rule_id", "severity", "relative_path", "message")


def _boolean(value: bool | None) -> str:
    """Encode an optional boolean for a CSV cell.

    :param value: Boolean value or unavailable state.
    :returns: Lowercase boolean text or an empty cell.
    """
    return "" if value is None else str(value).lower()


def _write_finding(writer: Any, category: str, finding: Finding) -> None:
    """Write one finding in a stable CSV column order.

    :param writer: Standard library CSV writer.
    :param category: Current, new, existing, or resolved.
    :param finding: Finding to write.
    """
    writer.writerow((
        category, finding.rule_id, finding.severity,
        finding.relative_path.as_posix(), finding.message,
    ))


def render_csv(report: Report) -> str:
    """Render one row per artifact file or lint finding.

    :param report: Structured inspect or lint result.
    :returns: CSV text with a stable header.
    :raises ValueError: If comparison output is requested as CSV.
    """
    if isinstance(report, CompareReport):
        raise ValueError("CSV output is not supported for compare")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    if isinstance(report, InspectReport):
        writer.writerow(INSPECT_COLUMNS)
        for file in report.artifact.files:
            binary = file.binary
            signature = binary.signature if binary is not None else None
            writer.writerow((
                str(report.artifact.source_path), file.relative_path.as_posix(),
                file.size_bytes, file.sha256,
                binary.format if binary is not None else "",
                binary.architecture if binary is not None else "",
                binary.kind if binary is not None else "",
                binary.file_version if binary is not None else "",
                binary.product_version if binary is not None else "",
                _boolean(signature.present) if signature is not None else "",
                _boolean(signature.valid) if signature is not None else "",
                signature.signer if signature is not None else "",
                _boolean(signature.timestamp) if signature is not None else "",
            ))
    else:
        writer.writerow(LINT_COLUMNS)
        comparison = report.baseline_comparison
        if comparison is None:
            for finding in report.findings:
                _write_finding(writer, "current", finding)
        else:
            for category in ("new", "existing", "resolved"):
                for finding in getattr(comparison, category):
                    _write_finding(writer, category, finding)
    return stream.getvalue()
