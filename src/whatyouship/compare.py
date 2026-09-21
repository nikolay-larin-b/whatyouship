# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Compare release artifact contents and PE metadata."""

import re
from dataclasses import dataclass, field
from pathlib import Path

from whatyouship.model import BinaryMetadata, ReleaseArtifact, Severity


_VERSION_PATTERN = re.compile(r"\s*\d+(?:\s*[.,]\s*\d+)*\s*[.,]?\s*", re.ASCII)


@dataclass
class SemanticDifference:
    """Describe a PE metadata change at a shared relative path.

    :param relative_path: Path of the file in both artifacts.
    :param field: Name of the changed metadata field.
    :param old_value: Earlier value formatted for display.
    :param new_value: Later value formatted for display.
    :param potentially_dangerous: Whether the change is signed to unsigned.
    :param severity: Severity of a version regression, when applicable.
    :param warning_message: Explanation of a version regression, when applicable.
    """

    relative_path: Path
    field: str
    old_value: str
    new_value: str
    potentially_dangerous: bool = False
    severity: Severity | None = None
    warning_message: str | None = None


@dataclass
class ComparisonResult:
    """Classify paths across two release artifacts.

    :param added: Paths found only in the new artifact.
    :param removed: Paths found only in the old artifact.
    :param changed: Paths with different SHA-256 digests.
    :param unchanged: Paths with matching SHA-256 digests.
    :param semantic_differences: PE metadata changes at shared paths.
    """

    added: list[Path] = field(default_factory=list)
    removed: list[Path] = field(default_factory=list)
    changed: list[Path] = field(default_factory=list)
    unchanged: list[Path] = field(default_factory=list)
    semantic_differences: list[SemanticDifference] = field(default_factory=list)


def _signature_state(binary: BinaryMetadata) -> str:
    """Describe the signature state of a binary.

    :param binary: Binary metadata to examine.
    :returns: A readable signature state.
    """
    signature = binary.signature
    if signature is None or signature.present is None:
        return "unknown"
    if not signature.present:
        return "unsigned"
    if signature.valid is True:
        return "signed (valid)"
    if signature.valid is False:
        return "signed (invalid)"
    return "signed (verification unknown)"


def _version_components(value: str) -> tuple[int, ...] | None:
    """Parse an unambiguous dotted or comma-separated numeric version.

    :param value: Embedded version string.
    :returns: Numeric components, or ``None`` if the value is ambiguous.
    """
    if _VERSION_PATTERN.fullmatch(value) is None:
        return None
    normalized = value.strip().rstrip(".,").strip()
    return tuple(int(component.strip()) for component in re.split(r"[.,]", normalized))


def _version_warning(old: str | None, new: str | None) -> str | None:
    """Identify a missing or numerically lower new version.

    :param old: Earlier version metadata.
    :param new: Later version metadata.
    :returns: Warning description, or ``None`` when no regression is known.
    """
    if old is None:
        return None
    if new is None:
        return "version metadata removed"
    old_components = _version_components(old)
    new_components = _version_components(new)
    if old_components is None or new_components is None:
        return None
    width = max(len(old_components), len(new_components))
    if new_components + (0,) * (width - len(new_components)) < old_components + (0,) * (
        width - len(old_components)
    ):
        return "version downgrade"
    return None


def _pe_differences(
    path: Path, old: BinaryMetadata, new: BinaryMetadata
) -> list[SemanticDifference]:
    """Find requested PE metadata changes between two files.

    :param path: Shared relative path.
    :param old: Earlier PE metadata.
    :param new: Later PE metadata.
    :returns: Differences in a stable field order.
    """
    differences = []
    fields = (
        ("Architecture", old.architecture, new.architecture),
        ("File version", old.file_version, new.file_version),
        ("Product version", old.product_version, new.product_version),
        ("Signature", _signature_state(old), _signature_state(new)),
        (
            "Signer",
            old.signature.signer if old.signature is not None else None,
            new.signature.signer if new.signature is not None else None,
        ),
    )
    if old.kind != new.kind and {old.kind, new.kind} == {"executable", "dll"}:
        differences.append(
            SemanticDifference(
                path,
                "Type",
                "EXE" if old.kind == "executable" else "DLL",
                "EXE" if new.kind == "executable" else "DLL",
            )
        )
    for field_name, old_value, new_value in fields:
        if old_value != new_value:
            warning_message = (
                _version_warning(old_value, new_value)
                if field_name in {"File version", "Product version"}
                else None
            )
            regression = (
                field_name == "Signature"
                and old.signature is not None
                and new.signature is not None
                and old.signature.present is True
                and new.signature.present is False
            )
            differences.append(
                SemanticDifference(
                    path,
                    field_name,
                    old_value if old_value is not None else "unavailable",
                    new_value if new_value is not None else "unavailable",
                    potentially_dangerous=regression,
                    severity="warning" if warning_message is not None else None,
                    warning_message=warning_message,
                )
            )
    return differences


def compare_artifacts(old: ReleaseArtifact, new: ReleaseArtifact) -> ComparisonResult:
    """Compare files in two artifacts by relative path and SHA-256.

    :param old: Earlier release artifact.
    :param new: Later release artifact.
    :returns: Sorted path classifications and PE metadata differences.
    """
    old_files = {file.relative_path: file for file in old.files}
    new_files = {file.relative_path: file for file in new.files}
    old_paths = old_files.keys()
    new_paths = new_files.keys()
    common_paths = old_paths & new_paths
    result = ComparisonResult(
        added=sorted(new_paths - old_paths),
        removed=sorted(old_paths - new_paths),
    )
    for path in sorted(common_paths):
        earlier = old_files[path]
        later = new_files[path]
        if earlier.sha256 != later.sha256:
            result.changed.append(path)
        else:
            result.unchanged.append(path)
        if (
            earlier.binary is not None
            and later.binary is not None
            and earlier.binary.format == "PE"
            and later.binary.format == "PE"
        ):
            result.semantic_differences.extend(
                _pe_differences(path, earlier.binary, later.binary)
            )
    return result
