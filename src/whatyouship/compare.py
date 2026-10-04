# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Compare release artifact contents and semantic metadata."""

import re
from dataclasses import dataclass, field
from pathlib import Path

from whatyouship.model import AppBundleMetadata, BinaryMetadata, ReleaseArtifact, Severity


_VERSION_PATTERN = re.compile(r"\s*\d+(?:\s*[.,]\s*\d+)*\s*[.,]?\s*", re.ASCII)


@dataclass
class SemanticDifference:
    """Describe an artifact or binary metadata change.

    :param relative_path: Shared file path, or ``.`` for the artifact itself.
    :param field: Name of the changed metadata field.
    :param old_value: Earlier value formatted for display.
    :param new_value: Later value formatted for display.
    :param potentially_dangerous: Whether the change is signed to unsigned.
    :param severity: Severity of a semantic regression, when applicable.
    :param warning_message: Explanation of a semantic regression, when applicable.
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
    :param semantic_differences: Artifact and binary metadata changes.
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
    if signature.valid is True and signature.trusted is False:
        return "signed (valid, untrusted)"
    if signature.valid is True:
        return "signed (valid)"
    if signature.valid is False:
        return "signed (invalid)"
    return "signed (verification unknown)"


def _dependency_state(binary: BinaryMetadata) -> str:
    """Format dynamic dependencies for semantic comparison.

    :param binary: Binary metadata to describe.
    :returns: Comma-separated dependency paths and weak markers.
    """
    return ", ".join(
        dependency.path + (" (weak)" if not dependency.required else "")
        for dependency in binary.dependencies
    ) or "none"


def _runtime_search_path_state(binary: BinaryMetadata) -> str:
    """Format runtime search paths for semantic comparison.

    :param binary: Binary metadata to describe.
    :returns: Comma-separated paths, or ``none``.
    """
    return ", ".join(binary.runtime_search_paths) or "none"


def _hardened_runtime_state(binary: BinaryMetadata) -> str:
    """Describe the Hardened Runtime state of a binary.

    :param binary: Binary metadata to examine.
    :returns: Enabled, disabled, or unknown state.
    """
    signature = binary.signature
    if signature is None or signature.hardened_runtime is None:
        return "unknown"
    return "enabled" if signature.hardened_runtime else "disabled"


def _entitlement_state(binary: BinaryMetadata) -> str:
    """Format embedded entitlements for semantic comparison.

    :param binary: Binary metadata to describe.
    :returns: Comma-separated entitlement assignments, or ``none``.
    """
    signature = binary.signature
    if signature is None:
        return "none"
    return ", ".join(
        f"{entitlement.key}={entitlement.value}"
        for entitlement in signature.entitlements
    ) or "none"


def _version_components(value: str) -> tuple[int, ...] | None:
    """Parse an unambiguous dotted or comma-separated numeric version.

    :param value: Embedded version string.
    :returns: Numeric components, or ``None`` if the value is ambiguous.
    """
    if _VERSION_PATTERN.fullmatch(value) is None:
        return None
    normalized = value.strip().rstrip(".,").strip()
    return tuple(int(component.strip()) for component in re.split(r"[.,]", normalized))


def _compare_numeric_versions(old: str, new: str) -> int | None:
    """Compare two unambiguous numeric versions.

    :param old: Earlier version metadata.
    :param new: Later version metadata.
    :returns: A negative, zero, or positive value when the new version is lower,
        equal, or higher, or ``None`` when either value is ambiguous.
    """
    old_components = _version_components(old)
    new_components = _version_components(new)
    if old_components is None or new_components is None:
        return None
    width = max(len(old_components), len(new_components))
    padded_old = old_components + (0,) * (width - len(old_components))
    padded_new = new_components + (0,) * (width - len(new_components))
    return (padded_new > padded_old) - (padded_new < padded_old)


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
    if _compare_numeric_versions(old, new) == -1:
        return "version downgrade"
    return None


def _minimum_os_warning(old: str | None, new: str | None) -> str | None:
    """Identify a numerically higher minimum operating system version.

    :param old: Earlier minimum operating system version.
    :param new: Later minimum operating system version.
    :returns: Compatibility warning, or ``None`` when no increase is known.
    """
    if old is None or new is None:
        return None
    if _compare_numeric_versions(old, new) == 1:
        return "minimum OS version increased"
    return None


def _binary_differences(
    path: Path, old: BinaryMetadata, new: BinaryMetadata
) -> list[SemanticDifference]:
    """Find requested binary metadata changes between two files.

    :param path: Shared relative path.
    :param old: Earlier binary metadata.
    :param new: Later binary metadata.
    :returns: Differences in a stable field order.
    """
    differences = []
    fields = (
        ("Architecture", old.architecture, new.architecture),
        ("File version", old.file_version, new.file_version),
        ("Product version", old.product_version, new.product_version),
        (
            "Minimum OS version",
            old.minimum_os_version,
            new.minimum_os_version,
        ),
        ("Dynamic dependencies", _dependency_state(old), _dependency_state(new)),
        (
            "Runtime search paths",
            _runtime_search_path_state(old),
            _runtime_search_path_state(new),
        ),
        (
            "Hardened Runtime",
            _hardened_runtime_state(old),
            _hardened_runtime_state(new),
        ),
        ("Entitlements", _entitlement_state(old), _entitlement_state(new)),
        ("Signature", _signature_state(old), _signature_state(new)),
        (
            "Signature type",
            old.signature.signature_type if old.signature is not None else None,
            new.signature.signature_type if new.signature is not None else None,
        ),
        (
            "Signer",
            old.signature.signer if old.signature is not None else None,
            new.signature.signer if new.signature is not None else None,
        ),
        (
            "Team ID",
            old.signature.team_id if old.signature is not None else None,
            new.signature.team_id if new.signature is not None else None,
        ),
    )
    if old.kind != new.kind and {old.kind, new.kind} == {"executable", "library"}:
        differences.append(
            SemanticDifference(
                path,
                "Type",
                old.kind,
                new.kind,
            )
        )
    for field_name, old_value, new_value in fields:
        if old_value != new_value:
            if field_name in {"File version", "Product version"}:
                warning_message = _version_warning(old_value, new_value)
            elif field_name == "Minimum OS version":
                warning_message = _minimum_os_warning(old_value, new_value)
            else:
                warning_message = None
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


def _bundle_differences(
    path: Path, old: AppBundleMetadata, new: AppBundleMetadata
) -> list[SemanticDifference]:
    """Find application bundle metadata changes.

    :param path: Shared application bundle path.
    :param old: Earlier bundle metadata.
    :param new: Later bundle metadata.
    :returns: Differences in a stable field order.
    """
    differences = []
    fields = (
        ("Bundle identifier", old.identifier, new.identifier),
        ("Bundle name", old.name, new.name),
        ("Bundle version", old.short_version, new.short_version),
        ("Bundle build version", old.bundle_version, new.bundle_version),
        ("Bundle executable", old.executable, new.executable),
        (
            "Minimum system version",
            old.minimum_system_version,
            new.minimum_system_version,
        ),
        ("Bundle package type", old.package_type, new.package_type),
    )
    for field_name, old_value, new_value in fields:
        if old_value == new_value:
            continue
        if field_name in {"Bundle version", "Bundle build version"}:
            warning_message = _version_warning(old_value, new_value)
        elif field_name == "Minimum system version":
            warning_message = _minimum_os_warning(old_value, new_value)
        else:
            warning_message = None
        differences.append(SemanticDifference(
            path,
            field_name,
            old_value if old_value is not None else "unavailable",
            new_value if new_value is not None else "unavailable",
            severity="warning" if warning_message is not None else None,
            warning_message=warning_message,
        ))
    return differences


def _symbolic_link_state(target: str, external: bool) -> str:
    """Format a symbolic link for semantic comparison.

    :param target: Link target stored in the artifact.
    :param external: Whether the target escapes the artifact root.
    :returns: Target with its external scope when applicable.
    """
    return target + (" (external)" if external else "")


def compare_artifacts(old: ReleaseArtifact, new: ReleaseArtifact) -> ComparisonResult:
    """Compare files and available semantic metadata in two artifacts.

    :param old: Earlier release artifact.
    :param new: Later release artifact.
    :returns: Sorted path classifications and semantic differences.
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
    signature_fields = (
        ("Artifact signature", old.signature.status, new.signature.status),
        ("Artifact signer", old.signature.signer, new.signature.signer),
        ("Artifact Team ID", old.signature.team_id, new.signature.team_id),
        (
            "Stapled notarization ticket",
            old.signature.notarization_ticket,
            new.signature.notarization_ticket,
        ),
    )
    for field_name, old_value, new_value in signature_fields:
        if old_value != new_value:
            result.semantic_differences.append(SemanticDifference(
                Path("."),
                field_name,
                str(old_value) if old_value is not None else "unavailable",
                str(new_value) if new_value is not None else "unavailable",
                potentially_dangerous=(
                    field_name == "Artifact signature"
                    and old_value == "valid"
                    and new_value != "valid"
                ),
            ))
    if old.installation_scope is not None and new.installation_scope is not None:
        old_scope = old.installation_scope.kind
        new_scope = new.installation_scope.kind
        if old_scope != new_scope:
            result.semantic_differences.append(
                SemanticDifference(Path("."), "Installation scope", old_scope, new_scope)
            )
    old_bundles = {bundle.relative_path: bundle for bundle in old.bundles}
    new_bundles = {bundle.relative_path: bundle for bundle in new.bundles}
    for path in sorted(old_bundles.keys() & new_bundles.keys()):
        result.semantic_differences.extend(
            _bundle_differences(path, old_bundles[path], new_bundles[path])
        )
    old_links = {link.relative_path: link for link in old.symbolic_links}
    new_links = {link.relative_path: link for link in new.symbolic_links}
    for path in sorted(old_links.keys() | new_links.keys()):
        earlier = old_links.get(path)
        later = new_links.get(path)
        old_state = (
            "unavailable"
            if earlier is None
            else _symbolic_link_state(earlier.target, earlier.external)
        )
        new_state = (
            "unavailable"
            if later is None
            else _symbolic_link_state(later.target, later.external)
        )
        if old_state != new_state:
            result.semantic_differences.append(
                SemanticDifference(path, "Symbolic link", old_state, new_state)
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
            and earlier.binary.format == later.binary.format
        ):
            result.semantic_differences.extend(
                _binary_differences(path, earlier.binary, later.binary)
            )
    return result
