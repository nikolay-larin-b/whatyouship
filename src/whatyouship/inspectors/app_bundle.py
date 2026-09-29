# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect macOS application bundle metadata without platform APIs."""

import plistlib
import posixpath
import re
from pathlib import Path

from whatyouship.model import AppBundleMetadata, ArtifactFile, BundleIssue


_STRING_KEYS = (
    "CFBundleIdentifier",
    "CFBundleDisplayName",
    "CFBundleName",
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "CFBundleExecutable",
    "LSMinimumSystemVersion",
    "CFBundlePackageType",
)

_VERSION_PATTERN = re.compile(r"\d+(?:\.\d+)*", re.ASCII)
_SYSTEM_LIBRARY_PREFIXES = ("/System/Library/", "/usr/lib/")


def _version_components(value: str) -> tuple[int, ...] | None:
    """Parse a dotted numeric version for semantic comparison.

    :param value: Version string to parse.
    :returns: Numeric components, or ``None`` for another version syntax.
    """
    if _VERSION_PATTERN.fullmatch(value) is None:
        return None
    return tuple(int(component) for component in value.split("."))


def _version_is_lower(declared: str, required: str) -> bool:
    """Check whether a declared deployment target is below a requirement.

    :param declared: Version declared by the application bundle.
    :param required: Version required by the main executable.
    :returns: Whether both versions are numeric and the declaration is lower.
    """
    declared_components = _version_components(declared)
    required_components = _version_components(required)
    if declared_components is None or required_components is None:
        return False
    width = max(len(declared_components), len(required_components))
    return declared_components + (0,) * (
        width - len(declared_components)
    ) < required_components + (0,) * (width - len(required_components))


def _joined_artifact_path(base: Path, suffix: str) -> Path | None:
    """Join and normalize a Mach-O path within an artifact tree.

    :param base: Artifact-relative directory used as the path origin.
    :param suffix: POSIX path suffix from a load command.
    :returns: Normalized artifact path, or ``None`` when it escapes the tree.
    """
    normalized = posixpath.normpath(f"{base.as_posix()}/{suffix}")
    if (
        posixpath.isabs(normalized)
        or normalized == ".."
        or normalized.startswith("../")
    ):
        return None
    return Path(*normalized.split("/"))


def _expand_runtime_path(
    value: str, loader_directory: Path, executable_directory: Path
) -> Path | None:
    """Expand a loader- or executable-relative Mach-O path.

    :param value: Dependency or runtime search path.
    :param loader_directory: Directory containing the current Mach-O file.
    :param executable_directory: Directory containing the app's main executable.
    :returns: Artifact-relative path, or ``None`` when it cannot be expanded.
    """
    for marker, base in (
        ("@loader_path", loader_directory),
        ("@executable_path", executable_directory),
    ):
        if value == marker:
            return base
        prefix = f"{marker}/"
        if value.startswith(prefix):
            return _joined_artifact_path(base, value[len(prefix):])
    return None


def _inside_bundle(path: Path, bundle: Path) -> bool:
    """Check whether an artifact path belongs to a bundle tree.

    :param path: Artifact-relative path.
    :param bundle: Artifact-relative bundle path, or ``.`` for the root.
    :returns: Whether ``path`` is inside ``bundle``.
    """
    if bundle == Path("."):
        return True
    try:
        path.relative_to(bundle)
    except ValueError:
        return False
    return True


def _owned_by_bundle(path: Path, bundle: Path) -> bool:
    """Exclude files owned by application bundles nested below a bundle.

    :param path: Artifact-relative file path.
    :param bundle: Artifact-relative bundle path, or ``.`` for the root.
    :returns: Whether the file belongs directly to this bundle.
    """
    if not _inside_bundle(path, bundle):
        return False
    relative = path if bundle == Path(".") else path.relative_to(bundle)
    return not any(part.lower().endswith(".app") for part in relative.parts[:-1])


def _dependency_exists(candidate: Path, files: set[Path]) -> bool:
    """Check a dependency path, including omitted framework symlinks.

    :param candidate: Resolved artifact-relative dependency path.
    :param files: Regular files represented by the artifact backend.
    :returns: Whether the dependency target is represented by a regular file.
    """
    if candidate in files:
        return True
    parts = candidate.parts
    for index, part in enumerate(parts):
        if not part.lower().endswith(".framework"):
            continue
        framework_name = part[:-len(".framework")]
        tail = parts[index + 1:]
        if tail not in {(framework_name,), ("Versions", "Current", framework_name)}:
            return False
        prefix = parts[:index + 1]
        return any(
            path.parts[:index + 1] == prefix
            and len(path.parts) == index + 4
            and path.parts[index + 1] == "Versions"
            and path.parts[index + 3] == framework_name
            for path in files
        )
    return False


def _dependency_candidates(
    dependency: str,
    binary_path: Path,
    executable_path: Path,
    runtime_search_directories: tuple[Path, ...],
) -> tuple[Path, ...]:
    """Resolve bundle-relative candidates for one Mach-O dependency.

    :param dependency: Dynamic library install name.
    :param binary_path: Artifact path of the importing Mach-O file.
    :param executable_path: Artifact path of the app's main executable.
    :param runtime_search_directories: Expanded bundle search directories.
    :returns: Unique artifact-relative candidate paths.
    """
    loader_directory = binary_path.parent
    executable_directory = executable_path.parent
    direct = _expand_runtime_path(
        dependency, loader_directory, executable_directory
    )
    if direct is not None:
        return (direct,)
    rpath_prefix = "@rpath/"
    if not dependency.startswith(rpath_prefix):
        return ()
    suffix = dependency[len(rpath_prefix):]
    candidates = []
    for directory in runtime_search_directories:
        candidate = _joined_artifact_path(directory, suffix)
        if candidate is not None:
            candidates.append(candidate)
    return tuple(dict.fromkeys(candidates))


def _dynamic_dependency_issues(
    bundle: Path,
    executable_path: Path,
    files_by_path: dict[Path, ArtifactFile],
) -> list[BundleIssue]:
    """Find required bundle-relative Mach-O dependencies that are absent.

    :param bundle: Artifact-relative application bundle path.
    :param executable_path: Artifact path of the app's main executable.
    :param files_by_path: Analyzed files keyed by artifact-relative path.
    :returns: Missing dependency issues in stable path and name order.
    """
    executable_file = files_by_path[executable_path]
    if executable_file.binary is None:
        return []
    represented_files = set(files_by_path)
    runtime_search_directories = []
    for owner_path, artifact_file in sorted(files_by_path.items()):
        binary = artifact_file.binary
        if (
            not _owned_by_bundle(owner_path, bundle)
            or binary is None
            or binary.format != "Mach-O"
        ):
            continue
        for runtime_path in binary.runtime_search_paths:
            expanded = _expand_runtime_path(
                runtime_path,
                owner_path.parent,
                executable_path.parent,
            )
            if expanded is not None and _inside_bundle(expanded, bundle):
                runtime_search_directories.append(expanded)
    search_directories = tuple(dict.fromkeys(runtime_search_directories))
    issues = []
    for binary_path, artifact_file in sorted(files_by_path.items()):
        binary = artifact_file.binary
        if (
            not _owned_by_bundle(binary_path, bundle)
            or binary is None
            or binary.format != "Mach-O"
        ):
            continue
        for dependency in binary.dependencies:
            if (
                not dependency.required
                or dependency.path.startswith(_SYSTEM_LIBRARY_PREFIXES)
            ):
                continue
            candidates = tuple(
                candidate
                for candidate in _dependency_candidates(
                    dependency.path,
                    binary_path,
                    executable_path,
                    search_directories,
                )
                if _inside_bundle(candidate, bundle)
            )
            if not candidates or any(
                _dependency_exists(candidate, represented_files)
                for candidate in candidates
            ):
                continue
            issues.append(BundleIssue(
                f"missing-dynamic-dependency:{binary_path.as_posix()}:"
                f"{dependency.path}",
                f"Mach-O file '{binary_path.as_posix()}' requires missing "
                f"bundled library '{dependency.path}'.",
            ))
    return issues


def _string_value(
    values: dict[str, object], key: str, issues: list[BundleIssue]
) -> str | None:
    """Read one optional non-empty string from an information property list.

    :param values: Parsed ``Info.plist`` dictionary.
    :param key: Property list key to read.
    :param issues: Mutable issue collection for invalid values.
    :returns: String value, or ``None`` when absent or invalid.
    """
    value = values.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        issues.append(BundleIssue(
            f"invalid-info-key:{key}",
            f"Info.plist key '{key}' must be a non-empty string.",
        ))
        return None
    return value


class AppBundleInspector:
    """Find and inspect ``.app`` bundles in an artifact directory tree."""

    def inspect(
        self, directory: Path, files: list[ArtifactFile]
    ) -> list[AppBundleMetadata]:
        """Read application bundle metadata and validate the main executable.

        :param directory: Artifact tree root.
        :param files: Files already analyzed relative to ``directory``.
        :returns: Application bundles ordered by relative path.
        """
        files_by_path = {file.relative_path: file for file in files}
        candidates = [
            path
            for path in (directory, *directory.rglob("*"))
            if path.is_dir()
            and not path.is_symlink()
            and path.suffix.lower() == ".app"
        ]
        return [
            self._inspect_bundle(directory, bundle, files_by_path)
            for bundle in sorted(candidates)
        ]

    def _inspect_bundle(
        self,
        directory: Path,
        bundle: Path,
        files_by_path: dict[Path, ArtifactFile],
    ) -> AppBundleMetadata:
        """Inspect one application bundle.

        :param directory: Artifact tree root.
        :param bundle: Application bundle directory.
        :param files_by_path: Analyzed files keyed by artifact-relative path.
        :returns: Parsed metadata and structural issues.
        """
        relative_path = bundle.relative_to(directory)
        if relative_path.parts == ():
            relative_path = Path(".")
        issues: list[BundleIssue] = []
        info_path = bundle / "Contents" / "Info.plist"
        if not info_path.is_file() or info_path.is_symlink():
            issues.append(BundleIssue(
                "missing-info-plist",
                "Application bundle has no regular Contents/Info.plist file.",
            ))
            return AppBundleMetadata(relative_path, issues=tuple(issues))

        try:
            values = plistlib.loads(info_path.read_bytes())
        except (OSError, ValueError, TypeError, OverflowError) as error:
            issues.append(BundleIssue(
                "invalid-info-plist",
                f"Unable to parse Contents/Info.plist: {error}",
            ))
            return AppBundleMetadata(relative_path, issues=tuple(issues))
        if not isinstance(values, dict):
            issues.append(BundleIssue(
                "invalid-info-plist-root",
                "Contents/Info.plist must contain a dictionary.",
            ))
            return AppBundleMetadata(relative_path, issues=tuple(issues))

        strings = {
            key: _string_value(values, key, issues) for key in _STRING_KEYS
        }
        identifier = strings["CFBundleIdentifier"]
        if identifier is None and "CFBundleIdentifier" not in values:
            issues.append(BundleIssue(
                "missing-bundle-identifier",
                "Info.plist has no CFBundleIdentifier.",
            ))
        executable = strings["CFBundleExecutable"]
        executable_path: Path | None = None
        executable_file: ArtifactFile | None = None
        if executable is None:
            if "CFBundleExecutable" not in values:
                issues.append(BundleIssue(
                    "missing-executable-name",
                    "Info.plist has no CFBundleExecutable.",
                ))
        elif executable in {".", ".."} or any(
            separator in executable for separator in "/\\"
        ):
            issues.append(BundleIssue(
                "invalid-executable-name",
                "CFBundleExecutable must be a file name without path components.",
            ))
        else:
            executable_path = (
                relative_path / "Contents" / "MacOS" / executable
                if relative_path != Path(".")
                else Path("Contents") / "MacOS" / executable
            )
            executable_file = files_by_path.get(executable_path)
            if executable_file is None:
                issues.append(BundleIssue(
                    "missing-executable",
                    f"Main executable is missing: {executable_path.as_posix()}.",
                ))
            elif (
                executable_file.binary is None
                or executable_file.binary.format != "Mach-O"
            ):
                issues.append(BundleIssue(
                    "non-macho-executable",
                    f"Main executable is not a Mach-O binary: "
                    f"{executable_path.as_posix()}.",
                ))
            elif (
                strings["LSMinimumSystemVersion"] is not None
                and executable_file.binary.minimum_os_version is not None
                and _version_is_lower(
                    strings["LSMinimumSystemVersion"],
                    executable_file.binary.minimum_os_version,
                )
            ):
                declared_version = strings["LSMinimumSystemVersion"]
                required_version = executable_file.binary.minimum_os_version
                issues.append(BundleIssue(
                    "minimum-system-version-mismatch",
                    f"LSMinimumSystemVersion is '{declared_version}', but the "
                    f"main executable requires macOS {required_version}.",
                ))

        if (
            executable_path is not None
            and executable_file is not None
            and executable_file.binary is not None
            and executable_file.binary.format == "Mach-O"
        ):
            issues.extend(_dynamic_dependency_issues(
                relative_path,
                executable_path,
                files_by_path,
            ))

        package_type = strings["CFBundlePackageType"]
        if package_type is not None and package_type != "APPL":
            issues.append(BundleIssue(
                "unexpected-package-type",
                f"CFBundlePackageType is '{package_type}', expected 'APPL'.",
            ))

        return AppBundleMetadata(
            relative_path=relative_path,
            identifier=identifier,
            name=(strings["CFBundleDisplayName"] or strings["CFBundleName"]),
            short_version=strings["CFBundleShortVersionString"],
            bundle_version=strings["CFBundleVersion"],
            executable=executable,
            executable_path=executable_path,
            minimum_system_version=strings["LSMinimumSystemVersion"],
            package_type=package_type,
            issues=tuple(issues),
        )
