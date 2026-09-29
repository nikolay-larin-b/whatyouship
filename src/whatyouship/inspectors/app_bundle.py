# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect macOS application bundle metadata without platform APIs."""

import plistlib
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
