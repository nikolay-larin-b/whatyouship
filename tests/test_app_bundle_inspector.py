# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for platform-independent macOS application bundle inspection."""

import os
import plistlib
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.config import LintConfiguration
from whatyouship.inspectors.app_bundle import AppBundleInspector
from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.lint import LintEngine
from whatyouship.model import (
    ArtifactFile,
    ArtifactSignature,
    ArtifactSymbolicLink,
    BinaryDependency,
    BinaryMetadata,
    SignatureMetadata,
)
from whatyouship.rules.invalid_app_bundle import InvalidAppBundleRule


def _macho_executable(
    minimum_os_version: tuple[int, int, int] | None = None,
) -> bytes:
    """Create a minimal arm64 Mach-O executable.

    :param minimum_os_version: Optional macOS deployment target.
    :returns: Serialized Mach-O header.
    """
    command = b""
    if minimum_os_version is not None:
        major, minor, patch = minimum_os_version
        encoded_version = major << 16 | minor << 8 | patch
        command = struct.pack(
            "<IIIIII",
            0x32,
            24,
            1,
            encoded_version,
            14 << 16,
            0,
        )
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        0x2,
        1 if command else 0,
        len(command),
        0,
        0,
    )
    return header + command


def _write_bundle(
    bundle: Path,
    values: dict[str, object],
    *,
    plist_format: plistlib.PlistFormat = plistlib.FMT_XML,
    executable_payload: bytes | None = None,
) -> None:
    """Create a test application bundle.

    :param bundle: Bundle directory to create.
    :param values: Information property list values.
    :param plist_format: Property list serialization format.
    :param executable_payload: Main executable bytes, or ``None`` to omit it.
    """
    contents = bundle / "Contents"
    macos = contents / "MacOS"
    macos.mkdir(parents=True)
    (contents / "Info.plist").write_bytes(
        plistlib.dumps(values, fmt=plist_format)
    )
    executable = values.get("CFBundleExecutable")
    if executable_payload is not None and isinstance(executable, str):
        (macos / executable).write_bytes(executable_payload)


class AppBundleInspectorTests(unittest.TestCase):
    """Verify bundle metadata extraction and validation."""

    def setUp(self) -> None:
        """Keep structural tests independent of the host ``codesign`` tool."""
        patcher = patch(
            "whatyouship.inspectors.app_bundle.AppSignatureInspector.inspect",
            return_value=ArtifactSignature(status="unsupported"),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_reads_xml_and_binary_information_property_lists(self) -> None:
        """Read common bundle metadata from both plist encodings."""
        values = {
            "CFBundleIdentifier": "com.example.sample",
            "CFBundleDisplayName": "Sample Application",
            "CFBundleName": "Fallback Name",
            "CFBundleShortVersionString": "2.4.1",
            "CFBundleVersion": "307",
            "CFBundleExecutable": "sample",
            "LSMinimumSystemVersion": "13.0",
            "CFBundlePackageType": "APPL",
        }
        for plist_format in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            with self.subTest(plist_format=plist_format):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    root = Path(temporary_directory)
                    _write_bundle(
                        root / "Sample.app",
                        values,
                        plist_format=plist_format,
                        executable_payload=_macho_executable(),
                    )

                    artifact = DirectoryInspector().inspect(root)

                self.assertEqual(len(artifact.bundles), 1)
                bundle = artifact.bundles[0]
                self.assertEqual(bundle.relative_path, Path("Sample.app"))
                self.assertEqual(bundle.identifier, "com.example.sample")
                self.assertEqual(bundle.name, "Sample Application")
                self.assertEqual(bundle.short_version, "2.4.1")
                self.assertEqual(bundle.bundle_version, "307")
                self.assertEqual(bundle.executable, "sample")
                self.assertEqual(
                    bundle.executable_path,
                    Path("Sample.app/Contents/MacOS/sample"),
                )
                self.assertEqual(bundle.minimum_system_version, "13.0")
                self.assertEqual(bundle.package_type, "APPL")
                self.assertEqual(bundle.issues, ())

    def test_inspects_a_bundle_used_as_the_artifact_root(self) -> None:
        """Represent the root application bundle with the artifact path ``.``."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            bundle_path = Path(temporary_directory) / "Root.app"
            _write_bundle(
                bundle_path,
                {
                    "CFBundleIdentifier": "com.example.root",
                    "CFBundleExecutable": "root",
                    "CFBundlePackageType": "APPL",
                },
                executable_payload=_macho_executable(),
            )

            artifact = DirectoryInspector().inspect(bundle_path)

        self.assertEqual(artifact.bundles[0].relative_path, Path("."))
        self.assertEqual(
            artifact.bundles[0].executable_path,
            Path("Contents/MacOS/root"),
        )

    def test_reports_missing_and_unreadable_information_property_lists(self) -> None:
        """Keep malformed bundles visible with stable issue identities."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "Missing.app").mkdir()
            broken = root / "Broken.app" / "Contents"
            broken.mkdir(parents=True)
            (broken / "Info.plist").write_bytes(b"not a property list")

            artifact = DirectoryInspector().inspect(root)

        self.assertEqual(
            [bundle.relative_path for bundle in artifact.bundles],
            [Path("Broken.app"), Path("Missing.app")],
        )
        self.assertEqual(
            [bundle.issues[0].identity for bundle in artifact.bundles],
            ["invalid-info-plist", "missing-info-plist"],
        )

    def test_validates_required_metadata_and_main_executable(self) -> None:
        """Report invalid keys, package type, path names, and binary format."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write_bundle(
                root / "EmptyMetadata.app",
                {},
            )
            _write_bundle(
                root / "Invalid.app",
                {
                    "CFBundleIdentifier": 42,
                    "CFBundleExecutable": "folder\\program",
                    "CFBundlePackageType": "BNDL",
                },
            )
            _write_bundle(
                root / "MissingExecutable.app",
                {
                    "CFBundleIdentifier": "com.example.missing",
                    "CFBundleExecutable": "program",
                    "CFBundlePackageType": "APPL",
                },
            )
            _write_bundle(
                root / "Text.app",
                {
                    "CFBundleIdentifier": "com.example.text",
                    "CFBundleExecutable": "program",
                    "CFBundlePackageType": "APPL",
                },
                executable_payload=b"plain text",
            )
            _write_bundle(
                root / "TargetMismatch.app",
                {
                    "CFBundleIdentifier": "com.example.target-mismatch",
                    "CFBundleExecutable": "program",
                    "CFBundlePackageType": "APPL",
                    "LSMinimumSystemVersion": "13.5",
                },
                executable_payload=_macho_executable((14, 2, 0)),
            )

            artifact = DirectoryInspector().inspect(root)

        issues = {
            bundle.relative_path: {issue.identity for issue in bundle.issues}
            for bundle in artifact.bundles
        }
        self.assertEqual(
            issues[Path("EmptyMetadata.app")],
            {"missing-bundle-identifier", "missing-executable-name"},
        )
        self.assertEqual(
            issues[Path("Invalid.app")],
            {
                "invalid-info-key:CFBundleIdentifier",
                "invalid-executable-name",
                "unexpected-package-type",
            },
        )
        self.assertEqual(
            issues[Path("MissingExecutable.app")],
            {"missing-executable"},
        )
        self.assertEqual(issues[Path("Text.app")], {"non-macho-executable"})
        self.assertEqual(
            issues[Path("TargetMismatch.app")],
            {"minimum-system-version-mismatch"},
        )

    @unittest.skipUnless(os.name == "posix", "requires POSIX file modes")
    def test_reports_main_executable_without_execute_permission(self) -> None:
        """Reject a main executable with no execute bit when modes are native."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            bundle = root / "Sample.app"
            _write_bundle(
                bundle,
                {
                    "CFBundleIdentifier": "com.example.sample",
                    "CFBundleExecutable": "sample",
                    "CFBundlePackageType": "APPL",
                },
                executable_payload=_macho_executable(),
            )
            executable = bundle / "Contents" / "MacOS" / "sample"
            executable.chmod(0o644)

            unchecked = DirectoryInspector().inspect(root)
            checked = DirectoryInspector().inspect(
                root,
                validate_executable_permissions=True,
            )
            executable.chmod(0o755)
            executable_checked = DirectoryInspector().inspect(
                root,
                validate_executable_permissions=True,
            )

        self.assertNotIn(
            "non-executable-main-file",
            {issue.identity for issue in unchecked.bundles[0].issues},
        )
        self.assertIn(
            "non-executable-main-file",
            {issue.identity for issue in checked.bundles[0].issues},
        )
        findings = InvalidAppBundleRule().check(checked)
        self.assertEqual(
            [
                (finding.relative_path, finding.identity)
                for finding in findings
                if finding.identity == "non-executable-main-file"
            ],
            [(Path("Sample.app"), "non-executable-main-file")],
        )
        self.assertNotIn(
            "non-executable-main-file",
            {issue.identity for issue in executable_checked.bundles[0].issues},
        )

    def test_lint_rule_reports_every_bundle_issue(self) -> None:
        """Convert bundle validation issues into configurable lint findings."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "Empty.app").mkdir()
            artifact = DirectoryInspector().inspect(root)

        findings = InvalidAppBundleRule(severity="warning").check(artifact)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "invalid-app-bundle")
        self.assertEqual(findings[0].severity, "warning")
        self.assertEqual(findings[0].relative_path, Path("Empty.app"))
        self.assertEqual(findings[0].identity, "missing-info-plist")

        default_findings = LintEngine(LintConfiguration().rules()).run(artifact)
        self.assertEqual(
            [(finding.rule_id, finding.severity) for finding in default_findings],
            [("invalid-app-bundle", "error")],
        )

    def test_accepts_a_bundle_target_at_or_above_the_executable_target(self) -> None:
        """Allow an application to require a newer system than its executable."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            for name, declared in (("Equal", "13.0"), ("Higher", "14.0")):
                _write_bundle(
                    root / f"{name}.app",
                    {
                        "CFBundleIdentifier": f"com.example.{name.lower()}",
                        "CFBundleExecutable": "program",
                        "CFBundlePackageType": "APPL",
                        "LSMinimumSystemVersion": declared,
                    },
                    executable_payload=_macho_executable((13, 0, 0)),
                )

            artifact = DirectoryInspector().inspect(root)

        self.assertTrue(all(not bundle.issues for bundle in artifact.bundles))

    def test_reports_only_missing_required_bundle_dependencies(self) -> None:
        """Resolve loader tokens and tolerate weak, system, and framework links."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            bundle_path = root / "Sample.app"
            _write_bundle(
                bundle_path,
                {
                    "CFBundleIdentifier": "com.example.dependencies",
                    "CFBundleExecutable": "sample",
                    "CFBundlePackageType": "APPL",
                },
                executable_payload=_macho_executable(),
            )
            main_path = Path("Sample.app/Contents/MacOS/sample")
            framework_root = Path("Sample.app/Contents/Frameworks")
            present_path = framework_root / "libPresent.dylib"
            framework_binary = (
                framework_root / "Kit.framework/Versions/A/Kit"
            )
            files = [
                ArtifactFile(
                    main_path,
                    32,
                    "a",
                    BinaryMetadata(
                        "Mach-O",
                        "arm64",
                        "executable",
                        dependencies=(
                            BinaryDependency("@rpath/libPresent.dylib"),
                            BinaryDependency("@rpath/libVersioned.1.dylib"),
                            BinaryDependency("@rpath/libMissing.dylib"),
                            BinaryDependency(
                                "@rpath/libOptional.dylib",
                                required=False,
                            ),
                            BinaryDependency("@rpath/Kit.framework/Kit"),
                            BinaryDependency("/usr/lib/libSystem.B.dylib"),
                            BinaryDependency("/Library/Frameworks/Host.framework/Host"),
                        ),
                        runtime_search_paths=(
                            "@executable_path/../Frameworks",
                        ),
                    ),
                ),
                ArtifactFile(
                    present_path,
                    32,
                    "b",
                    BinaryMetadata(
                        "Mach-O",
                        "arm64",
                        "library",
                        dependencies=(
                            BinaryDependency("@loader_path/libAdjacent.dylib"),
                        ),
                    ),
                ),
                ArtifactFile(
                    framework_root / "libVersioned.2023.09.1.dylib",
                    32,
                    "d",
                    BinaryMetadata("Mach-O", "arm64", "library"),
                ),
                ArtifactFile(
                    framework_binary,
                    32,
                    "c",
                    BinaryMetadata("Mach-O", "arm64", "library"),
                ),
            ]

            bundles = AppBundleInspector().inspect(
                root,
                files,
                [
                    ArtifactSymbolicLink(
                        framework_root / "libVersioned.1.dylib",
                        "libVersioned.2023.09.1.dylib",
                    ),
                ],
            )

        dependency_issues = [
            issue
            for issue in bundles[0].issues
            if issue.identity.startswith("missing-dynamic-dependency:")
        ]
        self.assertEqual(
            [issue.identity for issue in dependency_issues],
            [
                "missing-dynamic-dependency:Sample.app/Contents/Frameworks/"
                "libPresent.dylib:@loader_path/libAdjacent.dylib",
                "missing-dynamic-dependency:Sample.app/Contents/MacOS/"
                "sample:@rpath/libMissing.dylib",
            ],
        )

    def test_reports_nested_code_signed_by_a_different_team(self) -> None:
        """Compare directly owned Mach-O Team IDs with the bundle identity."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write_bundle(
                root / "Sample.app",
                {
                    "CFBundleIdentifier": "com.example.sample",
                    "CFBundleExecutable": "sample",
                    "CFBundlePackageType": "APPL",
                },
                executable_payload=_macho_executable(),
            )
            files = [
                ArtifactFile(
                    Path("Sample.app/Contents/MacOS/sample"),
                    32,
                    "a",
                    BinaryMetadata(
                        "Mach-O",
                        "arm64",
                        "executable",
                        signature=SignatureMetadata(
                            True,
                            valid=True,
                            team_id="TEAM123456",
                        ),
                    ),
                ),
                ArtifactFile(
                    Path("Sample.app/Contents/Frameworks/libOther.dylib"),
                    32,
                    "b",
                    BinaryMetadata(
                        "Mach-O",
                        "arm64",
                        "library",
                        signature=SignatureMetadata(
                            True,
                            valid=True,
                            team_id="OTHER98765",
                        ),
                    ),
                ),
            ]

            with patch(
                "whatyouship.inspectors.app_bundle.AppSignatureInspector.inspect",
                return_value=ArtifactSignature(
                    status="valid",
                    team_id="TEAM123456",
                ),
            ):
                bundles = AppBundleInspector().inspect(root, files)

        self.assertEqual(
            [
                issue.identity
                for issue in bundles[0].issues
                if issue.identity.startswith("nested-code-team-mismatch:")
            ],
            [
                "nested-code-team-mismatch:Sample.app/Contents/Frameworks/"
                "libOther.dylib"
            ],
        )


if __name__ == "__main__":
    unittest.main()
