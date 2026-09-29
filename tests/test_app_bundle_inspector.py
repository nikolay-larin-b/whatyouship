# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for platform-independent macOS application bundle inspection."""

import plistlib
import struct
import tempfile
import unittest
from pathlib import Path

from whatyouship.config import LintConfiguration
from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.lint import LintEngine
from whatyouship.rules.invalid_app_bundle import InvalidAppBundleRule


def _macho_executable() -> bytes:
    """Create a minimal arm64 Mach-O executable.

    :returns: Serialized Mach-O header.
    """
    return struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        0x0100000C,
        0,
        0x2,
        0,
        0,
        0,
        0,
    )


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


if __name__ == "__main__":
    unittest.main()
