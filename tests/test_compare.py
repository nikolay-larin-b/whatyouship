# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for release artifact comparison."""

import unittest
from pathlib import Path

from whatyouship.compare import ComparisonResult, SemanticDifference, compare_artifacts
from whatyouship.model import (
    AppBundleMetadata,
    ArtifactFile,
    BinaryDependency,
    BinaryMetadata,
    InstallationScope,
    ReleaseArtifact,
    SignatureMetadata,
)


def _version_differences(
    old_file: str | None,
    new_file: str | None,
    old_product: str | None = None,
    new_product: str | None = None,
) -> list[SemanticDifference]:
    """Compare version metadata for one binary at a shared path.

    :param old_file: Earlier file version.
    :param new_file: Later file version.
    :param old_product: Earlier product version.
    :param new_product: Later product version.
    :returns: Semantic differences for version fields.
    """
    path = Path("app.exe")
    old = ReleaseArtifact(Path("old"), [ArtifactFile(
        path, 1, "a", BinaryMetadata(
            "PE", "x86_64", "executable", old_file, old_product,
        ),
    )])
    new = ReleaseArtifact(Path("new"), [ArtifactFile(
        path, 1, "b", BinaryMetadata(
            "PE", "x86_64", "executable", new_file, new_product,
        ),
    )])
    return compare_artifacts(old, new).semantic_differences


class CompareTests(unittest.TestCase):
    """Verify file classification by relative path and content digest."""

    def test_classifies_all_paths_in_sorted_order(self) -> None:
        """Classify added, removed, changed, and unchanged paths."""
        old = ReleaseArtifact(Path("old"), [
            ArtifactFile(Path("z-removed"), 1, "a"),
            ArtifactFile(Path("b-removed"), 1, "a"),
            ArtifactFile(Path("z-changed"), 1, "a"),
            ArtifactFile(Path("b-changed"), 1, "a"),
            ArtifactFile(Path("same"), 1, "a"),
        ])
        new = ReleaseArtifact(Path("new"), [
            ArtifactFile(Path("z-added"), 1, "a"),
            ArtifactFile(Path("b-added"), 1, "a"),
            ArtifactFile(Path("z-changed"), 1, "b"),
            ArtifactFile(Path("b-changed"), 1, "b"),
            ArtifactFile(Path("same"), 2, "a", binary=BinaryMetadata("PE", "x86_64", "library")),
        ])

        result = compare_artifacts(old, new)

        self.assertEqual(result.added, [Path("b-added"), Path("z-added")])
        self.assertEqual(result.removed, [Path("b-removed"), Path("z-removed")])
        self.assertEqual(result.changed, [Path("b-changed"), Path("z-changed")])
        self.assertEqual(result.unchanged, [Path("same")])
        self.assertEqual(result.semantic_differences, [])

    def test_reports_pe_metadata_changes_separately_from_hashes(self) -> None:
        """Report binary field changes and highlight a signature regression."""
        path = Path("bin/app.exe")
        old_binary = BinaryMetadata(
            "PE", "x86", "executable", "1.0", "2.0",
            SignatureMetadata(True, True, "CN=Old Publisher"),
        )
        new_binary = BinaryMetadata(
            "PE", "x86_64", "library", "1.1", "2.1", SignatureMetadata(False),
        )
        old = ReleaseArtifact(Path("old"), [ArtifactFile(path, 1, "a", old_binary)])
        new = ReleaseArtifact(Path("new"), [ArtifactFile(path, 1, "b", new_binary)])

        result = compare_artifacts(old, new)

        self.assertEqual(result.changed, [path])
        self.assertEqual(
            [(difference.field, difference.old_value, difference.new_value) for difference in result.semantic_differences],
            [
                ("Type", "executable", "library"),
                ("Architecture", "x86", "x86_64"),
                ("File version", "1.0", "1.1"),
                ("Product version", "2.0", "2.1"),
                ("Signature", "signed (valid)", "unsigned"),
                ("Signer", "CN=Old Publisher", "unavailable"),
            ],
        )
        self.assertEqual(
            [difference.field for difference in result.semantic_differences if difference.potentially_dangerous],
            ["Signature"],
        )

    def test_reports_signer_and_validity_changes_without_regression(self) -> None:
        """Track signer and validity changes without marking them as unsigned."""
        path = Path("app.exe")
        old = ReleaseArtifact(Path("old"), [ArtifactFile(
            path, 1, "a", BinaryMetadata(
                "PE", "x86_64", "executable", signature=SignatureMetadata(True, True, "CN=Old"),
            ),
        )])
        new = ReleaseArtifact(Path("new"), [ArtifactFile(
            path, 1, "a", BinaryMetadata(
                "PE", "x86_64", "executable", signature=SignatureMetadata(True, False, "CN=New"),
            ),
        )])

        result = compare_artifacts(old, new)

        self.assertEqual(result.unchanged, [path])
        self.assertEqual(
            [(difference.field, difference.old_value, difference.new_value) for difference in result.semantic_differences],
            [("Signature", "signed (valid)", "signed (invalid)"), ("Signer", "CN=Old", "CN=New")],
        )
        self.assertFalse(any(difference.potentially_dangerous for difference in result.semantic_differences))

    def test_reports_binary_signature_type_changes(self) -> None:
        """Distinguish ad hoc and certificate-backed binary signatures."""
        path = Path("application")
        old = ReleaseArtifact(Path("old"), [ArtifactFile(
            path,
            1,
            "a",
            BinaryMetadata(
                "Mach-O",
                "arm64",
                "executable",
                signature=SignatureMetadata(
                    True,
                    signature_type="ad-hoc",
                ),
            ),
        )])
        new = ReleaseArtifact(Path("new"), [ArtifactFile(
            path,
            1,
            "b",
            BinaryMetadata(
                "Mach-O",
                "arm64",
                "executable",
                signature=SignatureMetadata(
                    True,
                    signature_type="certificate",
                ),
            ),
        )])

        differences = compare_artifacts(old, new).semantic_differences

        self.assertEqual(
            [
                (difference.field, difference.old_value, difference.new_value)
                for difference in differences
            ],
            [("Signature type", "ad-hoc", "certificate")],
        )

    def test_reports_macho_minimum_os_version_changes(self) -> None:
        """Compare Mach-O deployment targets as ordinary metadata changes."""
        path = Path("Sample.app/Contents/MacOS/sample")
        old = ReleaseArtifact(Path("old"), [ArtifactFile(
            path,
            1,
            "a",
            BinaryMetadata(
                "Mach-O",
                "arm64",
                "executable",
                minimum_os_version="12.0",
            ),
        )])
        new = ReleaseArtifact(Path("new"), [ArtifactFile(
            path,
            1,
            "b",
            BinaryMetadata(
                "Mach-O",
                "arm64",
                "executable",
                minimum_os_version="13.0",
            ),
        )])

        differences = compare_artifacts(old, new).semantic_differences

        self.assertEqual(
            differences,
            [SemanticDifference(path, "Minimum OS version", "12.0", "13.0")],
        )

    def test_reports_macho_dependency_and_search_path_changes(self) -> None:
        """Compare imported libraries and runtime search paths."""
        path = Path("Sample.app/Contents/MacOS/sample")
        old_binary = BinaryMetadata(
            "Mach-O",
            "arm64",
            "executable",
            dependencies=(BinaryDependency("@rpath/libOld.dylib"),),
            runtime_search_paths=("@loader_path/../Frameworks",),
        )
        new_binary = BinaryMetadata(
            "Mach-O",
            "arm64",
            "executable",
            dependencies=(
                BinaryDependency("@rpath/libNew.dylib"),
                BinaryDependency("@rpath/libOptional.dylib", required=False),
            ),
            runtime_search_paths=("@executable_path/../Frameworks",),
        )
        old = ReleaseArtifact(
            Path("old"), [ArtifactFile(path, 1, "a", old_binary)]
        )
        new = ReleaseArtifact(
            Path("new"), [ArtifactFile(path, 1, "b", new_binary)]
        )

        differences = compare_artifacts(old, new).semantic_differences

        self.assertEqual(
            [(difference.field, difference.old_value, difference.new_value)
             for difference in differences],
            [
                (
                    "Dynamic dependencies",
                    "@rpath/libOld.dylib",
                    "@rpath/libNew.dylib, @rpath/libOptional.dylib (weak)",
                ),
                (
                    "Runtime search paths",
                    "@loader_path/../Frameworks",
                    "@executable_path/../Frameworks",
                ),
            ],
        )

    def test_hash_only_change_has_no_semantic_difference(self) -> None:
        """Keep a digest change separate when binary metadata is identical."""
        path = Path("app.exe")
        binary = BinaryMetadata("PE", "x86_64", "executable", signature=SignatureMetadata(True, True))
        old = ReleaseArtifact(Path("old"), [ArtifactFile(path, 1, "a", binary)])
        new = ReleaseArtifact(Path("new"), [ArtifactFile(path, 1, "b", binary)])

        result = compare_artifacts(old, new)

        self.assertEqual(result.changed, [path])
        self.assertEqual(result.semantic_differences, [])

    def test_compares_binary_metadata_without_pe_specific_filter(self) -> None:
        """Compare recognized binaries of the same format by generic metadata."""
        path = Path("app.bin")
        old = ReleaseArtifact(Path("old"), [ArtifactFile(
            path, 1, "a", BinaryMetadata("synthetic", "x86", "executable"),
        )])
        new = ReleaseArtifact(Path("new"), [ArtifactFile(
            path, 1, "b", BinaryMetadata("synthetic", "arm64", "library"),
        )])

        differences = compare_artifacts(old, new).semantic_differences

        self.assertEqual(
            [(difference.field, difference.old_value, difference.new_value) for difference in differences],
            [("Type", "executable", "library"), ("Architecture", "x86", "arm64")],
        )

    def test_version_increase_is_an_ordinary_change(self) -> None:
        """Keep increasing file and product versions free of warnings."""
        differences = _version_differences("1.2.9", "1.2.10", "2.0", "2.1")

        self.assertEqual([difference.field for difference in differences], ["File version", "Product version"])
        self.assertTrue(all(difference.severity is None for difference in differences))
        self.assertTrue(all(difference.warning_message is None for difference in differences))

    def test_version_decrease_warns_for_each_field(self) -> None:
        """Mark numeric file and product version downgrades as warnings."""
        differences = _version_differences("1.2.10", "1.2.9", "3.0", "2.9")

        self.assertEqual([difference.field for difference in differences], ["File version", "Product version"])
        self.assertTrue(all(difference.severity == "warning" for difference in differences))
        self.assertTrue(all(difference.warning_message == "version downgrade" for difference in differences))

    def test_equal_versions_have_no_warning(self) -> None:
        """Treat identical and numerically equivalent versions as equal in order."""
        self.assertEqual(_version_differences("1.2.0", "1.2.0"), [])

        differences = _version_differences("1.2", "1.2.0")

        self.assertEqual(len(differences), 1)
        self.assertEqual((differences[0].old_value, differences[0].new_value), ("1.2", "1.2.0"))
        self.assertIsNone(differences[0].severity)

    def test_different_component_counts_compare_with_zero_padding(self) -> None:
        """Compare versions with missing trailing components as zero."""
        downgrade = _version_differences("1.2.1", "1.2")
        increase = _version_differences("1.2", "1.2.1")

        self.assertEqual(downgrade[0].warning_message, "version downgrade")
        self.assertIsNone(increase[0].severity)

    def test_comma_separated_windows_versions_compare_numerically(self) -> None:
        """Parse Windows versions with commas and optional spaces."""
        differences = _version_differences("1, 2, 10, 0", "1,2,9,9")

        self.assertEqual(differences[0].severity, "warning")
        self.assertEqual(differences[0].warning_message, "version downgrade")

    def test_trailing_separator_is_accepted(self) -> None:
        """Normalize a trailing dot without losing numeric ordering."""
        differences = _version_differences("4.7.", "4.6")

        self.assertEqual(differences[0].severity, "warning")
        self.assertEqual(differences[0].warning_message, "version downgrade")

    def test_disappearing_version_metadata_warns(self) -> None:
        """Warn when either version field disappears from a newer binary."""
        differences = _version_differences("1.2", None, "3.4", None)

        self.assertEqual([difference.field for difference in differences], ["File version", "Product version"])
        self.assertTrue(all(difference.severity == "warning" for difference in differences))
        self.assertTrue(all(difference.warning_message == "version metadata removed" for difference in differences))

    def test_appearing_version_metadata_has_no_warning(self) -> None:
        """Show newly available version fields as ordinary semantic changes."""
        differences = _version_differences(None, "1.2", None, "3.4")

        self.assertEqual([difference.field for difference in differences], ["File version", "Product version"])
        self.assertTrue(all(difference.severity is None for difference in differences))
        self.assertTrue(all(difference.old_value == "unavailable" for difference in differences))

    def test_unparseable_versions_do_not_imply_downgrade(self) -> None:
        """Avoid downgrade claims when either version is ambiguous."""
        for old_version, new_version in (
            ("1.2-beta", "1.1"),
            ("1.2", "1..1"),
            ("1.2.3 build 4", "1.1"),
        ):
            with self.subTest(old=old_version, new=new_version):
                differences = _version_differences(old_version, new_version)
                self.assertEqual(len(differences), 1)
                self.assertIsNone(differences[0].severity)
                self.assertIsNone(differences[0].warning_message)

    def test_empty_artifacts_have_no_changes(self) -> None:
        """Return empty classifications for two empty releases."""
        self.assertEqual(
            compare_artifacts(ReleaseArtifact(Path("old")), ReleaseArtifact(Path("new"))),
            ComparisonResult(),
        )

    def test_reports_installation_scope_change_between_artifacts(self) -> None:
        """Compare scope independently of shared files or binary metadata."""
        old = ReleaseArtifact(
            Path("old.msi"), installation_scope=InstallationScope("per-user")
        )
        new = ReleaseArtifact(
            Path("new.msi"), installation_scope=InstallationScope("per-machine")
        )

        differences = compare_artifacts(old, new).semantic_differences

        self.assertEqual(
            differences,
            [SemanticDifference(Path("."), "Installation scope", "per-user", "per-machine")],
        )
        self.assertEqual(
            compare_artifacts(old, ReleaseArtifact(Path("directory"))).semantic_differences,
            [],
        )

    def test_reports_application_bundle_metadata_changes(self) -> None:
        """Compare shared bundles and warn about version regressions."""
        path = Path("Sample.app")
        old = ReleaseArtifact(Path("old.dmg"), bundles=[AppBundleMetadata(
            path,
            identifier="com.example.old",
            name="Old Name",
            short_version="2.1",
            bundle_version="210",
            executable="old-app",
            minimum_system_version="13.0",
            package_type="APPL",
        )])
        new = ReleaseArtifact(Path("new.dmg"), bundles=[AppBundleMetadata(
            path,
            identifier="com.example.new",
            name="New Name",
            short_version="2.0",
            bundle_version=None,
            executable="new-app",
            minimum_system_version="14.0",
            package_type="BNDL",
        )])

        differences = compare_artifacts(old, new).semantic_differences

        self.assertEqual(
            [difference.field for difference in differences],
            [
                "Bundle identifier",
                "Bundle name",
                "Bundle version",
                "Bundle build version",
                "Bundle executable",
                "Minimum system version",
                "Bundle package type",
            ],
        )
        self.assertEqual(differences[2].warning_message, "version downgrade")
        self.assertEqual(
            differences[3].warning_message,
            "version metadata removed",
        )
        self.assertTrue(all(
            difference.relative_path == path for difference in differences
        ))

    def test_does_not_compare_bundles_at_different_paths(self) -> None:
        """Leave bundle additions and removals to ordinary file comparison."""
        old = ReleaseArtifact(
            Path("old"),
            bundles=[AppBundleMetadata(Path("Old.app"), identifier="com.example.old")],
        )
        new = ReleaseArtifact(
            Path("new"),
            bundles=[AppBundleMetadata(Path("New.app"), identifier="com.example.new")],
        )

        self.assertEqual(compare_artifacts(old, new).semantic_differences, [])


if __name__ == "__main__":
    unittest.main()
