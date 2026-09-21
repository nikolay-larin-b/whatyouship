# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for release artifact comparison."""

import unittest
from pathlib import Path

from whatyouship.compare import ComparisonResult, SemanticDifference, compare_artifacts
from whatyouship.model import ArtifactFile, BinaryMetadata, ReleaseArtifact, SignatureMetadata


def _version_differences(
    old_file: str | None,
    new_file: str | None,
    old_product: str | None = None,
    new_product: str | None = None,
) -> list[SemanticDifference]:
    """Compare version metadata for one PE file at a shared path.

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
            ArtifactFile(Path("same"), 2, "a", binary=BinaryMetadata("PE", "x86_64", "dll")),
        ])

        result = compare_artifacts(old, new)

        self.assertEqual(result.added, [Path("b-added"), Path("z-added")])
        self.assertEqual(result.removed, [Path("b-removed"), Path("z-removed")])
        self.assertEqual(result.changed, [Path("b-changed"), Path("z-changed")])
        self.assertEqual(result.unchanged, [Path("same")])
        self.assertEqual(result.semantic_differences, [])

    def test_reports_pe_metadata_changes_separately_from_hashes(self) -> None:
        """Report PE field changes and highlight a signed to unsigned regression."""
        path = Path("bin/app.exe")
        old_binary = BinaryMetadata(
            "PE", "x86", "executable", "1.0", "2.0",
            SignatureMetadata(True, True, "CN=Old Publisher"),
        )
        new_binary = BinaryMetadata(
            "PE", "x86_64", "dll", "1.1", "2.1", SignatureMetadata(False),
        )
        old = ReleaseArtifact(Path("old"), [ArtifactFile(path, 1, "a", old_binary)])
        new = ReleaseArtifact(Path("new"), [ArtifactFile(path, 1, "b", new_binary)])

        result = compare_artifacts(old, new)

        self.assertEqual(result.changed, [path])
        self.assertEqual(
            [(difference.field, difference.old_value, difference.new_value) for difference in result.semantic_differences],
            [
                ("Type", "EXE", "DLL"),
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

    def test_hash_only_change_has_no_semantic_difference(self) -> None:
        """Keep a digest change separate when PE metadata is identical."""
        path = Path("app.exe")
        binary = BinaryMetadata("PE", "x86_64", "executable", signature=SignatureMetadata(True, True))
        old = ReleaseArtifact(Path("old"), [ArtifactFile(path, 1, "a", binary)])
        new = ReleaseArtifact(Path("new"), [ArtifactFile(path, 1, "b", binary)])

        result = compare_artifacts(old, new)

        self.assertEqual(result.changed, [path])
        self.assertEqual(result.semantic_differences, [])

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
        """Warn when either version field disappears from a newer PE."""
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


if __name__ == "__main__":
    unittest.main()
