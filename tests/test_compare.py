# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for release artifact comparison."""

import unittest
from pathlib import Path

from whatyouship.compare import ComparisonResult, compare_artifacts
from whatyouship.model import ArtifactFile, BinaryMetadata, ReleaseArtifact, SignatureMetadata


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

    def test_empty_artifacts_have_no_changes(self) -> None:
        """Return empty classifications for two empty releases."""
        self.assertEqual(
            compare_artifacts(ReleaseArtifact(Path("old")), ReleaseArtifact(Path("new"))),
            ComparisonResult(),
        )


if __name__ == "__main__":
    unittest.main()
