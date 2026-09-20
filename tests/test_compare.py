# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for release artifact comparison."""

import unittest
from pathlib import Path

from whatyouship.compare import ComparisonResult, compare_artifacts
from whatyouship.model import ArtifactFile, BinaryMetadata, ReleaseArtifact


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

    def test_empty_artifacts_have_no_changes(self) -> None:
        """Return empty classifications for two empty releases."""
        self.assertEqual(
            compare_artifacts(ReleaseArtifact(Path("old")), ReleaseArtifact(Path("new"))),
            ComparisonResult(),
        )


if __name__ == "__main__":
    unittest.main()
