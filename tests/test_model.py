# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for the release artifact models."""

import unittest
from pathlib import Path

from whatyouship.model import ArtifactFile, ReleaseArtifact


class ModelTests(unittest.TestCase):
    """Verify release artifact data can be represented independently."""

    def test_release_artifact_contains_files(self) -> None:
        """Keep a file's path, size, and digest within its release artifact."""
        file = ArtifactFile(
            relative_path=Path("bin/app.exe"),
            size_bytes=1024,
            sha256="a" * 64,
        )
        artifact = ReleaseArtifact(
            source_path=Path("releases/app.msi"),
            files=[file],
        )

        self.assertEqual(artifact.source_path, Path("releases/app.msi"))
        self.assertEqual(artifact.files[0].relative_path, Path("bin/app.exe"))
        self.assertEqual(artifact.files[0].size_bytes, 1024)
        self.assertEqual(artifact.files[0].sha256, "a" * 64)

    def test_default_file_lists_are_independent(self) -> None:
        """Give each release artifact its own empty file list."""
        first = ReleaseArtifact(source_path=Path("first.zip"))
        second = ReleaseArtifact(source_path=Path("second.zip"))
        first.files.append(
            ArtifactFile(relative_path=Path("app"), size_bytes=1, sha256="b" * 64)
        )

        self.assertEqual(len(first.files), 1)
        self.assertEqual(second.files, [])


if __name__ == "__main__":
    unittest.main()
