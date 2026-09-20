# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for directory release artifact inspection."""

import tempfile
import unittest
from pathlib import Path

from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.model import ReleaseArtifact


class DirectoryInspectorTests(unittest.TestCase):
    """Verify directory inspection and invalid path handling."""

    def test_inspects_nested_files_in_sorted_order(self) -> None:
        """Record relative paths, byte sizes, and SHA-256 in stable order."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "nested").mkdir()
            (root / "nested" / "z.bin").write_bytes(b"abc")
            (root / "a.txt").write_bytes(b"")

            artifact = DirectoryInspector().inspect(root)

            self.assertIsInstance(artifact, ReleaseArtifact)
            self.assertEqual(artifact.source_path, root)
            self.assertEqual(
                [file.relative_path for file in artifact.files],
                [Path("a.txt"), Path("nested/z.bin")],
            )
            self.assertEqual([file.size_bytes for file in artifact.files], [0, 3])
            self.assertEqual(
                [file.sha256 for file in artifact.files],
                [
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                ],
            )

    def test_empty_directory_has_no_files(self) -> None:
        """Represent an empty directory with an empty file list."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact = DirectoryInspector().inspect(Path(temporary_directory))

            self.assertEqual(artifact.files, [])

    def test_missing_directory_raises_file_not_found(self) -> None:
        """Reject a path that does not exist."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            missing = Path(temporary_directory) / "missing"

            with self.assertRaises(FileNotFoundError):
                DirectoryInspector().inspect(missing)

    def test_regular_file_raises_not_a_directory(self) -> None:
        """Reject an existing file as the inspection root."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            file = Path(temporary_directory) / "release.zip"
            file.write_bytes(b"data")

            with self.assertRaises(NotADirectoryError):
                DirectoryInspector().inspect(file)


if __name__ == "__main__":
    unittest.main()
