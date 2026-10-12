# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for directory release artifact inspection."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.binary.errors import BinaryAnalysisError
from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.model import BinaryMetadata, ReleaseArtifact, symbolic_link_is_external


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

    def test_records_native_links_without_following_them(self) -> None:
        """Match native directory links with extracted DMG link metadata."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "data").mkdir()
            (root / "data" / "payload.txt").write_bytes(b"payload")
            try:
                (root / "current").symlink_to("data/payload.txt")
                (root / "external").symlink_to("/Applications")
            except OSError as error:
                if getattr(error, "winerror", None) == 1314:
                    self.skipTest("Creating symbolic links requires Windows privilege")
                raise

            artifact = DirectoryInspector().inspect(root)

        self.assertEqual(
            [file.relative_path for file in artifact.files],
            [Path("data/payload.txt")],
        )
        self.assertEqual(
            [
                (link.relative_path, link.target, link.external)
                for link in artifact.symbolic_links
            ],
            [
                (Path("current"), "data/payload.txt", False),
                (Path("external"), "/Applications", True),
            ],
        )

    def test_classifies_relative_link_targets_at_the_artifact_boundary(self) -> None:
        """Allow parent traversal within the root and flag traversal above it."""
        self.assertFalse(
            symbolic_link_is_external(Path("nested/current"), "../data")
        )
        self.assertTrue(
            symbolic_link_is_external(Path("nested/current"), "../../outside")
        )

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

    def test_binary_parse_failure_keeps_other_files(self) -> None:
        """Keep the artifact intact when one PE candidate cannot be parsed."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "broken.exe").write_bytes(b"broken")
            (root / "working.exe").write_bytes(b"working")
            (root / "readme.txt").write_bytes(b"text")

            def inspect_binary(path: Path) -> BinaryMetadata | None:
                """Return metadata or a failure based on the synthetic file name.

                :param path: Synthetic artifact file.
                :returns: Metadata for the working PE or ``None`` for text.
                :raises BinaryAnalysisError: For the broken PE.
                """
                if path.name == "broken.exe":
                    raise BinaryAnalysisError("PE", "truncated headers")
                if path.name == "working.exe":
                    return BinaryMetadata("PE", "x86_64", "executable")
                return None

            with patch(
                "whatyouship.inspectors.directory.PeInspector.inspect",
                side_effect=inspect_binary,
            ):
                artifact = DirectoryInspector().inspect(root)

            self.assertEqual(
                [file.relative_path for file in artifact.files],
                [Path("broken.exe"), Path("readme.txt"), Path("working.exe")],
            )
            self.assertIsNone(artifact.files[0].binary)
            self.assertIsNone(artifact.files[1].binary)
            self.assertEqual(artifact.files[2].binary.format, "PE")
            self.assertEqual(len(artifact.binary_diagnostics), 1)
            self.assertEqual(
                artifact.binary_diagnostics[0].relative_path,
                Path("broken.exe"),
            )
            self.assertEqual(artifact.binary_diagnostics[0].format, "PE")
            self.assertEqual(
                artifact.binary_diagnostics[0].reason,
                "truncated headers",
            )


if __name__ == "__main__":
    unittest.main()
