# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for the WhatYouShip command-line interface."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from whatyouship import __version__
from whatyouship.cli import main


class CliTests(unittest.TestCase):
    """Verify the supported command-line options."""

    def test_help(self) -> None:
        """Verify that ``--help`` prints usage information and exits."""
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as result:
            main(["--help"])

        self.assertEqual(result.exception.code, 0)
        self.assertIn("usage: whatyouship", output.getvalue())
        self.assertIn("--version", output.getvalue())

    def test_version(self) -> None:
        """Verify that ``--version`` prints the package version and exits."""
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as result:
            main(["--version"])

        self.assertEqual(result.exception.code, 0)
        self.assertEqual(output.getvalue(), f"whatyouship {__version__}\n")

    def test_inspect_prints_summary_and_sorted_files(self) -> None:
        """Print source, counts, sizes, and digests in path order."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "z.txt").write_bytes(b"abc")
            (root / "a.txt").write_bytes(b"")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["inspect", str(root)])

            self.assertEqual(result, 0)
            lines = output.getvalue().splitlines()
            self.assertEqual(lines[:3], [f"Source: {root}", "Files: 2", "Total size: 3 bytes"])
            self.assertEqual(lines[4], "Relative path | Size (bytes) | SHA-256")
            self.assertEqual(
                lines[5:],
                [
                    "a.txt | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "z.txt | 3 | ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                ],
            )

    def test_inspect_rejects_missing_directory(self) -> None:
        """Report a missing directory through argparse with exit code two."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            missing = Path(temporary_directory) / "missing"
            error_output = io.StringIO()

            with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                main(["inspect", str(missing)])

            self.assertEqual(result.exception.code, 2)
            self.assertIn("Directory does not exist", error_output.getvalue())

    def test_inspect_rejects_file_path(self) -> None:
        """Report a regular file through argparse with exit code two."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            file = Path(temporary_directory) / "file.txt"
            file.write_bytes(b"data")
            error_output = io.StringIO()

            with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                main(["inspect", str(file)])

            self.assertEqual(result.exception.code, 2)
            self.assertIn("Path is not a directory", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
