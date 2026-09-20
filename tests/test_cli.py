# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for the WhatYouShip command-line interface."""

import contextlib
import io
import unittest

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


if __name__ == "__main__":
    unittest.main()
