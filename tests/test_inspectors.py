# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for the artifact inspector dispatcher."""

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any

from whatyouship.exceptions import (
    ArtifactNotFoundError,
    UnsupportedArtifactError,
    WhatYouShipError,
)
from whatyouship.inspectors import inspect_artifact
from whatyouship.operations import inspect


class _CustomPath(os.PathLike[str]):
    """Provide a non-``pathlib`` path-like object for dispatcher tests."""

    def __init__(self, path: Path) -> None:
        """Store the path returned by :meth:`__fspath__`.

        :param path: Filesystem path represented by this object.
        """
        self._path = path

    def __fspath__(self) -> str:
        """Return the represented filesystem path.

        :returns: Native string path.
        """
        return os.fspath(self._path)


class InspectorDispatcherTests(unittest.TestCase):
    """Verify path normalization at the low-level dispatcher boundary."""

    def test_accepts_string_path(self) -> None:
        """Normalize a string before selecting an inspector."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory)
            (source / "payload.txt").write_bytes(b"payload")

            artifact = inspect_artifact(str(source))

        self.assertEqual(artifact.source_path, source)

    def test_accepts_pathlib_path(self) -> None:
        """Continue accepting a native :class:`pathlib.Path`."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory)

            artifact = inspect_artifact(source)

        self.assertEqual(artifact.source_path, source)

    def test_accepts_custom_path_like_object(self) -> None:
        """Normalize arbitrary implementations of :class:`os.PathLike`."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory)

            artifact = inspect_artifact(_CustomPath(source))

        self.assertEqual(artifact.source_path, source)

    def test_missing_path_uses_public_error_contract(self) -> None:
        """Report a missing string path through ``ArtifactNotFoundError``."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            missing = Path(temporary_directory) / "missing.zip"

            with self.assertRaises(ArtifactNotFoundError) as raised:
                inspect_artifact(str(missing))

        self.assertIsInstance(raised.exception, WhatYouShipError)
        self.assertIn(str(missing), str(raised.exception))

    def test_unsupported_path_uses_public_error_contract(self) -> None:
        """Report an unsupported path-like input without changing detection."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "release.bin"
            source.write_bytes(b"payload")

            with self.assertRaises(UnsupportedArtifactError) as raised:
                inspect_artifact(_CustomPath(source))

        self.assertIsInstance(raised.exception, WhatYouShipError)
        self.assertIn(str(source), str(raised.exception))

    def test_low_level_and_public_api_normalize_paths_consistently(self) -> None:
        """Return equivalent artifacts from both supported entry points."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory)
            (source / "payload.txt").write_bytes(b"payload")
            path_like = _CustomPath(source)

            artifact = inspect_artifact(path_like)
            report = inspect(path_like)

        self.assertEqual(report.artifact, artifact)

    def test_invalid_argument_type_is_not_wrapped(self) -> None:
        """Preserve ``TypeError`` at both supported entry points."""
        invalid: Any = 42

        for operation in (inspect_artifact, inspect):
            with self.subTest(operation=operation.__name__), self.assertRaises(
                TypeError
            ) as raised:
                operation(invalid)
            self.assertNotIsInstance(raised.exception, WhatYouShipError)


if __name__ == "__main__":
    unittest.main()
