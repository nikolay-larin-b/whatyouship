# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for atomic publication of extracted cache entries."""

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.inspectors.extraction_cache import ExtractionCache


def _populate(entry: Path) -> None:
    """Write a complete synthetic staging entry.

    :param entry: Staging directory to populate.
    """
    (entry / "complete").write_text("ready", encoding="utf-8")


def _load(entry: Path) -> Path | None:
    """Load a synthetic entry only when its completion marker exists.

    :param entry: Candidate cache entry.
    :returns: Entry path when complete, otherwise ``None``.
    """
    marker = entry / "complete"
    return entry if marker.is_file() and marker.read_text(encoding="utf-8") == "ready" else None


class ExtractionCacheTests(unittest.TestCase):
    """Verify staging cleanup and directory rename behavior."""

    def test_promotion_uses_directory_rename_instead_of_replace(self) -> None:
        """Avoid Windows directory replacement semantics during publication."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "cache"
            real_rename = os.rename

            with (
                patch(
                    "whatyouship.inspectors.extraction_cache.os.rename",
                    wraps=real_rename,
                ) as rename,
                patch(
                    "whatyouship.inspectors.extraction_cache.os.replace"
                ) as replace,
            ):
                entry = ExtractionCache(root).load_or_populate(
                    "a" * 64, _populate, _load
                )

            self.assertEqual(entry, root / ("a" * 64))
            rename.assert_called_once()
            replace.assert_not_called()
            self.assertEqual(list(root.glob(".tmp-*")), [])

    def test_existing_entry_after_failed_rename_wins_race(self) -> None:
        """Use a concurrently published final entry and discard staging."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "cache"
            final = root / ("b" * 64)

            def publish_then_fail(source: Path, destination: Path) -> None:
                """Simulate Windows reporting access denied after a race.

                :param source: Complete staging directory.
                :param destination: Final content-addressed entry.
                :raises PermissionError: Always, after publishing a competing entry.
                """
                self.assertEqual(destination, final)
                shutil.copytree(source, destination)
                error = PermissionError(13, "Access is denied", str(destination))
                error.winerror = 5
                raise error

            with patch(
                "whatyouship.inspectors.extraction_cache.os.rename",
                side_effect=publish_then_fail,
            ):
                entry = ExtractionCache(root).load_or_populate(
                    "b" * 64, _populate, _load
                )

            self.assertEqual(entry, final)
            self.assertEqual((final / "complete").read_text(encoding="utf-8"), "ready")
            self.assertEqual(list(root.glob(".tmp-*")), [])

    def test_failed_promotion_removes_staging_without_publishing_entry(self) -> None:
        """Remove incomplete staging when no valid final entry exists."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "cache"
            final = root / ("c" * 64)

            with (
                patch(
                    "whatyouship.inspectors.extraction_cache.os.rename",
                    side_effect=PermissionError(13, "Access is denied"),
                ),
                self.assertRaises(PermissionError),
            ):
                ExtractionCache(root).load_or_populate("c" * 64, _populate, _load)

            self.assertFalse(final.exists())
            self.assertEqual(list(root.glob(".tmp-*")), [])


if __name__ == "__main__":
    unittest.main()
