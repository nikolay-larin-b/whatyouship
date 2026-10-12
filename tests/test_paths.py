# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for user-specific WhatYouShip data paths and cache scopes."""

import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from whatyouship.inspectors import inspect_artifact
from whatyouship.inspectors.zip import ZipInspector
from whatyouship.inspectors.zip_cache import ZipExtractionCache
from whatyouship.paths import (
    cache_directory,
    cache_root_directory,
    cache_scope,
    config_directory,
    user_data_directory,
)


class UserDataPathTests(unittest.TestCase):
    """Verify the platform-independent home-relative data layout."""

    def test_user_data_layout_is_rooted_below_home(self) -> None:
        """Place caches and configuration below ``~/.whatyouship``."""
        home = Path("/users/example")

        with (
            patch("whatyouship.paths.Path.home", return_value=home),
            cache_scope(persistent=True),
        ):
            self.assertEqual(user_data_directory(), home / ".whatyouship")
            self.assertEqual(
                cache_directory("msi"),
                home / ".whatyouship" / "cache" / "msi" / "v1",
            )
            self.assertEqual(
                cache_directory("zip"),
                home / ".whatyouship" / "cache" / "zip" / "v1",
            )
            self.assertEqual(
                config_directory(), home / ".whatyouship" / "config"
            )

    def test_cache_directory_requires_explicit_or_operation_scope(self) -> None:
        """Prevent extraction caches from falling back to persistent storage."""
        with self.assertRaisesRegex(RuntimeError, "active cache scope"):
            cache_directory("zip")

    def test_temporary_cache_scope_is_removed_on_exit(self) -> None:
        """Use and remove a command-scoped cache instead of persistent data."""
        with cache_scope(persistent=False):
            root = cache_root_directory()
            entry = cache_directory("zip") / "entry"
            entry.mkdir(parents=True)
            self.assertTrue(entry.is_dir())
            self.assertEqual(root.name.split("-")[0], "whatyouship")

        self.assertFalse(root.exists())

    def test_persistent_cache_scope_keeps_user_cache_root(self) -> None:
        """Keep the home-relative cache when persistent caching is requested."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory)
            with (
                patch("whatyouship.paths.Path.home", return_value=home),
                cache_scope(persistent=True),
            ):
                self.assertEqual(
                    cache_root_directory(), home / ".whatyouship" / "cache"
                )

    def test_direct_inspection_uses_and_removes_temporary_cache(self) -> None:
        """Give a direct Python inspection operation an isolated cache lifetime."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home = root / "home"
            source = root / "release.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("payload.txt", b"payload")
            selected_roots: list[Path] = []

            original_extract = ZipExtractionCache._extract

            def record_extract(
                cache: ZipExtractionCache, source_path: Path, entry: Path
            ) -> None:
                """Record the active root before extracting the test archive.

                :param cache: ZIP cache performing the extraction.
                :param source_path: Test ZIP archive.
                :param entry: Temporary cache entry.
                """
                selected_roots.append(cache_root_directory())
                original_extract(cache, source_path, entry)

            with (
                patch("whatyouship.paths.Path.home", return_value=home),
                patch.object(
                    ZipExtractionCache,
                    "_extract",
                    autospec=True,
                    side_effect=record_extract,
                ),
            ):
                artifact = inspect_artifact(source)

            self.assertEqual(
                [file.relative_path for file in artifact.files],
                [Path("payload.txt")],
            )
            self.assertEqual(len(selected_roots), 1)
            self.assertFalse(selected_roots[0].exists())
            self.assertFalse((home / ".whatyouship" / "cache").exists())

    def test_direct_inspection_removes_temporary_cache_after_error(self) -> None:
        """Remove an operation-owned cache when artifact extraction fails."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "release.zip"
            source.write_bytes(b"not a ZIP")
            selected_roots: list[Path] = []

            def fail_extract(
                _cache: ZipExtractionCache, _source_path: Path, _entry: Path
            ) -> None:
                """Create temporary data and simulate an extraction failure.

                :param _cache: ZIP cache performing the extraction.
                :param _source_path: Test ZIP archive.
                :param _entry: Temporary cache entry.
                :raises ValueError: Always, after recording the cache root.
                """
                selected_root = cache_root_directory()
                selected_roots.append(selected_root)
                (selected_root / "partial").mkdir()
                raise ValueError("test extraction failure")

            with patch.object(
                ZipExtractionCache,
                "_extract",
                autospec=True,
                side_effect=fail_extract,
            ), self.assertRaisesRegex(ValueError, "test extraction failure"):
                ZipInspector().inspect(source)

            self.assertEqual(len(selected_roots), 1)
            self.assertFalse(selected_roots[0].exists())

    def test_explicit_cache_scope_is_reused_by_direct_inspections(self) -> None:
        """Reuse one temporary cache across repeated Python operations."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "release.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("payload.txt", b"payload")

            with cache_scope(persistent=False):
                selected_root = cache_root_directory()
                with patch.object(
                    ZipExtractionCache,
                    "_extract",
                    wraps=ZipExtractionCache()._extract,
                ) as extract:
                    first = ZipInspector().inspect(source)
                    second = ZipInspector().inspect(source)
                self.assertTrue(selected_root.is_dir())

            self.assertEqual(first, second)
            self.assertEqual(extract.call_count, 1)
            self.assertFalse(selected_root.exists())

    def test_explicit_persistent_scope_is_reused_and_preserved(self) -> None:
        """Use the user cache only when persistent storage is requested."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            home = root / "home"
            source = root / "release.zip"
            with zipfile.ZipFile(source, "w") as archive:
                archive.writestr("payload.txt", b"payload")

            with (
                patch("whatyouship.paths.Path.home", return_value=home),
                cache_scope(persistent=True),
                patch.object(
                    ZipExtractionCache,
                    "_extract",
                    wraps=ZipExtractionCache()._extract,
                ) as extract,
            ):
                first = ZipInspector().inspect(source)
                second = ZipInspector().inspect(source)
                selected_root = cache_root_directory()

            self.assertEqual(first, second)
            self.assertEqual(extract.call_count, 1)
            self.assertEqual(selected_root, home / ".whatyouship" / "cache")
            self.assertTrue(selected_root.is_dir())


if __name__ == "__main__":
    unittest.main()
