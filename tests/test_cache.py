# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for persistent artifact cache inspection and removal."""

import os
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

from whatyouship.cache import clear_cache, inspect_cache


class CacheManagementTests(unittest.TestCase):
    """Verify cache statistics and explicit removal scopes."""

    def setUp(self) -> None:
        """Create a disposable persistent cache root."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "cache"

    def _write_entry(
        self, namespace: str, version: str, name: str, content: bytes
    ) -> Path:
        """Write one synthetic cache entry.

        :param namespace: Internal cache namespace.
        :param version: Cache layout version.
        :param name: Entry directory name.
        :param content: Payload bytes to store.
        :returns: Created entry directory.
        """
        entry = self.root / namespace / version / name
        entry.mkdir(parents=True)
        (entry / "payload").write_bytes(content)
        return entry

    def test_missing_cache_is_empty(self) -> None:
        """Report a cache that has not been created without modifying it."""
        info = inspect_cache(self.root)

        self.assertEqual(info.root, self.root)
        self.assertEqual(info.entries, 0)
        self.assertEqual(info.temporary_entries, 0)
        self.assertEqual(info.size_bytes, 0)
        self.assertEqual(info.formats, ())
        self.assertFalse(self.root.exists())

    def test_info_groups_namespaces_and_reports_layouts(self) -> None:
        """Combine DMG backends and identify interrupted staging entries."""
        self._write_entry("dmg", "v1", "a" * 64, b"image")
        self._write_entry("dmg-7zip", "v2", "b" * 64, b"tree")
        self._write_entry("zip", "v1", ".tmp-interrupted", b"partial")
        self._write_entry("future", "v3", "c" * 64, b"unknown")

        info = inspect_cache(self.root)

        self.assertEqual(info.entries, 3)
        self.assertEqual(info.temporary_entries, 1)
        self.assertEqual(
            [item.format_name for item in info.formats], ["dmg", "future", "zip"]
        )
        dmg = info.formats[0]
        self.assertEqual(dmg.entries, 2)
        self.assertEqual(dmg.temporary_entries, 0)
        self.assertEqual(dmg.layouts, ("dmg/v1", "dmg-7zip/v2"))
        self.assertEqual(dmg.size_bytes, len(b"image") + len(b"tree"))
        self.assertEqual(info.formats[2].temporary_entries, 1)
        self.assertEqual(
            info.size_bytes, sum(item.size_bytes for item in info.formats)
        )

    def test_clear_format_removes_all_backend_versions(self) -> None:
        """Remove every namespace and layout belonging to one public format."""
        self._write_entry("dmg", "v1", "a" * 64, b"image")
        self._write_entry("dmg-7zip", "v1", "b" * 64, b"old")
        self._write_entry("dmg-7zip", "v2", "c" * 64, b"current")
        zip_entry = self._write_entry("zip", "v1", "d" * 64, b"zip")

        result = clear_cache(("dmg",), self.root)

        self.assertEqual(result.failures, ())
        self.assertIsNotNone(result.selected)
        assert result.selected is not None
        self.assertEqual(result.selected.entries, 3)
        self.assertEqual(
            result.selected.size_bytes,
            len(b"image") + len(b"old") + len(b"current"),
        )
        self.assertFalse((self.root / "dmg").exists())
        self.assertFalse((self.root / "dmg-7zip").exists())
        self.assertTrue(zip_entry.is_dir())

    def test_clear_all_is_idempotent_and_removes_unknown_data(self) -> None:
        """Remove the complete root, including unrecognized cache namespaces."""
        self._write_entry("zip", "v1", "a" * 64, b"zip")
        self._write_entry("future", "v2", "b" * 64, b"future")

        result = clear_cache(root=self.root)
        empty_result = clear_cache(root=self.root)

        self.assertEqual(result.failures, ())
        self.assertIsNotNone(result.selected)
        assert result.selected is not None
        self.assertEqual(result.selected.entries, 2)
        self.assertEqual(result.selected.size_bytes, len(b"zip") + len(b"future"))
        self.assertFalse(self.root.exists())
        self.assertEqual(empty_result.failures, ())
        self.assertIsNotNone(empty_result.selected)
        assert empty_result.selected is not None
        self.assertEqual(empty_result.selected.entries, 0)
        self.assertEqual(empty_result.selected.size_bytes, 0)

    def test_clear_all_restores_access_to_unreadable_directories(self) -> None:
        """Remove an interrupted extraction containing an unreadable directory."""
        entry = self._write_entry(
            "dmg-7zip", "v2", ".tmp-interrupted", b"partial"
        )
        private = entry / "files" / ".HFS+ Private Directory Data_"
        private.mkdir(parents=True)
        original_scandir = os.scandir
        original_chmod = os.chmod
        restored = False

        def scandir(path: str | os.PathLike[str]) -> Iterator[os.DirEntry[str]]:
            """Reject traversal until owner access is restored.

            :param path: Directory to inspect.
            :returns: Directory iterator for accessible paths.
            :raises PermissionError: If the private directory is still inaccessible.
            """
            if Path(path) == private and not restored:
                raise PermissionError(5, "Access is denied", str(path))
            return original_scandir(path)

        def chmod(path: str | os.PathLike[str], mode: int) -> None:
            """Record restored access and apply the requested mode.

            :param path: File or directory whose mode is changed.
            :param mode: New permission mode.
            """
            nonlocal restored
            if Path(path) == private:
                restored = True
            original_chmod(path, mode)

        with patch("whatyouship.cache.os.scandir", side_effect=scandir), patch(
            "whatyouship.cache.os.chmod", side_effect=chmod
        ):
            result = clear_cache(root=self.root)

        self.assertTrue(restored)
        self.assertEqual(result.failures, ())
        self.assertIsNotNone(result.selected)
        assert result.selected is not None
        self.assertEqual(result.selected.temporary_entries, 1)
        self.assertFalse(self.root.exists())

    def test_clear_all_continues_after_unrecoverable_directory(self) -> None:
        """Remove sibling entries after one directory remains inaccessible."""
        blocked = self._write_entry(
            "dmg-7zip", "v2", ".tmp-blocked", b"blocked"
        )
        removable = self._write_entry(
            "dmg-7zip", "v2", ".tmp-removable", b"removable"
        )
        original_scandir = os.scandir
        original_chmod = os.chmod

        def scandir(path: str | os.PathLike[str]) -> Iterator[os.DirEntry[str]]:
            """Reject traversal of the blocked staging entry.

            :param path: Directory to inspect.
            :returns: Directory iterator for accessible paths.
            :raises PermissionError: If the blocked entry is inspected.
            """
            if Path(path) == blocked:
                raise PermissionError(5, "Access is denied", str(path))
            return original_scandir(path)

        def chmod(path: str | os.PathLike[str], mode: int) -> None:
            """Reject permission repair for the blocked staging entry.

            :param path: File or directory whose mode is changed.
            :param mode: New permission mode.
            :raises PermissionError: If the blocked entry is changed.
            """
            if Path(path) == blocked:
                raise PermissionError(5, "Access is denied", str(path))
            original_chmod(path, mode)

        with patch("whatyouship.cache.os.scandir", side_effect=scandir), patch(
            "whatyouship.cache.os.chmod", side_effect=chmod
        ):
            result = clear_cache(root=self.root)

        self.assertIsNone(result.selected)
        self.assertEqual(len(result.failures), 1)
        self.assertEqual(result.failures[0].path, blocked)
        self.assertTrue(blocked.is_dir())
        self.assertFalse(removable.exists())

    def test_clear_format_does_not_traverse_other_formats(self) -> None:
        """Leave inaccessible data outside the selected format untouched."""
        self._write_entry("dmg-7zip", "v2", "a" * 64, b"dmg")
        other = self._write_entry("future", "v1", "b" * 64, b"future")
        original_scandir = os.scandir

        def scandir(path: str | os.PathLike[str]) -> Iterator[os.DirEntry[str]]:
            """Reject traversal of the unselected cache namespace.

            :param path: Directory to inspect.
            :returns: Directory iterator for selected paths.
            :raises PermissionError: If unselected data is inspected.
            """
            if Path(path) == self.root / "future":
                raise PermissionError(5, "Access is denied", str(path))
            return original_scandir(path)

        with patch("whatyouship.cache.os.scandir", side_effect=scandir):
            result = clear_cache(("dmg",), self.root)

        self.assertEqual(result.failures, ())
        self.assertIsNotNone(result.selected)
        assert result.selected is not None
        self.assertEqual(result.selected.entries, 1)
        self.assertTrue(other.is_dir())

    def test_clear_rejects_unknown_format(self) -> None:
        """Reject unsupported selective removal without changing cache data."""
        entry = self._write_entry("zip", "v1", "a" * 64, b"zip")

        with self.assertRaisesRegex(ValueError, "Unsupported cache format: future"):
            clear_cache(("future",), self.root)

        self.assertTrue(entry.is_dir())


if __name__ == "__main__":
    unittest.main()
