# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for persistent artifact cache inspection and removal."""

import tempfile
import unittest
from pathlib import Path

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

        removed = clear_cache(("dmg",), self.root)

        self.assertEqual(removed.entries, 3)
        self.assertEqual(
            removed.size_bytes, len(b"image") + len(b"old") + len(b"current")
        )
        self.assertFalse((self.root / "dmg").exists())
        self.assertFalse((self.root / "dmg-7zip").exists())
        self.assertTrue(zip_entry.is_dir())

    def test_clear_all_is_idempotent_and_removes_unknown_data(self) -> None:
        """Remove the complete root, including unrecognized cache namespaces."""
        self._write_entry("zip", "v1", "a" * 64, b"zip")
        self._write_entry("future", "v2", "b" * 64, b"future")

        removed = clear_cache(root=self.root)
        empty = clear_cache(root=self.root)

        self.assertEqual(removed.entries, 2)
        self.assertEqual(removed.size_bytes, len(b"zip") + len(b"future"))
        self.assertFalse(self.root.exists())
        self.assertEqual(empty.entries, 0)
        self.assertEqual(empty.size_bytes, 0)

    def test_clear_rejects_unknown_format(self) -> None:
        """Reject unsupported selective removal without changing cache data."""
        entry = self._write_entry("zip", "v1", "a" * 64, b"zip")

        with self.assertRaisesRegex(ValueError, "Unsupported cache format: future"):
            clear_cache(("future",), self.root)

        self.assertTrue(entry.is_dir())


if __name__ == "__main__":
    unittest.main()
