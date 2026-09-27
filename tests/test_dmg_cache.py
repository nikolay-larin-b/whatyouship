# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for content-addressed normalized DMG caching."""

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.inspectors.dmg_cache import DmgConversionCache


class DmgConversionCacheTests(unittest.TestCase):
    """Verify cache reuse, validation, and atomic recovery."""

    def setUp(self) -> None:
        """Create a disposable cache and source image."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache_root = self.root / "cache" / "dmg" / "v1"
        self.source = self.root / "source.dmg"
        self.source.write_bytes(b"source image")
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()

    def test_cache_miss_converts_and_cache_hit_reuses_image(self) -> None:
        """Publish one normalized image and reuse it on the next load."""
        def convert(source: Path, destination: Path) -> None:
            self.assertEqual(source, self.source)
            destination.write_bytes(b"normalized image")

        with patch(
            "whatyouship.inspectors.dmg_cache.cache_directory",
            return_value=self.cache_root,
        ), patch(
            "whatyouship.inspectors.dmg_cache.convert_disk_image",
            side_effect=convert,
        ) as conversion:
            first = DmgConversionCache().load_or_populate(self.digest, self.source)
            second = DmgConversionCache().load_or_populate(self.digest, self.source)

        self.assertEqual(first, second)
        self.assertEqual(first.read_bytes(), b"normalized image")
        self.assertEqual(conversion.call_count, 1)

    def test_tampered_entry_is_rebuilt(self) -> None:
        """Replace an image whose size no longer matches its manifest."""
        entry = self.cache_root / self.digest
        entry.mkdir(parents=True)
        (entry / "image.dmg").write_bytes(b"damaged")
        (entry / "manifest.json").write_text(
            '{"version": 1, "size_bytes": 100}', encoding="utf-8"
        )

        with patch(
            "whatyouship.inspectors.dmg_cache.cache_directory",
            return_value=self.cache_root,
        ), patch(
            "whatyouship.inspectors.dmg_cache.convert_disk_image",
            side_effect=lambda _source, destination: destination.write_bytes(b"fresh"),
        ):
            image = DmgConversionCache().load_or_populate(self.digest, self.source)

        self.assertEqual(image.read_bytes(), b"fresh")

    def test_failed_conversion_does_not_publish_an_entry(self) -> None:
        """Keep the final digest path absent after conversion failure."""
        with patch(
            "whatyouship.inspectors.dmg_cache.cache_directory",
            return_value=self.cache_root,
        ), patch(
            "whatyouship.inspectors.dmg_cache.convert_disk_image",
            side_effect=ValueError("conversion failed"),
        ), self.assertRaisesRegex(ValueError, "conversion failed"):
            DmgConversionCache().load_or_populate(self.digest, self.source)

        self.assertFalse((self.cache_root / self.digest).exists())


if __name__ == "__main__":
    unittest.main()
