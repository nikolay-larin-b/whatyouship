# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Cache normalized DMG images by their complete source digest."""

import hashlib
import json
from pathlib import Path

from whatyouship.inspectors.extraction_cache import ExtractionCache
from whatyouship.inspectors.macos_disk_image import (
    convert_disk_image,
    verify_disk_image,
)
from whatyouship.paths import cache_directory


class DmgConversionCache:
    """Store converted filesystem-bearing DMG images atomically."""

    def __init__(self) -> None:
        """Select the versioned DMG cache directory."""
        self._root = cache_directory("dmg")

    def load_or_populate(self, digest: str, source_path: Path) -> Path:
        """Return a validated normalized image, converting on a cache miss.

        :param digest: SHA-256 of the complete original DMG.
        :param source_path: Original image to convert.
        :returns: Path to the cached normalized image.
        """
        return ExtractionCache(self._root).load_or_populate(
            digest, lambda entry: self._convert(source_path, entry), self._load
        )

    def _convert(self, source_path: Path, entry: Path) -> None:
        """Convert an image and write its completion manifest.

        :param source_path: Original image to convert.
        :param entry: Temporary cache entry.
        """
        image_path = entry / "image.dmg"
        convert_disk_image(source_path, image_path)
        verify_disk_image(image_path)
        size_bytes = image_path.stat().st_size
        with image_path.open("rb") as stream:
            image_digest = hashlib.file_digest(stream, "sha256").hexdigest()
        (entry / "manifest.json").write_text(
            json.dumps({
                "version": 3,
                "size_bytes": size_bytes,
                "sha256": image_digest,
            }),
            encoding="utf-8",
        )

    def _load(self, entry: Path) -> Path | None:
        """Validate and load a complete cache entry.

        :param entry: Candidate cache entry.
        :returns: Cached image path, or ``None`` for an invalid entry.
        """
        if entry.is_symlink() or not entry.is_dir():
            return None
        try:
            expected_names = {"image.dmg", "manifest.json"}
            if {path.name for path in entry.iterdir()} != expected_names:
                return None
            image_path = entry / "image.dmg"
            manifest_path = entry / "manifest.json"
            if (
                image_path.is_symlink()
                or not image_path.is_file()
                or manifest_path.is_symlink()
                or not manifest_path.is_file()
            ):
                return None
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict) or set(manifest) != {
                "version", "size_bytes", "sha256"
            }:
                return None
            version = manifest.get("version")
            size_bytes = manifest.get("size_bytes")
            image_digest = manifest.get("sha256")
            if type(version) is not int or version != 3:
                return None
            if type(size_bytes) is not int or size_bytes < 0:
                return None
            if (
                not isinstance(image_digest, str)
                or len(image_digest) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in image_digest
                )
                or image_path.stat().st_size != size_bytes
            ):
                return None
            with image_path.open("rb") as stream:
                actual_digest = hashlib.file_digest(stream, "sha256").hexdigest()
            return image_path if actual_digest == image_digest else None
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return None
