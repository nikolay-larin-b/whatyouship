# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Store extracted MSI payloads in a versioned user cache."""

import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import platformdirs


@dataclass(frozen=True)
class CachedMsiFile:
    """Describe a validated extracted file in an MSI cache entry.

    :param relative_path: Installation path relative to the artifact root.
    :param payload_path: Path to the extracted payload in the cache.
    :param size_bytes: Validated payload size.
    :param sha256: Validated payload digest.
    """

    relative_path: Path
    payload_path: Path
    size_bytes: int
    sha256: str


class MsiPayloadCache:
    """Cache extracted MSI files under a SHA-256 content key."""

    def __init__(self) -> None:
        """Select the versioned user cache directory."""
        self._root = Path(platformdirs.user_cache_dir("whatyouship")) / "msi" / "v1"

    def load_or_populate(
        self,
        msi_sha256: str,
        extract: Callable[[], Iterable[tuple[Path, bytes]]],
    ) -> list[CachedMsiFile]:
        """Return validated payloads or extract and publish a cache entry.

        :param msi_sha256: SHA-256 digest of the complete MSI file.
        :param extract: Callback yielding installation paths and payload bytes.
        :returns: Cached files in extraction order.
        :raises OSError: If the cache cannot be written.
        :raises ValueError: If extraction does not produce a complete entry.
        """
        entry = self._root / msi_sha256
        cached = self._load(entry)
        if cached is not None:
            return cached

        self._root.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=".tmp-", dir=self._root))
        try:
            self._write(temporary, extract())
            if self._load(temporary) is None:
                raise ValueError("Extracted MSI cache entry is incomplete")

            cached = self._load(entry)
            if cached is not None:
                return cached
            self._remove_invalid(entry)
            try:
                os.replace(temporary, entry)
            except OSError:
                cached = self._load(entry)
                if cached is not None:
                    return cached
                raise

            cached = self._load(entry)
            if cached is None:
                raise ValueError("Published MSI cache entry is incomplete")
            return cached
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def _write(
        self, entry: Path, payloads: Iterable[tuple[Path, bytes]]
    ) -> None:
        """Write extracted payloads and a completion manifest.

        :param entry: Temporary directory for the entry.
        :param payloads: Installation paths and decompressed contents.
        """
        payload_directory = entry / "files"
        payload_directory.mkdir()
        records = []
        for index, (relative_path, content) in enumerate(payloads):
            (payload_directory / f"{index:08d}.bin").write_bytes(content)
            records.append(
                {
                    "relative_path": relative_path.as_posix(),
                    "size_bytes": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                }
            )
        (entry / "manifest.json").write_text(
            json.dumps({"version": 1, "files": records}), encoding="utf-8"
        )

    def _load(self, entry: Path) -> list[CachedMsiFile] | None:
        """Validate an entry before treating it as a cache hit.

        :param entry: Candidate cache entry directory.
        :returns: Validated files, or ``None`` for an incomplete entry.
        """
        if entry.is_symlink() or not entry.is_dir():
            return None
        try:
            payload_directory = entry / "files"
            if payload_directory.is_symlink() or not payload_directory.is_dir():
                return None
            manifest = json.loads((entry / "manifest.json").read_text(encoding="utf-8"))
            if (
                not isinstance(manifest, dict)
                or type(manifest.get("version")) is not int
                or manifest["version"] != 1
                or not isinstance(manifest.get("files"), list)
            ):
                return None

            files = []
            for index, record in enumerate(manifest["files"]):
                if not isinstance(record, dict):
                    return None
                relative_name = record.get("relative_path")
                size = record.get("size_bytes")
                digest = record.get("sha256")
                if (
                    not isinstance(relative_name, str)
                    or relative_name in {"", "."}
                    or type(size) is not int
                    or size < 0
                    or not isinstance(digest, str)
                    or len(digest) != 64
                    or any(character not in "0123456789abcdef" for character in digest)
                ):
                    return None
                relative_path = Path(relative_name)
                if relative_path.is_absolute() or ".." in relative_path.parts:
                    return None
                payload_path = payload_directory / f"{index:08d}.bin"
                if payload_path.is_symlink() or not payload_path.is_file():
                    return None
                if payload_path.stat().st_size != size:
                    return None
                with payload_path.open("rb") as stream:
                    if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                        return None
                files.append(CachedMsiFile(relative_path, payload_path, size, digest))
            return files
        except (OSError, ValueError, TypeError, KeyError):
            return None

    def _remove_invalid(self, entry: Path) -> None:
        """Remove an unusable entry before publishing its replacement.

        :param entry: Entry path derived from the MSI digest.
        """
        if entry.is_symlink() or entry.is_file():
            entry.unlink()
        elif entry.is_dir():
            shutil.rmtree(entry)
