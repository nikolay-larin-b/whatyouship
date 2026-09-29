# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Validate and publish directory trees produced by external extractors."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from whatyouship.inspectors.extraction_cache import ExtractionCache


@dataclass(frozen=True)
class ExtractedTreeEntry:
    """Describe a validated extracted tree and its backend metadata.

    :param files_root: Directory containing extracted regular files.
    :param metadata: Validated backend-specific manifest metadata.
    """

    files_root: Path
    metadata: dict[str, object]


class ExtractedTreeCache:
    """Cache an externally extracted directory tree by source digest."""

    def __init__(self, root: Path, extractor_name: str) -> None:
        """Set the cache root and extractor name used in errors.

        :param root: Versioned content-addressed cache root.
        :param extractor_name: Human-readable external extractor name.
        """
        self._root = root
        self._extractor_name = extractor_name

    def load_or_populate(
        self, digest: str, populate: Callable[[Path], None]
    ) -> Path:
        """Return a validated tree, populating and publishing it on a miss.

        :param digest: SHA-256 of the complete source artifact.
        :param populate: Callback that extracts files below ``entry/files``.
        :returns: Directory containing the extracted files.
        """
        return ExtractionCache(self._root).load_or_populate(
            digest, lambda entry: self._populate(entry, populate), self._load
        )

    def load_or_populate_with_metadata(
        self,
        digest: str,
        populate: Callable[[Path], dict[str, object]],
        validate_metadata: Callable[[object], dict[str, object] | None],
    ) -> ExtractedTreeEntry:
        """Return a validated tree with backend-specific manifest metadata.

        :param digest: SHA-256 of the complete source artifact.
        :param populate: Callback that extracts files and returns metadata.
        :param validate_metadata: Callback that validates cached metadata.
        :returns: Extracted files and validated metadata.
        """
        return ExtractionCache(self._root).load_or_populate(
            digest,
            lambda entry: self._populate(entry, populate),
            lambda entry: self._load_entry(entry, validate_metadata),
        )

    def _populate(
        self,
        entry: Path,
        populate: Callable[[Path], dict[str, object] | None],
    ) -> None:
        """Extract into staging and write a completion manifest.

        :param entry: Temporary cache entry.
        :param populate: Callback that writes the extracted tree.
        :raises ValueError: If extraction creates an unsupported file type.
        """
        files_root = entry / "files"
        files_root.mkdir()
        metadata = populate(files_root) or {}

        records: list[dict[str, str | int]] = []
        for path in sorted(files_root.rglob("*")):
            if path.is_symlink():
                raise ValueError(
                    f"{self._extractor_name} extracted an unsupported symbolic link: "
                    f"{path.name}"
                )
            if path.is_file():
                records.append({
                    "relative_path": path.relative_to(files_root).as_posix(),
                    "size_bytes": path.stat().st_size,
                })
            elif not path.is_dir():
                raise ValueError(
                    f"{self._extractor_name} extracted an unsupported file type: "
                    f"{path.name}"
                )
        (entry / "manifest.json").write_text(
            json.dumps({"version": 1, "files": records, "metadata": metadata}),
            encoding="utf-8",
        )

    def _load(self, entry: Path) -> Path | None:
        """Validate a completed extracted-tree cache entry.

        :param entry: Candidate content-addressed cache entry.
        :returns: Extracted tree, or ``None`` for an incomplete entry.
        """
        loaded = self._load_entry(
            entry,
            lambda metadata: metadata if isinstance(metadata, dict) else None,
        )
        return loaded.files_root if loaded is not None else None

    def _load_entry(
        self,
        entry: Path,
        validate_metadata: Callable[[object], dict[str, object] | None],
    ) -> ExtractedTreeEntry | None:
        """Validate files and backend metadata in one cache entry.

        :param entry: Candidate content-addressed cache entry.
        :param validate_metadata: Callback that validates manifest metadata.
        :returns: Validated cache entry, or ``None`` when incomplete.
        """
        if entry.is_symlink() or not entry.is_dir():
            return None
        try:
            files_root = entry / "files"
            manifest_path = entry / "manifest.json"
            if (
                files_root.is_symlink()
                or not files_root.is_dir()
                or manifest_path.is_symlink()
            ):
                return None
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (
                not isinstance(manifest, dict)
                or type(manifest.get("version")) is not int
                or manifest["version"] != 1
                or not isinstance(manifest.get("files"), list)
            ):
                return None
            metadata = validate_metadata(manifest.get("metadata", {}))
            if metadata is None:
                return None

            expected: set[Path] = set()
            for record in manifest["files"]:
                if not isinstance(record, dict):
                    return None
                name = record.get("relative_path")
                size = record.get("size_bytes")
                if not isinstance(name, str) or type(size) is not int or size < 0:
                    return None
                relative_path = Path(name)
                if (
                    relative_path.is_absolute()
                    or relative_path in expected
                    or relative_path.parts in {(), (".",)}
                    or ".." in relative_path.parts
                ):
                    return None
                expected.add(relative_path)
                file_path = files_root / relative_path
                if file_path.is_symlink() or not file_path.is_file():
                    return None
                if file_path.stat().st_size != size:
                    return None

            actual: set[Path] = set()
            for path in files_root.rglob("*"):
                if path.is_symlink():
                    return None
                if path.is_file():
                    actual.add(path.relative_to(files_root))
                elif not path.is_dir():
                    return None
            return (
                ExtractedTreeEntry(files_root, metadata)
                if actual == expected else None
            )
        except (OSError, ValueError, TypeError, KeyError):
            return None
