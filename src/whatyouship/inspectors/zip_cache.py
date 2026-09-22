# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Cache safely extracted ZIP distribution trees."""

import hashlib
import json
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

from whatyouship.inspectors.extraction_cache import ExtractionCache
from whatyouship.paths import cache_directory


def _safe_path(name: str) -> Path:
    """Validate an archive member path before using it in the cache.

    :param name: Path stored in a ZIP entry.
    :returns: Relative path below the extraction root.
    :raises ValueError: If the entry could escape or alias another path.
    """
    normalized = name.rstrip("/")
    parts = normalized.split("/")
    if (
        not normalized
        or "\\" in name
        or PurePosixPath(name).is_absolute()
        or PureWindowsPath(name).is_absolute()
        or any(part in {"", ".", ".."} for part in parts)
        or ":" in parts[0]
    ):
        raise ValueError(f"Unsafe ZIP entry path: {name!r}")
    return Path(*parts)


class ZipExtractionCache:
    """Store extracted ZIP files by the digest of the complete archive."""

    def __init__(self) -> None:
        """Select the versioned user cache directory."""
        self._root = cache_directory("zip")

    def load_or_populate(self, digest: str, source_path: Path) -> Path:
        """Return a validated extracted tree, populating it when needed.

        :param digest: SHA-256 of the complete ZIP archive.
        :param source_path: Archive to extract on a cache miss.
        :returns: Directory containing the extracted files.
        """
        return ExtractionCache(self._root).load_or_populate(
            digest, lambda entry: self._extract(source_path, entry), self._load
        )

    def _extract(self, source_path: Path, entry: Path) -> None:
        """Extract safe regular files and write a completion manifest.

        :param source_path: ZIP archive to read.
        :param entry: Temporary cache entry.
        :raises ValueError: If an entry is unsafe or duplicated.
        :raises zipfile.BadZipFile: If archive data is damaged.
        """
        files_root = entry / "files"
        files_root.mkdir()
        records: list[dict[str, str | int]] = []
        seen_files: set[Path] = set()
        with zipfile.ZipFile(source_path) as archive:
            for member in archive.infolist():
                relative_path = _safe_path(member.filename)
                mode = member.external_attr >> 16
                file_type = stat.S_IFMT(mode)
                if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise ValueError(f"Unsupported ZIP entry type: {member.filename!r}")
                target = files_root / relative_path
                if member.is_dir():
                    if relative_path in seen_files:
                        raise ValueError(f"Conflicting ZIP entry path: {member.filename!r}")
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if file_type == stat.S_IFDIR or relative_path in seen_files or target.exists():
                    raise ValueError(f"Conflicting ZIP entry path: {member.filename!r}")
                seen_files.add(relative_path)
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as source, target.open("wb") as destination:
                    shutil.copyfileobj(source, destination)
                records.append({
                    "relative_path": relative_path.as_posix(),
                    "size_bytes": target.stat().st_size,
                })
        (entry / "manifest.json").write_text(
            json.dumps({"version": 1, "files": records}), encoding="utf-8"
        )

    def _load(self, entry: Path) -> Path | None:
        """Validate the completion manifest and extracted file tree.

        :param entry: Candidate cache entry.
        :returns: Extracted tree, or ``None`` for an incomplete entry.
        """
        if entry.is_symlink() or not entry.is_dir():
            return None
        try:
            files_root = entry / "files"
            if files_root.is_symlink() or not files_root.is_dir():
                return None
            manifest_path = entry / "manifest.json"
            if manifest_path.is_symlink():
                return None
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (
                not isinstance(manifest, dict)
                or type(manifest.get("version")) is not int
                or manifest["version"] != 1
                or not isinstance(manifest.get("files"), list)
            ):
                return None

            expected: set[Path] = set()
            for record in manifest["files"]:
                if not isinstance(record, dict):
                    return None
                name = record.get("relative_path")
                size = record.get("size_bytes")
                if not isinstance(name, str) or type(size) is not int or size < 0:
                    return None
                relative_path = _safe_path(name)
                if relative_path in expected:
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
            return files_root if actual == expected else None
        except (OSError, ValueError, TypeError, KeyError):
            return None
