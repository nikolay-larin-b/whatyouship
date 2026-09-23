# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Cache NSIS payload trees extracted by 7-Zip."""

import json
import shutil
import subprocess
from pathlib import Path

from whatyouship.inspectors.extraction_cache import ExtractionCache
from whatyouship.paths import cache_directory


_SEVEN_ZIP_NAMES = ("7zz", "7z", "7z.exe")
_SEVEN_ZIP_REQUIRED = "NSIS extraction requires 7-Zip. Add '7z' or '7zz' to PATH."


def find_7zip() -> str:
    """Find a supported 7-Zip executable using ``PATH`` only.

    :returns: Resolved executable path.
    :raises FileNotFoundError: If no supported executable is on ``PATH``.
    """
    for name in _SEVEN_ZIP_NAMES:
        executable = shutil.which(name)
        if executable is not None:
            return executable
    raise FileNotFoundError(_SEVEN_ZIP_REQUIRED)


class NsisExtractionCache:
    """Store extracted NSIS payloads by the installer's complete digest."""

    def __init__(self) -> None:
        """Select the versioned NSIS cache directory."""
        self._root = cache_directory("nsis")

    def load_or_populate(self, digest: str, source_path: Path) -> Path:
        """Return a validated payload tree, extracting it on a cache miss.

        :param digest: SHA-256 of the complete NSIS installer.
        :param source_path: Installer to extract on a cache miss.
        :returns: Directory containing the extracted payload.
        """
        return ExtractionCache(self._root).load_or_populate(
            digest, lambda entry: self._extract(source_path, entry), self._load
        )

    def _extract(self, source_path: Path, entry: Path) -> None:
        """Extract an NSIS payload and write its completion manifest.

        :param source_path: NSIS installer to extract.
        :param entry: Temporary cache entry.
        :raises FileNotFoundError: If 7-Zip is not available on ``PATH``.
        :raises ValueError: If extraction fails or creates an unsafe tree.
        """
        files_root = entry / "files"
        files_root.mkdir()
        executable = find_7zip()
        result = subprocess.run(
            [executable, "x", "-y", "-bd", "-bb0", f"-o{files_root}", str(source_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            output = result.stderr.strip() or result.stdout.strip()
            detail = output.splitlines()[-1] if output else ""
            suffix = f": {detail}" if detail else ""
            raise ValueError(
                f"7-Zip extraction failed with exit code {result.returncode}{suffix}"
            )

        records: list[dict[str, str | int]] = []
        for path in sorted(files_root.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"7-Zip extracted an unsupported symbolic link: {path.name}")
            if path.is_file():
                records.append({
                    "relative_path": path.relative_to(files_root).as_posix(),
                    "size_bytes": path.stat().st_size,
                })
            elif not path.is_dir():
                raise ValueError(f"7-Zip extracted an unsupported file type: {path.name}")
        (entry / "manifest.json").write_text(
            json.dumps({"version": 1, "files": records}), encoding="utf-8"
        )

    def _load(self, entry: Path) -> Path | None:
        """Validate a completed NSIS cache entry.

        :param entry: Candidate content-addressed cache entry.
        :returns: Extracted tree, or ``None`` for an incomplete entry.
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
            return files_root if actual == expected else None
        except (OSError, ValueError, TypeError, KeyError):
            return None
