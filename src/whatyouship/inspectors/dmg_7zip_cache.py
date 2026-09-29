# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Cache single-volume DMG trees extracted by 7-Zip."""

import shutil
import subprocess
from pathlib import Path

from whatyouship.inspectors.extracted_tree_cache import ExtractedTreeCache
from whatyouship.paths import cache_directory


_SEVEN_ZIP_NAMES = ("7zz", "7z", "7z.exe")
_SEVEN_ZIP_REQUIRED = (
    "DMG extraction requires 7-Zip. Add '7z' or '7zz' to PATH."
)
_FILESYSTEM_TYPES = {"APFS", "HFS"}


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


def _failure_detail(result: subprocess.CompletedProcess[str]) -> str:
    """Select bounded diagnostics from a failed 7-Zip command.

    :param result: Completed 7-Zip process.
    :returns: Diagnostic text suitable for a one-line error.
    """
    output = result.stderr.strip() or result.stdout.strip()
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return " | ".join(lines[-6:])[:1000]


def _archive_types(output: str) -> list[str]:
    """Read archive types from 7-Zip technical listing output.

    :param output: Standard output from ``7z l -slt``.
    :returns: Archive types in traversal order.
    """
    prefix = "Type = "
    return [
        line[len(prefix):].strip()
        for line in output.splitlines()
        if line.startswith(prefix)
    ]


class DmgSevenZipExtractionCache:
    """Store regular files from a single-volume DMG by source digest."""

    def __init__(self) -> None:
        """Select the versioned 7-Zip DMG cache directory."""
        self._root = cache_directory("dmg-7zip")

    def load_or_populate(self, digest: str, source_path: Path) -> Path:
        """Return the single extracted volume root.

        :param digest: SHA-256 of the complete DMG artifact.
        :param source_path: DMG artifact to extract on a cache miss.
        :returns: Directory representing the volume root.
        :raises FileNotFoundError: If 7-Zip is unavailable.
        :raises ValueError: If the image cannot be inspected or extracted.
        """
        files_root = ExtractedTreeCache(self._root, "7-Zip").load_or_populate(
            digest, lambda output: self._extract(source_path, output)
        )
        return self._volume_root(files_root)

    def _extract(self, source_path: Path, files_root: Path) -> None:
        """Validate and extract one DMG filesystem into staging.

        Symbolic links and alternate streams are deliberately omitted to match
        the format-independent directory inspection model.

        :param source_path: DMG artifact to extract.
        :param files_root: Temporary directory for extracted files.
        :raises FileNotFoundError: If 7-Zip is unavailable.
        :raises ValueError: If listing or extraction fails.
        """
        executable = find_7zip()
        listing = subprocess.run(
            [executable, "l", "-slt", "-sccUTF-8", "-bd", str(source_path)],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        if listing.returncode != 0:
            detail = _failure_detail(listing)
            suffix = f": {detail}" if detail else ""
            raise ValueError(
                f"7-Zip DMG listing failed with exit code "
                f"{listing.returncode}{suffix}"
            )
        types = _archive_types(listing.stdout)
        filesystems = [value for value in types if value in _FILESYSTEM_TYPES]
        if not types or types[0] != "Dmg" or len(filesystems) != 1:
            raise ValueError(
                "7-Zip did not find exactly one supported filesystem in the DMG"
            )

        result = subprocess.run(
            [
                executable,
                "x",
                "-y",
                "-bd",
                "-bb0",
                "-sns-",
                "-snl-",
                "-sccUTF-8",
                f"-o{files_root}",
                str(source_path),
            ],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        if result.returncode != 0:
            detail = _failure_detail(result)
            suffix = f": {detail}" if detail else ""
            raise ValueError(
                f"7-Zip DMG extraction failed with exit code "
                f"{result.returncode}{suffix}"
            )
        self._volume_root(files_root)

    def _volume_root(self, files_root: Path) -> Path:
        """Select the only top-level directory produced for the volume.

        :param files_root: Validated extraction root.
        :returns: Single extracted volume directory.
        :raises ValueError: If extraction did not produce one volume root.
        """
        entries = list(files_root.iterdir())
        if len(entries) != 1 or entries[0].is_symlink() or not entries[0].is_dir():
            raise ValueError(
                "7-Zip did not extract exactly one DMG volume directory"
            )
        return entries[0]
