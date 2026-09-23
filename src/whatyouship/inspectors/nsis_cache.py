# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Cache NSIS payload trees extracted by 7-Zip."""

import shutil
import subprocess
from pathlib import Path

from whatyouship.inspectors.extracted_tree_cache import ExtractedTreeCache
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
        return ExtractedTreeCache(self._root, "7-Zip").load_or_populate(
            digest, lambda files_root: self._extract(source_path, files_root)
        )

    def _extract(self, source_path: Path, files_root: Path) -> None:
        """Extract an NSIS payload into a staging tree.

        :param source_path: NSIS installer to extract.
        :param files_root: Temporary directory for extracted files.
        :raises FileNotFoundError: If 7-Zip is not available on ``PATH``.
        :raises ValueError: If extraction fails.
        """
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
