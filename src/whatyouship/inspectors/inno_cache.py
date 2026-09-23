# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Cache Inno Setup payload trees extracted by innoextract."""

import shutil
import subprocess
from pathlib import Path

from whatyouship.inspectors.extracted_tree_cache import ExtractedTreeCache
from whatyouship.paths import cache_directory


_INNOEXTRACT_REQUIRED = (
    "Inno Setup extraction requires innoextract. Add 'innoextract' to PATH."
)
_INNOEXTRACT_BOILERPLATE_PREFIXES = (
    "Done with ",
    "If you are sure the setup file is not corrupted",
    "filing a bug report at ",
)


def _failure_detail(stdout: str, stderr: str) -> str:
    """Select useful, bounded diagnostics from failed innoextract output.

    :param stdout: Captured standard output.
    :param stderr: Captured standard error.
    :returns: Diagnostic text suitable for a one-line CLI error.
    """
    all_lines = [
        line.strip()
        for output in (stderr, stdout)
        for line in output.splitlines()
        if line.strip()
    ]
    useful_lines = [
        line
        for line in all_lines
        if not line.startswith(_INNOEXTRACT_BOILERPLATE_PREFIXES)
    ]
    selected = useful_lines[-6:] or all_lines[-1:]
    return " | ".join(selected)[:1000]


def find_innoextract() -> str:
    """Find innoextract using ``PATH`` only.

    :returns: Resolved executable path.
    :raises FileNotFoundError: If innoextract is not on ``PATH``.
    """
    executable = shutil.which("innoextract")
    if executable is None:
        raise FileNotFoundError(_INNOEXTRACT_REQUIRED)
    return executable


class InnoExtractionCache:
    """Store extracted Inno Setup payloads by installer digest."""

    def __init__(self) -> None:
        """Select the versioned Inno Setup cache directory."""
        self._root = cache_directory("inno")

    def load_or_populate(self, digest: str, source_path: Path) -> Path:
        """Return a validated payload tree, extracting it on a cache miss.

        :param digest: SHA-256 of the complete Inno Setup installer.
        :param source_path: Installer to extract on a cache miss.
        :returns: Directory containing the extracted payload.
        """
        return ExtractedTreeCache(self._root, "innoextract").load_or_populate(
            digest, lambda files_root: self._extract(source_path, files_root)
        )

    def _extract(self, source_path: Path, files_root: Path) -> None:
        """Extract an Inno Setup payload into a staging tree.

        :param source_path: Inno Setup installer to extract.
        :param files_root: Temporary directory for extracted files.
        :raises FileNotFoundError: If innoextract is unavailable.
        :raises ValueError: If extraction fails.
        """
        executable = find_innoextract()
        result = subprocess.run(
            [
                executable,
                "--extract",
                "--silent",
                "--output-dir",
                str(files_root),
                "--",
                str(source_path),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            detail = _failure_detail(result.stdout, result.stderr)
            suffix = f": {detail}" if detail else ""
            raise ValueError(
                f"innoextract failed with exit code {result.returncode}{suffix}"
            )
