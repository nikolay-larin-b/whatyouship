# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect portable ZIP release artifacts through their extracted files."""

import hashlib
import zipfile
from dataclasses import replace
from pathlib import Path

from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.inspectors.zip_cache import ZipExtractionCache
from whatyouship.model import ReleaseArtifact


class ZipInspector:
    """Build a release artifact from a ZIP distribution."""

    def inspect(self, source_path: Path) -> ReleaseArtifact:
        """Extract a ZIP through the cache and inspect its file tree.

        :param source_path: ZIP archive to inspect.
        :returns: Artifact with paths relative to the archive root.
        :raises FileNotFoundError: If the archive does not exist.
        :raises IsADirectoryError: If the path is not a regular file.
        :raises ValueError: If the ZIP cannot be safely extracted.
        """
        if not source_path.exists():
            raise FileNotFoundError(f"Artifact does not exist: {source_path}")
        if not source_path.is_file():
            raise IsADirectoryError(f"ZIP artifact is not a file: {source_path}")

        try:
            with source_path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            extracted = ZipExtractionCache().load_or_populate(digest, source_path)
            return replace(DirectoryInspector().inspect(extracted), source_path=source_path)
        except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as error:
            raise ValueError(f"Unable to inspect ZIP '{source_path}': {error}") from error
