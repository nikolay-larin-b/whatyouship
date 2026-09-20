# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect ordinary files in a directory release artifact."""

import hashlib
from pathlib import Path

from whatyouship.binary.pe import PeInspector
from whatyouship.model import ArtifactFile, ReleaseArtifact


class DirectoryInspector:
    """Build a release artifact from a directory tree."""

    def inspect(self, directory: Path) -> ReleaseArtifact:
        """Inspect all ordinary files below a directory.

        :param directory: Root directory of the release artifact.
        :returns: An artifact with files ordered by relative path.
        :raises FileNotFoundError: If the directory does not exist.
        :raises NotADirectoryError: If the path is not a directory.
        """
        if not directory.exists():
            raise FileNotFoundError(f"Directory does not exist: {directory}")
        if not directory.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {directory}")

        files = []
        binary_inspector = PeInspector()
        for path in sorted(directory.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue

            with path.open("rb") as stream:
                sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
            files.append(
                ArtifactFile(
                    relative_path=path.relative_to(directory),
                    size_bytes=path.stat().st_size,
                    sha256=sha256,
                    binary=binary_inspector.inspect(path),
                )
            )

        return ReleaseArtifact(source_path=directory, files=files)
