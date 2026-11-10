# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect TAR release archives through the shared artifact analysis pipeline."""

import hashlib
import tarfile
from dataclasses import replace
from pathlib import Path

from whatyouship.exceptions import ArtifactExtractionError
from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.inspectors.tar_cache import TarExtractionCache
from whatyouship.model import ReleaseArtifact
from whatyouship.paths import _default_cache_scope


try:
    from lzma import LZMAError
except ImportError:
    _COMPRESSION_ERRORS: tuple[type[Exception], ...] = ()
else:
    _COMPRESSION_ERRORS = (LZMAError,)

try:
    from zlib import error as ZlibError
except ImportError:
    pass
else:
    _COMPRESSION_ERRORS += (ZlibError,)


class TarInspector:
    """Inspect TAR payload files, symbolic links, and original file permissions."""

    @_default_cache_scope
    def inspect(self, source_path: Path) -> ReleaseArtifact:
        """Extract a supported TAR archive without executing or installing it.

        :param source_path: TAR archive with optional gzip, xz, or bzip2 compression.
        :returns: Artifact with archive-relative paths and POSIX file modes.
        :raises FileNotFoundError: If the archive does not exist.
        :raises IsADirectoryError: If the source is not a file.
        :raises ArtifactExtractionError: If safe extraction fails.
        """
        if not source_path.exists():
            raise FileNotFoundError(f"Artifact does not exist: {source_path}")
        if not source_path.is_file():
            raise IsADirectoryError(f"TAR artifact is not a file: {source_path}")
        try:
            with source_path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            tree = TarExtractionCache().load_or_populate(digest, source_path)
            artifact = DirectoryInspector().inspect(tree.files_root, tree.symbolic_links)
            return replace(
                artifact, source_path=source_path,
                files=[replace(file, posix_mode=tree.modes[file.relative_path]) for file in artifact.files],
            )
        except (OSError, ValueError, EOFError, RuntimeError, tarfile.TarError, *_COMPRESSION_ERRORS) as error:
            raise ArtifactExtractionError(f"Unable to inspect TAR '{source_path}': {error}") from error
