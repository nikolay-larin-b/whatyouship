# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect NSIS installers through payloads extracted by 7-Zip."""

import hashlib
import sys
from dataclasses import replace
from pathlib import Path

from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.inspectors.nsis_cache import NsisExtractionCache
from whatyouship.model import ArtifactSignature, ReleaseArtifact


class NsisInspector:
    """Build a release artifact from an NSIS installer payload."""

    def inspect(self, source_path: Path) -> ReleaseArtifact:
        """Extract an NSIS installer through the cache and inspect its payload.

        :param source_path: NSIS installer to inspect.
        :returns: Artifact with paths relative to the extracted payload root.
        :raises FileNotFoundError: If the installer or 7-Zip does not exist.
        :raises IsADirectoryError: If the installer is not a regular file.
        :raises ValueError: If extraction or payload inspection fails.
        """
        if not source_path.exists():
            raise FileNotFoundError(f"Artifact does not exist: {source_path}")
        if not source_path.is_file():
            raise IsADirectoryError(f"NSIS artifact is not a file: {source_path}")

        try:
            with source_path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            extracted = NsisExtractionCache().load_or_populate(digest, source_path)
            artifact = DirectoryInspector().inspect(extracted)
            return replace(
                artifact,
                source_path=source_path,
                signature=self._signature(source_path),
            )
        except (OSError, ValueError, RuntimeError) as error:
            raise ValueError(f"Unable to inspect NSIS '{source_path}': {error}") from error

    def _signature(self, source_path: Path) -> ArtifactSignature:
        """Verify the outer installer on Windows when supported.

        :param source_path: Original NSIS executable.
        :returns: Installer signature status.
        """
        if sys.platform != "win32":
            return ArtifactSignature(status="unsupported")

        from whatyouship.inspectors.windows_authenticode import WindowsAuthenticodeVerifier

        return WindowsAuthenticodeVerifier().verify(source_path)
