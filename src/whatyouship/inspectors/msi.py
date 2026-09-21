# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect files stored in Windows Installer packages."""

import hashlib
import io
from collections.abc import Iterator
from contextlib import redirect_stdout
from operator import attrgetter
from pathlib import Path

import pymsi
from pymsi.msi.file import File

from whatyouship.binary.pe import PeInspector
from whatyouship.inspectors.msi_cache import MsiPayloadCache
from whatyouship.inspectors.msi_scope import MsiScopeInspector
from whatyouship.inspectors.msi_signature import MsiSignatureInspector
from whatyouship.model import ArtifactFile, ReleaseArtifact


def _long_name(value: str) -> str:
    """Select the long name from an MSI short-name and long-name pair.

    :param value: MSI file or directory name.
    :returns: The long name when present, otherwise the original name.
    """
    return value.split("|", 1)[-1]


class MsiInspector:
    """Build a release artifact from the files in an MSI package."""

    def inspect(self, source_path: Path) -> ReleaseArtifact:
        """Read installed file paths and payloads from an MSI package.

        :param source_path: Path to the MSI package.
        :returns: An artifact with files ordered by relative installation path.
        :raises FileNotFoundError: If the package does not exist.
        :raises IsADirectoryError: If the path is not a regular file.
        :raises ValueError: If the package or a file payload cannot be read.
        """
        if not source_path.exists():
            raise FileNotFoundError(f"Artifact does not exist: {source_path}")
        if not source_path.is_file():
            raise IsADirectoryError(f"MSI artifact is not a file: {source_path}")

        try:
            digest = self._msi_sha256(source_path)
            signature = MsiSignatureInspector().inspect(source_path)
            installation_scope = MsiScopeInspector().inspect(source_path)
            cached = MsiPayloadCache().load_or_populate(
                digest, lambda: self._extract_payloads(source_path)
            )
            binary_inspector = PeInspector()
            files = [
                ArtifactFile(
                    relative_path=file.relative_path,
                    size_bytes=file.size_bytes,
                    sha256=file.sha256,
                    binary=binary_inspector.inspect(file.payload_path),
                )
                for file in cached
            ]
        except Exception as error:
            raise ValueError(f"Unable to inspect MSI '{source_path}': {error}") from error

        files.sort(key=attrgetter("relative_path"))
        return ReleaseArtifact(
            source_path=source_path,
            files=files,
            signature=signature,
            installation_scope=installation_scope,
        )

    def _msi_sha256(self, source_path: Path) -> str:
        """Validate and hash the complete MSI file.

        :param source_path: MSI file to read.
        :returns: SHA-256 digest of the full MSI contents.
        :raises ValueError: If the file header is not an MSI header.
        """
        with source_path.open("rb") as stream:
            if stream.read(8) != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                raise ValueError("Invalid MSI file header")
            stream.seek(0)
            return hashlib.file_digest(stream, "sha256").hexdigest()

    def _extract_payloads(self, source_path: Path) -> Iterator[tuple[Path, bytes]]:
        """Yield installed paths and decompressed payloads from an MSI.

        :param source_path: MSI package to extract.
        :yields: Relative installation path and payload bytes for each file.
        :raises ValueError: If the package has no Directory table.
        """
        with redirect_stdout(io.StringIO()), pymsi.Package(source_path) as package:
            msi = pymsi.Msi(package, load_data=True)
            directory_table = package.get("Directory")
            if directory_table is None:
                raise ValueError("MSI has no Directory table")
            target_names = {
                row["Directory"]: row["DefaultDir"].split(":", 1)[0]
                for row in directory_table.iter()
            }
            for file in msi.files.values():
                payload = file.resolve().decompress()
                yield self._installation_path(file, target_names), bytes(payload)

    def _installation_path(self, file: File, target_names: dict[str, str]) -> Path:
        """Build a file's path relative to the MSI target directory.

        :param file: MSI file entry.
        :param target_names: Target names indexed by MSI directory ID.
        :returns: Relative installation path of the file.
        """
        parts = [_long_name(file.name)]
        directory = file.component.directory
        seen = set()
        while directory.parent is not None:
            if directory.id in seen:
                raise ValueError(f"MSI directory cycle at {directory.id}")
            seen.add(directory.id)
            target_name = target_names[directory.id]
            if target_name != ".":
                parts.append(_long_name(target_name))
            directory = directory.parent
        return Path(*reversed(parts))
