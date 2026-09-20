# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect files stored in Windows Installer packages."""

import hashlib
import io
from contextlib import redirect_stdout
from operator import attrgetter
from pathlib import Path

import pymsi
from pymsi.msi.file import File

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
            with source_path.open("rb") as stream:
                if stream.read(8) != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
                    raise ValueError("Invalid MSI file header")
            with redirect_stdout(io.StringIO()), pymsi.Package(source_path) as package:
                msi = pymsi.Msi(package, load_data=True)
                directory_table = package.get("Directory")
                if directory_table is None:
                    raise ValueError("MSI has no Directory table")
                target_names = {
                    row["Directory"]: row["DefaultDir"].split(":", 1)[0]
                    for row in directory_table.iter()
                }

                files = []
                for file in msi.files.values():
                    payload = file.resolve().decompress()
                    files.append(
                        ArtifactFile(
                            relative_path=self._installation_path(file, target_names),
                            size_bytes=len(payload),
                            sha256=hashlib.sha256(payload).hexdigest(),
                        )
                    )
        except Exception as error:
            raise ValueError(f"Unable to inspect MSI '{source_path}': {error}") from error

        files.sort(key=attrgetter("relative_path"))
        return ReleaseArtifact(source_path=source_path, files=files)

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
