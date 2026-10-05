# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect ordinary files in a directory release artifact."""

import hashlib
import os
from collections.abc import Iterable
from pathlib import Path

from whatyouship.binary.macho import MachOInspector
from whatyouship.binary.pe import PeInspector
from whatyouship.inspectors.app_bundle import AppBundleInspector
from whatyouship.model import (
    ArtifactFile,
    ArtifactSymbolicLink,
    ReleaseArtifact,
    symbolic_link_is_external,
)


class DirectoryInspector:
    """Build a release artifact from a directory tree."""

    def inspect(
        self,
        directory: Path,
        symbolic_links: Iterable[ArtifactSymbolicLink] = (),
        *,
        validate_executable_permissions: bool = False,
    ) -> ReleaseArtifact:
        """Inspect all ordinary files below a directory.

        :param directory: Root directory of the release artifact.
        :param symbolic_links: Links supplied by an extraction backend.
        :param validate_executable_permissions: Whether filesystem mode bits are
            authoritative for application bundle validation.
        :returns: An artifact with files ordered by relative path.
        :raises FileNotFoundError: If the directory does not exist.
        :raises NotADirectoryError: If the path is not a directory.
        """
        if not directory.exists():
            raise FileNotFoundError(f"Directory does not exist: {directory}")
        if not directory.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {directory}")

        files = []
        links_by_path = {link.relative_path: link for link in symbolic_links}
        pe_inspector = PeInspector()
        macho_inspector = MachOInspector()
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                relative_path = path.relative_to(directory)
                target = os.readlink(path)
                links_by_path[relative_path] = ArtifactSymbolicLink(
                    relative_path,
                    target,
                    symbolic_link_is_external(relative_path, target),
                )
                continue
            if not path.is_file():
                continue

            with path.open("rb") as stream:
                sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
            files.append(
                ArtifactFile(
                    relative_path=path.relative_to(directory),
                    size_bytes=path.stat().st_size,
                    sha256=sha256,
                    binary=(
                        pe_inspector.inspect(path) or macho_inspector.inspect(path)
                    ),
                )
            )

        bundles = AppBundleInspector().inspect(
            directory,
            files,
            links_by_path.values(),
            validate_executable_permissions=validate_executable_permissions,
        )
        return ReleaseArtifact(
            source_path=directory,
            files=files,
            symbolic_links=[links_by_path[path] for path in sorted(links_by_path)],
            bundles=bundles,
        )
