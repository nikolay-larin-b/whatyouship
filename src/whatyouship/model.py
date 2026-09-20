# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Format-independent models for release artifacts."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ArtifactFile:
    """Describe one file contained in a release artifact.

    :param relative_path: Path relative to the root of the release artifact.
    :param size_bytes: File size in bytes.
    :param sha256: SHA-256 digest of the file contents.
    """

    relative_path: Path
    size_bytes: int
    sha256: str


@dataclass
class ReleaseArtifact:
    """Describe a release artifact and the files it contains.

    :param source_path: Path to the original artifact being analyzed.
    :param files: Files contained in the artifact.
    """

    source_path: Path
    files: list[ArtifactFile] = field(default_factory=list)
