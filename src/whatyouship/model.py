# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Format-independent models for release artifacts."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


@dataclass
class BinaryMetadata:
    """Describe identified binary properties without format-specific fields.

    :param format: Binary file format.
    :param architecture: Target architecture.
    :param kind: Executable, library, or other binary kind.
    :param file_version: Embedded file version, when available.
    :param product_version: Embedded product version, when available.
    """

    format: str
    architecture: str
    kind: str
    file_version: str | None = None
    product_version: str | None = None


@dataclass
class ArtifactFile:
    """Describe one file contained in a release artifact.

    :param relative_path: Path relative to the root of the release artifact.
    :param size_bytes: File size in bytes.
    :param sha256: SHA-256 digest of the file contents.
    :param binary: Identified binary metadata, when available.
    """

    relative_path: Path
    size_bytes: int
    sha256: str
    binary: BinaryMetadata | None = None


@dataclass
class ReleaseArtifact:
    """Describe a release artifact and the files it contains.

    :param source_path: Path to the original artifact being analyzed.
    :param files: Files contained in the artifact.
    """

    source_path: Path
    files: list[ArtifactFile] = field(default_factory=list)


@dataclass
class Finding:
    """Describe a condition reported by a lint rule.

    :param rule_id: Identifier of the rule that reported the finding.
    :param severity: Severity of the finding.
    :param relative_path: Path of the affected file within the artifact.
    :param message: Short description of the condition.
    """

    rule_id: str
    severity: Literal["warning"]
    relative_path: Path
    message: str
