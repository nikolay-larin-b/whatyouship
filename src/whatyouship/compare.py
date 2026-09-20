# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Compare release artifact contents by relative path and SHA-256."""

from dataclasses import dataclass, field
from pathlib import Path

from whatyouship.model import ReleaseArtifact


@dataclass
class ComparisonResult:
    """Classify paths across two release artifacts.

    :param added: Paths found only in the new artifact.
    :param removed: Paths found only in the old artifact.
    :param changed: Paths with different SHA-256 digests.
    :param unchanged: Paths with matching SHA-256 digests.
    """

    added: list[Path] = field(default_factory=list)
    removed: list[Path] = field(default_factory=list)
    changed: list[Path] = field(default_factory=list)
    unchanged: list[Path] = field(default_factory=list)


def compare_artifacts(old: ReleaseArtifact, new: ReleaseArtifact) -> ComparisonResult:
    """Compare files in two artifacts by relative path and SHA-256.

    :param old: Earlier release artifact.
    :param new: Later release artifact.
    :returns: Sorted paths classified by their change status.
    """
    old_files = {file.relative_path: file for file in old.files}
    new_files = {file.relative_path: file for file in new.files}
    old_paths = old_files.keys()
    new_paths = new_files.keys()
    common_paths = old_paths & new_paths
    return ComparisonResult(
        added=sorted(new_paths - old_paths),
        removed=sorted(old_paths - new_paths),
        changed=sorted(
            path for path in common_paths if old_files[path].sha256 != new_files[path].sha256
        ),
        unchanged=sorted(
            path for path in common_paths if old_files[path].sha256 == new_files[path].sha256
        ),
    )
