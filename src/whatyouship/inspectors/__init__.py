# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect release artifacts from supported sources."""

from os import PathLike
from pathlib import Path

from whatyouship.exceptions import ArtifactNotFoundError, UnsupportedArtifactError
from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.inspectors.dmg import DmgInspector
from whatyouship.inspectors.inno import InnoInspector
from whatyouship.inspectors.inno_detection import is_inno_installer
from whatyouship.inspectors.msi import MsiInspector
from whatyouship.inspectors.nsis import NsisInspector
from whatyouship.inspectors.nsis_detection import is_nsis_installer
from whatyouship.inspectors.zip import ZipInspector
from whatyouship.model import ReleaseArtifact
from whatyouship.paths import _default_cache_scope


@_default_cache_scope
def inspect_artifact(source_path: str | PathLike[str]) -> ReleaseArtifact:
    """Inspect a directory, DMG, MSI, NSIS, Inno Setup, or ZIP artifact.

    :param source_path: String or path-like release artifact path.
    :returns: Files contained in the artifact.
    :raises ArtifactNotFoundError: If the artifact does not exist.
    :raises UnsupportedArtifactError: If the artifact type is unsupported.
    :raises TypeError: If ``source_path`` is not string or path-like.
    """
    artifact_path = Path(source_path)
    if not artifact_path.exists():
        raise ArtifactNotFoundError(f"Artifact does not exist: {artifact_path}")
    if artifact_path.is_dir():
        return DirectoryInspector().inspect(artifact_path)
    if artifact_path.is_file() and artifact_path.suffix.lower() == ".msi":
        return MsiInspector().inspect(artifact_path)
    if artifact_path.is_file() and artifact_path.suffix.lower() == ".zip":
        return ZipInspector().inspect(artifact_path)
    if artifact_path.is_file() and artifact_path.suffix.lower() == ".dmg":
        return DmgInspector().inspect(artifact_path)
    if artifact_path.is_file() and artifact_path.suffix.lower() == ".exe":
        if is_nsis_installer(artifact_path):
            return NsisInspector().inspect(artifact_path)
        if is_inno_installer(artifact_path):
            return InnoInspector().inspect(artifact_path)
        raise UnsupportedArtifactError(
            "Unsupported EXE artifact "
            f"(not an NSIS or Inno Setup installer): {artifact_path}"
        )
    raise UnsupportedArtifactError(f"Unsupported artifact type: {artifact_path}")
