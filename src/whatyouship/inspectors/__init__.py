# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect release artifacts from supported sources."""

from pathlib import Path

from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.inspectors.inno import InnoInspector
from whatyouship.inspectors.inno_detection import is_inno_installer
from whatyouship.inspectors.msi import MsiInspector
from whatyouship.inspectors.nsis import NsisInspector
from whatyouship.inspectors.nsis_detection import is_nsis_installer
from whatyouship.inspectors.zip import ZipInspector
from whatyouship.model import ReleaseArtifact


def inspect_artifact(source_path: Path) -> ReleaseArtifact:
    """Inspect a directory, MSI, NSIS, Inno Setup, or ZIP release artifact.

    :param source_path: Path to the release artifact.
    :returns: Files contained in the artifact.
    :raises FileNotFoundError: If the artifact does not exist.
    :raises ValueError: If the artifact type is unsupported.
    """
    if not source_path.exists():
        raise FileNotFoundError(f"Artifact does not exist: {source_path}")
    if source_path.is_dir():
        return DirectoryInspector().inspect(source_path)
    if source_path.is_file() and source_path.suffix.lower() == ".msi":
        return MsiInspector().inspect(source_path)
    if source_path.is_file() and source_path.suffix.lower() == ".zip":
        return ZipInspector().inspect(source_path)
    if source_path.is_file() and source_path.suffix.lower() == ".exe":
        if is_nsis_installer(source_path):
            return NsisInspector().inspect(source_path)
        if is_inno_installer(source_path):
            return InnoInspector().inspect(source_path)
        raise ValueError(
            "Unsupported EXE artifact "
            f"(not an NSIS or Inno Setup installer): {source_path}"
        )
    raise ValueError(f"Unsupported artifact type: {source_path}")
