# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect macOS DMG artifacts through their mounted volume."""

import hashlib
from dataclasses import replace
from pathlib import Path

from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.inspectors.dmg_cache import DmgConversionCache
from whatyouship.inspectors.macos_disk_image import (
    MacOSDiskImageMounter,
    inspect_disk_image_metadata,
)
from whatyouship.model import ReleaseArtifact


class DmgInspector:
    """Build a release artifact from a single-volume macOS disk image."""

    def inspect(self, source_path: Path) -> ReleaseArtifact:
        """Mount a DMG read-only and inspect its regular files.

        :param source_path: DMG artifact to inspect.
        :returns: Artifact with paths relative to the mounted volume root.
        :raises FileNotFoundError: If the artifact does not exist.
        :raises IsADirectoryError: If the artifact is not a regular file.
        :raises ValueError: If the image cannot be mounted or inspected.
        """
        if not source_path.exists():
            raise FileNotFoundError(f"Artifact does not exist: {source_path}")
        if not source_path.is_file():
            raise IsADirectoryError(f"DMG artifact is not a file: {source_path}")

        try:
            metadata = inspect_disk_image_metadata(source_path)
            if metadata.encrypted:
                raise ValueError("Encrypted DMG artifacts are not supported")
            inspection_source = source_path
            if metadata.license_agreement_present:
                with source_path.open("rb") as stream:
                    digest = hashlib.file_digest(stream, "sha256").hexdigest()
                inspection_source = DmgConversionCache().load_or_populate(
                    digest, source_path
                )
            with MacOSDiskImageMounter().mount(inspection_source) as mounted:
                artifact = DirectoryInspector().inspect(mounted)
            return replace(
                artifact,
                source_path=source_path,
                license_agreement_present=metadata.license_agreement_present,
            )
        except (OSError, ValueError, RuntimeError) as error:
            raise ValueError(
                f"Unable to inspect DMG '{source_path}': {error}"
            ) from error
