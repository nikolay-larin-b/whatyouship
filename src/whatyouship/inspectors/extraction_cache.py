# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Publish extracted artifact contents through a versioned staging cache."""

import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar


_Entry = TypeVar("_Entry")


class ExtractionCache:
    """Manage atomic publication of content-addressed extraction entries."""

    def __init__(self, root: Path) -> None:
        """Set the versioned cache root.

        :param root: Directory containing entries named by source SHA-256.
        """
        self._root = root

    def load_or_populate(
        self,
        digest: str,
        populate: Callable[[Path], None],
        load: Callable[[Path], _Entry | None],
    ) -> _Entry:
        """Load a complete entry or populate and publish one from staging.

        :param digest: SHA-256 of the complete source artifact.
        :param populate: Callback that writes a complete staging entry.
        :param load: Callback that validates and reads a complete entry.
        :returns: The validated cache entry.
        :raises ValueError: If the populated entry is incomplete.
        """
        entry = self._root / digest
        cached = load(entry)
        if cached is not None:
            return cached

        self._root.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=".tmp-", dir=self._root))
        try:
            populate(temporary)
            staged = load(temporary)
            if staged is None:
                raise ValueError("Extracted cache entry is incomplete")

            cached = load(entry)
            if cached is not None:
                return cached
            self._remove_invalid(entry)
            try:
                os.replace(temporary, entry)
            except OSError:
                cached = load(entry)
                if cached is not None:
                    return cached
                raise

            published = load(entry)
            if published is None:
                raise ValueError("Published cache entry is incomplete")
            return published
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def _remove_invalid(self, entry: Path) -> None:
        """Discard an invalid entry after a replacement is ready.

        :param entry: Invalid entry path derived from the source digest.
        """
        if entry.is_symlink() or entry.is_file():
            entry.unlink()
        elif entry.is_dir():
            shutil.rmtree(entry)
