# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Publish extracted artifact contents through a versioned staging cache."""

import os
import shutil
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar


_Entry = TypeVar("_Entry")

_WINDOWS_RENAME_RETRY_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6, 3.2)
_WINDOWS_TRANSIENT_RENAME_ERRORS = {5, 32}


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
            if load(temporary) is None:
                raise ValueError("Extracted cache entry is incomplete")

            cached = load(entry)
            if cached is not None:
                return cached
            self._remove_invalid(entry)
            cached = self._promote(temporary, entry, load)
            if cached is not None:
                return cached

            published = load(entry)
            if published is None:
                raise ValueError("Published cache entry is incomplete")
            return published
        finally:
            if temporary.exists():
                shutil.rmtree(temporary)

    def _promote(
        self,
        temporary: Path,
        entry: Path,
        load: Callable[[Path], _Entry | None],
    ) -> _Entry | None:
        """Atomically rename staging, retrying transient Windows locks.

        :param temporary: Complete staging directory.
        :param entry: Final content-addressed cache path.
        :param load: Callback that validates and reads a complete entry.
        :returns: A concurrently published entry, or ``None`` after promotion.
        :raises OSError: If promotion fails permanently.
        """
        delays = iter(_WINDOWS_RENAME_RETRY_DELAYS)
        while True:
            try:
                os.rename(temporary, entry)
                return None
            except OSError as error:
                cached = load(entry)
                if cached is not None:
                    return cached
                if (
                    sys.platform != "win32"
                    or getattr(error, "winerror", None)
                    not in _WINDOWS_TRANSIENT_RENAME_ERRORS
                ):
                    raise
                try:
                    delay = next(delays)
                except StopIteration:
                    raise error
                time.sleep(delay)

    def _remove_invalid(self, entry: Path) -> None:
        """Discard an invalid entry after a replacement is ready.

        :param entry: Invalid entry path derived from the source digest.
        """
        if entry.is_symlink() or entry.is_file():
            entry.unlink()
        elif entry.is_dir():
            shutil.rmtree(entry)
