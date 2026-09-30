# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Define user data paths shared by WhatYouShip features."""

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path


_cache_root_override: ContextVar[Path | None] = ContextVar(
    "whatyouship_cache_root_override", default=None
)


def user_data_directory() -> Path:
    """Return the root directory for user-specific WhatYouShip data.

    :returns: ``.whatyouship`` below the current user's home directory.
    """
    return Path.home() / ".whatyouship"


def cache_root_directory() -> Path:
    """Return the active root directory for artifact caches.

    :returns: Temporary override when one is active, otherwise the persistent
        user cache directory.
    """
    override = _cache_root_override.get()
    if override is not None:
        return override
    return user_data_directory() / "cache"


def cache_directory(artifact_type: str, version: str = "v1") -> Path:
    """Return a versioned extraction cache directory.

    :param artifact_type: Artifact format identifier such as ``msi`` or ``zip``.
    :param version: Cache layout version.
    :returns: Versioned cache directory for the artifact format.
    """
    return cache_root_directory() / artifact_type / version


@contextmanager
def cache_scope(persistent: bool) -> Iterator[None]:
    """Select persistent or command-scoped temporary artifact caching.

    :param persistent: Whether to use the persistent user cache.
    :yields: Control while the selected cache root is active.
    """
    if persistent:
        yield
        return

    with tempfile.TemporaryDirectory(prefix="whatyouship-cache-") as temporary:
        token = _cache_root_override.set(Path(temporary))
        try:
            yield
        finally:
            _cache_root_override.reset(token)


def config_directory() -> Path:
    """Return the reserved directory for user configuration.

    :returns: Configuration directory below the WhatYouShip data root.
    """
    return user_data_directory() / "config"
