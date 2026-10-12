# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Define user data paths shared by WhatYouShip features."""

import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from typing import Callable, ParamSpec, TypeVar


_cache_root_override: ContextVar[Path | None] = ContextVar(
    "whatyouship_cache_root_override", default=None
)
_cache_scope_active: ContextVar[bool] = ContextVar(
    "whatyouship_cache_scope_active", default=False
)
_Parameters = ParamSpec("_Parameters")
_Result = TypeVar("_Result")


def user_data_directory() -> Path:
    """Return the root directory for user-specific WhatYouShip data.

    :returns: ``.whatyouship`` below the current user's home directory.
    """
    return Path.home() / ".whatyouship"


def cache_root_directory() -> Path:
    """Return the active root directory for artifact caches.

    Outside an active scope, the persistent path is returned for cache
    management operations. Extraction code must obtain a versioned path through
    :func:`cache_directory`, which requires an active scope.

    :returns: Scoped temporary or persistent user cache root.
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
    :raises RuntimeError: If no explicit or operation-owned cache scope is active.
    """
    if not _cache_scope_active.get():
        raise RuntimeError("Artifact cache access requires an active cache scope")
    return cache_root_directory() / artifact_type / version


@contextmanager
def cache_scope(persistent: bool) -> Iterator[None]:
    """Select persistent or command-scoped temporary artifact caching.

    :param persistent: Whether to use the persistent user cache.
    :yields: Control while the selected cache root is active.
    """
    active_token = _cache_scope_active.set(True)
    if persistent:
        root_token = _cache_root_override.set(None)
        try:
            yield
        finally:
            _cache_root_override.reset(root_token)
            _cache_scope_active.reset(active_token)
        return

    try:
        with tempfile.TemporaryDirectory(prefix="whatyouship-cache-") as temporary:
            root_token = _cache_root_override.set(Path(temporary))
            try:
                yield
            finally:
                _cache_root_override.reset(root_token)
    finally:
        _cache_scope_active.reset(active_token)


def _default_cache_scope(
    operation: Callable[_Parameters, _Result],
) -> Callable[_Parameters, _Result]:
    """Run an artifact operation in a temporary cache unless a scope is active.

    :param operation: Artifact operation that may use an extraction cache.
    :returns: Wrapped operation with safe default cache lifecycle management.
    """

    @wraps(operation)
    def wrapped(*args: _Parameters.args, **kwargs: _Parameters.kwargs) -> _Result:
        if _cache_scope_active.get():
            return operation(*args, **kwargs)
        with cache_scope(persistent=False):
            return operation(*args, **kwargs)

    return wrapped


def config_directory() -> Path:
    """Return the reserved directory for user configuration.

    :returns: Configuration directory below the WhatYouShip data root.
    """
    return user_data_directory() / "config"
