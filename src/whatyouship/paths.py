# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Define user data paths shared by WhatYouShip features."""

from pathlib import Path


def user_data_directory() -> Path:
    """Return the root directory for user-specific WhatYouShip data.

    :returns: ``.whatyouship`` below the current user's home directory.
    """
    return Path.home() / ".whatyouship"


def cache_directory(artifact_type: str, version: str = "v1") -> Path:
    """Return a versioned extraction cache directory.

    :param artifact_type: Artifact format identifier such as ``msi`` or ``zip``.
    :param version: Cache layout version.
    :returns: Versioned cache directory for the artifact format.
    """
    return user_data_directory() / "cache" / artifact_type / version


def config_directory() -> Path:
    """Return the reserved directory for user configuration.

    :returns: Configuration directory below the WhatYouShip data root.
    """
    return user_data_directory() / "config"
