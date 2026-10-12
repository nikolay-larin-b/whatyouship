# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Define expected errors raised by public WhatYouShip operations."""


__all__ = [
    "ArtifactExtractionError",
    "ArtifactInspectionError",
    "ArtifactNotFoundError",
    "ConfigurationError",
    "ExternalToolError",
    "UnsupportedArtifactError",
    "WhatYouShipError",
]


class WhatYouShipError(Exception):
    """Base class for expected WhatYouShip operation failures."""


class ArtifactNotFoundError(FileNotFoundError, WhatYouShipError):
    """Indicate that a requested release artifact does not exist."""


class UnsupportedArtifactError(ValueError, WhatYouShipError):
    """Indicate that no inspector supports the supplied artifact."""


class ArtifactInspectionError(ValueError, WhatYouShipError):
    """Indicate that a recognized artifact could not be analyzed."""


class ArtifactExtractionError(ArtifactInspectionError):
    """Indicate that an artifact payload could not be extracted safely."""


class ExternalToolError(FileNotFoundError, ValueError, WhatYouShipError):
    """Indicate that an external tool required by an operation is unavailable.

    The built-in bases preserve the historical low-level contracts: tool lookup
    raised :class:`FileNotFoundError`, while inspectors exposed :class:`ValueError`.
    """


class ConfigurationError(ValueError, WhatYouShipError):
    """Indicate that an explicit lint configuration could not be loaded."""
