# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Select the platform backend for release artifact signature verification."""

import sys
from pathlib import Path

from whatyouship.model import ArtifactSignature


class MsiSignatureInspector:
    """Verify an MSI package signature when the platform supports it."""

    def inspect(self, source_path: Path) -> ArtifactSignature:
        """Verify the original package independently of extracted payloads.

        :param source_path: MSI package to verify.
        :returns: The signature status for the release artifact.
        """
        if sys.platform != "win32":
            return ArtifactSignature(status="unsupported")

        from whatyouship.inspectors.windows_authenticode import WindowsAuthenticodeVerifier

        return WindowsAuthenticodeVerifier().verify(source_path)
