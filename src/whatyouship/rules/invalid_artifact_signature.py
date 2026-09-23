# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report release artifacts with invalid digital signatures."""

from pathlib import Path

from whatyouship.model import Finding, ReleaseArtifact, Severity


class InvalidArtifactSignatureRule:
    """Flag artifacts whose own signature is cryptographically invalid."""

    rule_id = "invalid-artifact-signature"

    def __init__(self, severity: Severity = "error") -> None:
        """Set the severity for invalid signatures.

        :param severity: Severity assigned to findings.
        """
        self.severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Report a cryptographically invalid artifact signature.

        :param artifact: Artifact to examine.
        :returns: A finding for an invalid signature, otherwise an empty list.
        """
        if artifact.signature.status != "invalid":
            return []
        return [
            Finding(
                self.rule_id,
                self.severity,
                Path("."),
                "invalid",
                "Invalid release artifact signature.",
            )
        ]
