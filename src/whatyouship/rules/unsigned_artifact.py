# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report release artifacts that have no digital signature."""

from pathlib import Path

from whatyouship.model import Finding, ReleaseArtifact, Severity


class UnsignedArtifactRule:
    """Flag artifacts whose supported signature check found no signature."""

    rule_id = "unsigned-artifact"

    def __init__(self, severity: Severity = "warning") -> None:
        """Set the severity for unsigned artifacts.

        :param severity: Severity assigned to findings.
        """
        self.severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Report an unsigned artifact when signature checking is supported.

        :param artifact: Artifact to examine.
        :returns: A finding for an unsigned artifact, otherwise an empty list.
        """
        if artifact.signature.status != "unsigned":
            return []
        return [
            Finding(
                self.rule_id,
                self.severity,
                Path("."),
                "unsigned",
                "Unsigned release artifact.",
            )
        ]
