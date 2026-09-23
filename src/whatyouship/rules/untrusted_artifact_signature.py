# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report release artifacts signed by an untrusted signer."""

from pathlib import Path

from whatyouship.model import Finding, ReleaseArtifact, Severity


class UntrustedArtifactSignatureRule:
    """Flag artifacts whose signature is intact but not trusted."""

    rule_id = "untrusted-artifact-signature"

    def __init__(self, severity: Severity = "warning") -> None:
        """Set the severity for untrusted signatures.

        :param severity: Severity assigned to findings.
        """
        self.severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Report an artifact signed by an untrusted signer.

        :param artifact: Artifact to examine.
        :returns: A finding for an untrusted signature, otherwise an empty list.
        """
        if artifact.signature.status != "untrusted":
            return []
        return [
            Finding(
                self.rule_id,
                self.severity,
                Path("."),
                "untrusted",
                "Release artifact is signed, but the signer is not trusted.",
            )
        ]
