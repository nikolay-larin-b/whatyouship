# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report untrusted macOS application bundle signatures."""

from whatyouship.model import Finding, ReleaseArtifact, Severity


class UntrustedAppBundleSignatureRule:
    """Flag valid bundle signatures without an Apple-trusted identity."""

    rule_id = "untrusted-app-bundle-signature"

    def __init__(self, severity: Severity = "warning") -> None:
        """Set the severity for untrusted bundle signatures.

        :param severity: Severity assigned to findings.
        """
        self.severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Report every untrusted application bundle signature.

        :param artifact: Artifact whose bundles should be checked.
        :returns: One finding for each untrusted bundle signature.
        """
        return [
            Finding(
                self.rule_id,
                self.severity,
                bundle.relative_path,
                "untrusted",
                "Untrusted application bundle signature.",
            )
            for bundle in artifact.bundles
            if bundle.signature.status == "untrusted"
        ]
