# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report invalid macOS application bundle signatures."""

from whatyouship.model import Finding, ReleaseArtifact, Severity


class InvalidAppBundleSignatureRule:
    """Flag bundles whose signature or sealed contents are invalid."""

    rule_id = "invalid-app-bundle-signature"

    def __init__(self, severity: Severity = "error") -> None:
        """Set the severity for invalid bundle signatures.

        :param severity: Severity assigned to findings.
        """
        self.severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Report every invalid application bundle signature.

        :param artifact: Artifact whose bundles should be checked.
        :returns: One finding for each invalid bundle signature.
        """
        return [
            Finding(
                self.rule_id,
                self.severity,
                bundle.relative_path,
                "invalid",
                "Invalid application bundle signature or resource seal.",
            )
            for bundle in artifact.bundles
            if bundle.signature.status == "invalid"
        ]
