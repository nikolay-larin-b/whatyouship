# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report unsigned macOS application bundles."""

from whatyouship.model import Finding, ReleaseArtifact, Severity


class UnsignedAppBundleRule:
    """Flag application bundles without a code signature."""

    rule_id = "unsigned-app-bundle"

    def __init__(self, severity: Severity = "warning") -> None:
        """Set the severity for unsigned bundles.

        :param severity: Severity assigned to findings.
        """
        self.severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Report every unsigned application bundle.

        :param artifact: Artifact whose bundles should be checked.
        :returns: One finding for each unsigned bundle.
        """
        return [
            Finding(
                self.rule_id,
                self.severity,
                bundle.relative_path,
                "unsigned",
                "Unsigned application bundle.",
            )
            for bundle in artifact.bundles
            if bundle.signature.status == "unsigned"
        ]
