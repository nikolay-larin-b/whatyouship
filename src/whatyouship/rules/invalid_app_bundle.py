# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report malformed macOS application bundles."""

from whatyouship.model import Finding, ReleaseArtifact, Severity


class InvalidAppBundleRule:
    """Report structural and metadata problems in ``.app`` bundles."""

    def __init__(self, severity: Severity = "error") -> None:
        """Store the severity used by the rule.

        :param severity: Severity assigned to bundle findings.
        """
        self._severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Convert application bundle issues to lint findings.

        :param artifact: Artifact whose application bundles should be checked.
        :returns: One finding for every bundle issue.
        """
        return [
            Finding(
                rule_id="invalid-app-bundle",
                severity=self._severity,
                relative_path=bundle.relative_path,
                identity=issue.identity,
                message=issue.message,
            )
            for bundle in artifact.bundles
            for issue in bundle.issues
        ]
