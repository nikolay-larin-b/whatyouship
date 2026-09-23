# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report contradictory installation scope signals in release artifacts."""

from pathlib import Path

from whatyouship.model import Finding, ReleaseArtifact, Severity


class InconsistentInstallationScopeRule:
    """Report concrete conflicts from a static installation scope assessment."""

    rule_id = "inconsistent-installation-scope"

    def __init__(self, severity: Severity = "warning") -> None:
        """Set the severity for installation scope findings.

        :param severity: Severity assigned to findings.
        """
        self.severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Turn documented scope conflicts into lint findings.

        :param artifact: Artifact to examine.
        :returns: One finding per concrete conflict.
        """
        scope = artifact.installation_scope
        if scope is None:
            return []
        return [
            Finding(
                self.rule_id,
                self.severity,
                Path("."),
                conflict.identity,
                conflict.message,
            )
            for conflict in scope.conflicts
        ]
