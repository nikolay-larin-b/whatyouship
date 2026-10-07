# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report incompatible binary dependency architectures."""

from whatyouship.model import Finding, ReleaseArtifact, Severity


class IncompatibleBinaryArchitectureRule:
    """Report required bundled libraries that lack an importing architecture."""

    def __init__(self, severity: Severity = "error") -> None:
        """Store the severity used by the rule.

        :param severity: Severity assigned to architecture findings.
        """
        self._severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Convert dependency architecture issues to lint findings.

        :param artifact: Artifact whose application bundles should be checked.
        :returns: One finding for every incompatible bundled dependency.
        """
        return [
            Finding(
                rule_id="incompatible-binary-architecture",
                severity=self._severity,
                relative_path=bundle.relative_path,
                identity=issue.identity,
                message=issue.message,
            )
            for bundle in artifact.bundles
            for issue in bundle.issues
            if issue.rule_id == "incompatible-binary-architecture"
        ]
