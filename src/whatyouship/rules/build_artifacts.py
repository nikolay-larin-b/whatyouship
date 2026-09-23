# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Detect files with suspicious build artifact extensions."""

from collections.abc import Iterable

from whatyouship.model import Finding, ReleaseArtifact, Severity


DEFAULT_EXTENSIONS = frozenset(
    {".ilk", ".obj", ".iobj", ".ipdb", ".tlog", ".lastbuildstate"}
)


class BuildArtifactRule:
    """Report files whose extension identifies a build artifact."""

    def __init__(
        self, extensions: Iterable[str] = DEFAULT_EXTENSIONS, severity: Severity = "warning"
    ) -> None:
        """Store the extensions and severity used by this rule.

        :param extensions: File extensions to report.
        :param severity: Severity of reported findings.
        """
        self._extensions = frozenset(extension.lower() for extension in extensions)
        self._severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Find suspicious build artifact files.

        :param artifact: Artifact whose files should be checked.
        :returns: One finding for each file with a configured extension.
        """
        findings = []
        for file in artifact.files:
            extension = file.relative_path.suffix.lower()
            if extension in self._extensions:
                findings.append(
                    Finding(
                        rule_id="build-artifact-extension",
                        severity=self._severity,
                        relative_path=file.relative_path,
                        identity=f"extension:{extension}",
                        message=f"Suspicious build artifact extension: {extension}.",
                    )
                )
        return findings
