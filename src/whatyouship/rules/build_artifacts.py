# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Detect files with suspicious build artifact extensions."""

from whatyouship.model import Finding, ReleaseArtifact


_BUILD_ARTIFACT_EXTENSIONS = frozenset(
    {".ilk", ".obj", ".iobj", ".ipdb", ".tlog", ".lastbuildstate"}
)


class BuildArtifactRule:
    """Report files whose extension identifies a build artifact."""

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Find suspicious build artifact files.

        :param artifact: Artifact whose files should be checked.
        :returns: One warning for each file with a suspicious extension.
        """
        findings = []
        for file in artifact.files:
            extension = file.relative_path.suffix.lower()
            if extension in _BUILD_ARTIFACT_EXTENSIONS:
                findings.append(
                    Finding(
                        rule_id="build-artifact-extension",
                        severity="warning",
                        relative_path=file.relative_path,
                        message=f"Suspicious build artifact extension: {extension}.",
                    )
                )
        return findings
