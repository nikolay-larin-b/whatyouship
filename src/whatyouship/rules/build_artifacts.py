# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Detect files and directories with suspicious build artifact extensions."""

from collections.abc import Iterable
from pathlib import Path

from whatyouship.model import Finding, ReleaseArtifact, Severity


DEFAULT_EXTENSIONS = frozenset(
    {".ilk", ".obj", ".iobj", ".ipdb", ".tlog", ".lastbuildstate", ".dsym"}
)


class BuildArtifactRule:
    """Report paths whose extension identifies a build artifact."""

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
        """Find suspicious build artifact files and containing directories.

        :param artifact: Artifact whose files should be checked.
        :returns: One finding for each matching file or directory path.
        """
        matches: dict[tuple[Path, str], None] = {}
        for file in artifact.files:
            for path in (file.relative_path, *file.relative_path.parents):
                extension = path.suffix.lower()
                if extension in self._extensions:
                    matches.setdefault((path, extension), None)
        return [
            Finding(
                rule_id="build-artifact-extension",
                severity=self._severity,
                relative_path=path,
                identity=f"extension:{extension}",
                message=f"Suspicious build artifact extension: {extension}.",
            )
            for path, extension in matches
        ]
