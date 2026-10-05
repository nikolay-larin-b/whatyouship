# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report non-portable runtime search paths in release binaries."""

from whatyouship.model import Finding, ReleaseArtifact, Severity


_DEVELOPER_PATH_PREFIXES = (
    "/Users/",
    "/home/",
    "/private/tmp/",
    "/private/var/folders/",
    "/tmp/",
    "/var/folders/",
)
_DEVELOPER_PATHS = {prefix.rstrip("/") for prefix in _DEVELOPER_PATH_PREFIXES}


def _is_developer_path(path: str) -> bool:
    """Identify an absolute path tied to a developer or temporary directory.

    :param path: Runtime search path stored in a binary.
    :returns: Whether the path has a known developer-specific prefix.
    """
    return path in _DEVELOPER_PATHS or path.startswith(_DEVELOPER_PATH_PREFIXES)


class DeveloperRuntimeSearchPathRule:
    """Report runtime search paths tied to build-machine directories."""

    def __init__(self, severity: Severity = "error") -> None:
        """Store the severity used by the rule.

        :param severity: Severity of reported findings.
        """
        self._severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Find runtime search paths tied to developer or temporary directories.

        :param artifact: Artifact whose binaries should be checked.
        :returns: One finding for each developer-specific runtime search path.
        """
        findings = []
        for file in artifact.files:
            if file.binary is None:
                continue
            for path in file.binary.runtime_search_paths:
                if _is_developer_path(path):
                    findings.append(Finding(
                        rule_id="developer-runtime-search-path",
                        severity=self._severity,
                        relative_path=file.relative_path,
                        identity=f"runtime-search-path:{path}",
                        message=(
                            "Runtime search path points into a developer or "
                            f"temporary directory: '{path}'."
                        ),
                    ))
        return findings


class AbsoluteRuntimeSearchPathRule:
    """Report absolute runtime search paths not tied to developer directories."""

    def __init__(self, severity: Severity = "warning") -> None:
        """Store the severity used by the rule.

        :param severity: Severity of reported findings.
        """
        self._severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Find absolute runtime search paths not handled by the stricter rule.

        :param artifact: Artifact whose binaries should be checked.
        :returns: One finding for each remaining absolute runtime search path.
        """
        findings = []
        for file in artifact.files:
            if file.binary is None:
                continue
            for path in file.binary.runtime_search_paths:
                if path.startswith("/") and not _is_developer_path(path):
                    findings.append(Finding(
                        rule_id="absolute-runtime-search-path",
                        severity=self._severity,
                        relative_path=file.relative_path,
                        identity=f"runtime-search-path:{path}",
                        message=(
                            "Absolute runtime search path may make the binary "
                            f"non-portable: '{path}'."
                        ),
                    ))
        return findings
