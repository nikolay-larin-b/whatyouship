# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report unsigned executable and library binaries."""

from whatyouship.model import Finding, ReleaseArtifact, Severity


class UnsignedBinaryRule:
    """Report executables and libraries without embedded signatures."""

    def __init__(self, severity: Severity = "warning") -> None:
        """Store the severity used by this rule.

        :param severity: Severity of reported findings.
        """
        self._severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Find unsigned executable and library binaries.

        :param artifact: Artifact whose files should be checked.
        :returns: One finding for each unsigned executable or library.
        """
        findings = []
        for file in artifact.files:
            binary = file.binary
            if (
                binary is not None
                and binary.kind in {"executable", "library"}
                and binary.signature is not None
                and binary.signature.present is False
            ):
                findings.append(
                    Finding(
                        rule_id="unsigned-binary",
                        severity=self._severity,
                        relative_path=file.relative_path,
                        message=f"Unsigned {binary.kind}.",
                    )
                )
        return findings
