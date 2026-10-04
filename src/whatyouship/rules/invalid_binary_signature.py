# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report executable and library binaries with invalid signatures."""

from whatyouship.model import Finding, ReleaseArtifact, Severity


class InvalidBinarySignatureRule:
    """Flag binaries whose embedded signature is cryptographically invalid."""

    rule_id = "invalid-binary-signature"

    def __init__(self, severity: Severity = "error") -> None:
        """Set the severity for invalid signatures.

        :param severity: Severity assigned to findings.
        """
        self.severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Report every cryptographically invalid binary signature.

        :param artifact: Artifact whose files should be checked.
        :returns: One finding for each invalid executable or library signature.
        """
        return [
            Finding(
                self.rule_id,
                self.severity,
                file.relative_path,
                "invalid",
                f"Invalid {file.binary.kind} signature.",
            )
            for file in artifact.files
            if file.binary is not None
            and file.binary.kind in {"executable", "library"}
            and file.binary.signature is not None
            and file.binary.signature.present is True
            and file.binary.signature.valid is False
        ]
