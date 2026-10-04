# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report executable and library binaries with untrusted signatures."""

from whatyouship.model import Finding, ReleaseArtifact, Severity


class UntrustedBinarySignatureRule:
    """Flag valid signatures without a trusted signing identity."""

    rule_id = "untrusted-binary-signature"

    def __init__(self, severity: Severity = "warning") -> None:
        """Set the severity for untrusted signatures.

        :param severity: Severity assigned to findings.
        """
        self.severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Report every valid but untrusted executable or library signature.

        :param artifact: Artifact whose files should be checked.
        :returns: One finding for each untrusted executable or library signature.
        """
        return [
            Finding(
                self.rule_id,
                self.severity,
                file.relative_path,
                "untrusted",
                f"Untrusted {file.binary.kind} signature.",
            )
            for file in artifact.files
            if file.binary is not None
            and file.binary.kind in {"executable", "library"}
            and file.binary.signature is not None
            and file.binary.signature.present is True
            and file.binary.signature.valid is True
            and file.binary.signature.trusted is False
        ]
