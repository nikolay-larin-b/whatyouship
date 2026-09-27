# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report artifacts that support but omit an embedded license agreement."""

from pathlib import Path

from whatyouship.model import Finding, ReleaseArtifact, Severity


class MissingLicenseAgreementRule:
    """Flag artifacts whose format exposes an absent license agreement."""

    rule_id = "missing-license-agreement"

    def __init__(self, severity: Severity = "error") -> None:
        """Set the severity for a missing agreement.

        :param severity: Severity assigned to findings.
        """
        self.severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Report a missing agreement when the metadata is supported.

        :param artifact: Artifact to examine.
        :returns: A finding when an agreement is explicitly absent.
        """
        if artifact.license_agreement_present is not False:
            return []
        return [
            Finding(
                self.rule_id,
                self.severity,
                Path("."),
                "missing",
                "Release artifact does not contain an embedded license agreement.",
            )
        ]
