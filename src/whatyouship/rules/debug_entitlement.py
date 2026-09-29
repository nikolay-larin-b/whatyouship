# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report debugger entitlements in release binaries."""

from whatyouship.model import Finding, ReleaseArtifact, Severity


_DEBUG_ENTITLEMENTS = {
    "com.apple.security.get-task-allow",
    "get-task-allow",
}


class DebugEntitlementRule:
    """Report Mach-O binaries that allow a debugger to attach."""

    def __init__(self, severity: Severity = "error") -> None:
        """Store the severity used by the rule.

        :param severity: Severity assigned to debug entitlement findings.
        """
        self._severity = severity

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Find enabled debug entitlements in recognized binaries.

        :param artifact: Artifact whose binaries should be checked.
        :returns: One finding for every enabled debug entitlement.
        """
        findings = []
        for file in artifact.files:
            binary = file.binary
            signature = binary.signature if binary is not None else None
            if signature is None:
                continue
            for entitlement in signature.entitlements:
                if (
                    entitlement.key in _DEBUG_ENTITLEMENTS
                    and entitlement.value == "true"
                ):
                    findings.append(Finding(
                        rule_id="debug-entitlement",
                        severity=self._severity,
                        relative_path=file.relative_path,
                        identity=f"entitlement:{entitlement.key}",
                        message=(
                            f"Debug entitlement '{entitlement.key}' is enabled."
                        ),
                    ))
        return findings
