# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Report unsigned PE executables and libraries."""

from whatyouship.model import Finding, ReleaseArtifact


class UnsignedPeRule:
    """Report PE executables and DLLs without embedded signatures."""

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Find unsigned PE executables and DLLs.

        :param artifact: Artifact whose files should be checked.
        :returns: One warning for each unsigned PE executable or DLL.
        """
        findings = []
        for file in artifact.files:
            binary = file.binary
            if (
                binary is not None
                and binary.format == "PE"
                and binary.kind in {"executable", "dll"}
                and binary.signature is not None
                and binary.signature.present is False
            ):
                findings.append(
                    Finding(
                        rule_id="unsigned-pe-binary",
                        severity="warning",
                        relative_path=file.relative_path,
                        message=f"Unsigned PE {binary.kind}.",
                    )
                )
        return findings
