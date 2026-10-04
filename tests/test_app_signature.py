# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for native macOS application bundle signature verification."""

import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from whatyouship.inspectors.app_signature import AppSignatureInspector
from whatyouship.model import AppBundleMetadata, ArtifactSignature, ReleaseArtifact
from whatyouship.rules.invalid_app_bundle_signature import (
    InvalidAppBundleSignatureRule,
)
from whatyouship.rules.unsigned_app_bundle import UnsignedAppBundleRule
from whatyouship.rules.untrusted_app_bundle_signature import (
    UntrustedAppBundleSignatureRule,
)


def _result(
    returncode: int,
    stderr: str = "",
) -> SimpleNamespace:
    """Create a minimal completed-process substitute.

    :param returncode: Process exit status.
    :param stderr: Standard error text.
    :returns: Object exposing the fields used by the inspector.
    """
    return SimpleNamespace(returncode=returncode, stdout="", stderr=stderr)


class AppSignatureInspectorTests(unittest.TestCase):
    """Verify ``codesign`` invocation and result classification."""

    def test_reports_valid_signature_metadata(self) -> None:
        """Read the signer, Team ID, and timestamp from native output."""
        display = """Authority=Developer ID Application: Example (TEAM123456)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=29 Sep 2026 at 01:50:28
TeamIdentifier=TEAM123456
"""
        with patch(
            "whatyouship.inspectors.app_signature.sys.platform",
            "darwin",
        ), patch(
            "whatyouship.inspectors.app_signature.shutil.which",
            return_value="codesign",
        ), patch(
            "whatyouship.inspectors.app_signature.subprocess.run",
            side_effect=[_result(0), _result(0), _result(0, display)],
        ) as run:
            signature = AppSignatureInspector().inspect(Path("Sample.app"))

        self.assertEqual(signature.status, "valid")
        self.assertEqual(
            signature.signer,
            "Developer ID Application: Example (TEAM123456)",
        )
        self.assertEqual(signature.team_id, "TEAM123456")
        self.assertEqual(
            signature.timestamp,
            datetime(2026, 9, 29, 1, 50, 28, tzinfo=timezone.utc),
        )
        self.assertEqual(run.call_count, 3)
        integrity_command = run.call_args_list[0].args[0]
        trust_command = run.call_args_list[1].args[0]
        display_command = run.call_args_list[2].args[0]
        self.assertIn("--deep", integrity_command)
        self.assertIn("--strict=all", integrity_command)
        self.assertIn("=anchor apple generic", trust_command)
        self.assertIn("--display", display_command)
        self.assertEqual(run.call_args_list[0].kwargs["env"]["LC_ALL"], "C")
        self.assertEqual(run.call_args_list[0].kwargs["env"]["LANG"], "C")

    def test_distinguishes_untrusted_unsigned_and_invalid_bundles(self) -> None:
        """Map native verification outcomes to stable signature states."""
        cases = (
            (0, 1, "", "untrusted"),
            (1, 1, "code object is not signed at all", "unsigned"),
            (1, 1, "a sealed resource is missing or invalid", "invalid"),
        )
        for integrity, trust, diagnostic, expected in cases:
            with self.subTest(expected=expected), patch(
                "whatyouship.inspectors.app_signature.sys.platform",
                "darwin",
            ), patch(
                "whatyouship.inspectors.app_signature.shutil.which",
                return_value="codesign",
            ), patch(
                "whatyouship.inspectors.app_signature.subprocess.run",
                side_effect=[
                    _result(integrity, diagnostic),
                    _result(trust),
                    _result(0),
                ],
            ):
                signature = AppSignatureInspector().inspect(Path("Sample.app"))

            self.assertEqual(signature.status, expected)

    def test_reports_unsupported_when_codesign_is_unavailable(self) -> None:
        """Avoid guessing bundle signature validity on other platforms."""
        with patch(
            "whatyouship.inspectors.app_signature.sys.platform",
            "darwin",
        ), patch(
            "whatyouship.inspectors.app_signature.shutil.which",
            return_value=None,
        ), patch(
            "whatyouship.inspectors.app_signature.subprocess.run",
        ) as run:
            signature = AppSignatureInspector().inspect(Path("Sample.app"))

        self.assertEqual(signature.status, "unsupported")
        run.assert_not_called()

    def test_reports_unsupported_on_other_operating_systems(self) -> None:
        """Do not invoke a similarly named non-Apple executable."""
        with patch(
            "whatyouship.inspectors.app_signature.sys.platform",
            "linux",
        ), patch(
            "whatyouship.inspectors.app_signature.shutil.which",
        ) as which:
            signature = AppSignatureInspector().inspect(Path("Sample.app"))

        self.assertEqual(signature.status, "unsupported")
        which.assert_not_called()


class AppSignatureRuleTests(unittest.TestCase):
    """Verify lint findings for application bundle signature states."""

    def test_rules_report_only_their_matching_state(self) -> None:
        """Create one finding for each configured signature problem."""
        cases = (
            (UnsignedAppBundleRule("error"), "unsigned", "unsigned-app-bundle"),
            (
                UntrustedAppBundleSignatureRule("error"),
                "untrusted",
                "untrusted-app-bundle-signature",
            ),
            (
                InvalidAppBundleSignatureRule("error"),
                "invalid",
                "invalid-app-bundle-signature",
            ),
        )
        for rule, status, rule_id in cases:
            with self.subTest(status=status):
                artifact = ReleaseArtifact(
                    Path("release.dmg"),
                    bundles=[AppBundleMetadata(
                        Path("Sample.app"),
                        signature=ArtifactSignature(status=status),
                    )],
                )

                findings = rule.check(artifact)

                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].rule_id, rule_id)
                self.assertEqual(findings[0].severity, "error")
                self.assertEqual(findings[0].relative_path, Path("Sample.app"))


if __name__ == "__main__":
    unittest.main()
