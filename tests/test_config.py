# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for explicit TOML lint configuration loading."""

import tempfile
import unittest
from pathlib import Path

from whatyouship.config import LintConfiguration, load_config


class ConfigTests(unittest.TestCase):
    """Verify TOML settings and configuration errors."""

    def test_loads_example_configuration(self) -> None:
        """Load the documented example with supported rule settings."""
        path = Path(__file__).resolve().parents[1] / "examples" / "whatyouship.toml"

        config = load_config(path)

        self.assertTrue(config.build_artifacts.enabled)
        self.assertEqual(config.build_artifacts.severity, "error")
        self.assertIn(".exp", config.build_artifacts.extensions)
        self.assertIn(".lib", config.build_artifacts.extensions)
        self.assertIn(".dsym", config.build_artifacts.extensions)
        self.assertEqual(config.app_bundle.severity, "error")
        self.assertEqual(config.unsigned_app_bundle.severity, "warning")
        self.assertEqual(
            config.untrusted_app_bundle_signature.severity,
            "warning",
        )
        self.assertEqual(config.invalid_app_bundle_signature.severity, "error")
        self.assertEqual(config.incompatible_binary_architecture.severity, "error")
        self.assertEqual(config.debug_entitlement.severity, "error")
        self.assertEqual(config.developer_runtime_search_path.severity, "error")
        self.assertEqual(config.absolute_runtime_search_path.severity, "warning")
        self.assertEqual(config.unsigned_binary.severity, "warning")
        self.assertEqual(config.untrusted_binary_signature.severity, "warning")
        self.assertEqual(config.invalid_binary_signature.severity, "error")
        self.assertEqual(config.unsigned_artifact.severity, "warning")
        self.assertEqual(config.untrusted_artifact_signature.severity, "warning")
        self.assertEqual(config.invalid_artifact_signature.severity, "error")
        self.assertEqual(config.installation_scope.severity, "warning")
        self.assertEqual(config.license_agreement.severity, "error")

    def test_partial_configuration_preserves_rule_defaults(self) -> None:
        """Use default settings for omitted rules and parameters."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text("[rules.build-artifact-extension]\nseverity = 'error'\n")

            config = load_config(path)

        self.assertEqual(config.build_artifacts.severity, "error")
        self.assertIn(".obj", config.build_artifacts.extensions)
        self.assertEqual(config.unsigned_binary, LintConfiguration().unsigned_binary)

    def test_normalizes_extensions_and_disables_rules(self) -> None:
        """Normalize configured extensions and omit disabled rules."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text(
                "[rules.build-artifact-extension]\n"
                "extensions = ['.OBJ', '.LiB']\n"
                "[rules.unsigned-binary]\n"
                "enabled = false\n"
            )

            config = load_config(path)

        self.assertEqual(config.build_artifacts.extensions, frozenset({".obj", ".lib"}))
        self.assertEqual(len(config.rules()), 16)

    def test_artifact_signature_rules_accept_common_settings(self) -> None:
        """Configure enabled state and severity for artifact signature rules."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text(
                "[rules.unsigned-artifact]\nenabled = false\n"
                "[rules.untrusted-artifact-signature]\nseverity = 'error'\n"
                "[rules.invalid-artifact-signature]\nseverity = 'warning'\n"
            )

            config = load_config(path)

        self.assertFalse(config.unsigned_artifact.enabled)
        self.assertEqual(config.untrusted_artifact_signature.severity, "error")
        self.assertEqual(config.invalid_artifact_signature.severity, "warning")
        self.assertEqual(len(config.rules()), 16)

    def test_installation_scope_rule_accepts_common_settings(self) -> None:
        """Configure the new scope rule through the existing TOML format."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text(
                "[rules.inconsistent-installation-scope]\n"
                "enabled = false\nseverity = 'error'\n"
            )

            config = load_config(path)

        self.assertFalse(config.installation_scope.enabled)
        self.assertEqual(config.installation_scope.severity, "error")
        self.assertEqual(len(config.rules()), 16)

    def test_license_agreement_rule_accepts_common_settings(self) -> None:
        """Allow the missing agreement rule to be downgraded or disabled."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text(
                "[rules.missing-license-agreement]\n"
                "enabled = false\nseverity = 'warning'\n"
            )

            config = load_config(path)

        self.assertFalse(config.license_agreement.enabled)
        self.assertEqual(config.license_agreement.severity, "warning")
        self.assertEqual(len(config.rules()), 16)

    def test_app_bundle_signature_rules_accept_common_settings(self) -> None:
        """Configure all application bundle signature findings."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text(
                "[rules.unsigned-app-bundle]\nenabled = false\n"
                "[rules.untrusted-app-bundle-signature]\nseverity = 'error'\n"
                "[rules.invalid-app-bundle-signature]\nseverity = 'warning'\n"
            )

            config = load_config(path)

        self.assertFalse(config.unsigned_app_bundle.enabled)
        self.assertEqual(config.untrusted_app_bundle_signature.severity, "error")
        self.assertEqual(config.invalid_app_bundle_signature.severity, "warning")
        self.assertEqual(len(config.rules()), 16)

    def test_app_bundle_rule_accepts_common_settings(self) -> None:
        """Allow malformed application bundle findings to be configured."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text(
                "[rules.invalid-app-bundle]\n"
                "enabled = false\nseverity = 'warning'\n"
            )

            config = load_config(path)

        self.assertFalse(config.app_bundle.enabled)
        self.assertEqual(config.app_bundle.severity, "warning")
        self.assertEqual(len(config.rules()), 16)

    def test_binary_architecture_rule_accepts_common_settings(self) -> None:
        """Allow dependency architecture findings to be configured."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text(
                "[rules.incompatible-binary-architecture]\n"
                "enabled = false\nseverity = 'warning'\n"
            )

            config = load_config(path)

        self.assertFalse(config.incompatible_binary_architecture.enabled)
        self.assertEqual(config.incompatible_binary_architecture.severity, "warning")
        self.assertEqual(len(config.rules()), 16)

    def test_debug_entitlement_rule_accepts_common_settings(self) -> None:
        """Allow debugger entitlement findings to be configured."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text(
                "[rules.debug-entitlement]\n"
                "enabled = false\nseverity = 'warning'\n"
            )

            config = load_config(path)

        self.assertFalse(config.debug_entitlement.enabled)
        self.assertEqual(config.debug_entitlement.severity, "warning")
        self.assertEqual(len(config.rules()), 16)

    def test_runtime_search_path_rules_accept_independent_settings(self) -> None:
        """Configure developer and other absolute search paths separately."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text(
                "[rules.developer-runtime-search-path]\n"
                "severity = 'warning'\n"
                "[rules.absolute-runtime-search-path]\n"
                "enabled = false\nseverity = 'error'\n"
            )

            config = load_config(path)

        self.assertEqual(config.developer_runtime_search_path.severity, "warning")
        self.assertFalse(config.absolute_runtime_search_path.enabled)
        self.assertEqual(config.absolute_runtime_search_path.severity, "error")
        self.assertEqual(len(config.rules()), 16)

    def test_missing_file_has_readable_error(self) -> None:
        """Name the missing configuration file in the error."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "missing.toml"

            with self.assertRaisesRegex(FileNotFoundError, "Configuration file does not exist"):
                load_config(path)

    def test_invalid_toml_has_readable_error(self) -> None:
        """Report TOML syntax errors with the file path."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "invalid.toml"
            path.write_text("[rules.build-artifact-extension\n")

            with self.assertRaisesRegex(ValueError, "Invalid TOML in configuration file"):
                load_config(path)

    def test_rejects_unknown_rule_and_invalid_severity(self) -> None:
        """Reject unsupported rule IDs and severity values."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text("[rules.unknown-rule]\nenabled = true\n")
            with self.assertRaisesRegex(ValueError, "Unknown rule ID: unknown-rule"):
                load_config(path)

            path.write_text("[rules.unsigned-binary]\nseverity = 'critical'\n")
            with self.assertRaisesRegex(ValueError, "Invalid severity for rule 'unsigned-binary'"):
                load_config(path)

    def test_rejects_invalid_rule_settings(self) -> None:
        """Reject mistyped booleans, extensions, and unsupported settings."""
        cases = (
            ("enabled = 'yes'", "enabled must be a boolean"),
            ("extensions = ['obj']", "extensions must be a list"),
            ("extensions = '.obj'", "extensions must be a list"),
            ("unknown = true", "Unknown setting"),
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            for setting, message in cases:
                with self.subTest(setting=setting):
                    path.write_text(f"[rules.build-artifact-extension]\n{setting}\n")
                    with self.assertRaisesRegex(ValueError, message):
                        load_config(path)


if __name__ == "__main__":
    unittest.main()
