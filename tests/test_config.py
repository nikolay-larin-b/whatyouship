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
        self.assertEqual(config.unsigned_binary.severity, "warning")
        self.assertEqual(config.unsigned_artifact.severity, "warning")
        self.assertEqual(config.invalid_artifact_signature.severity, "error")
        self.assertEqual(config.installation_scope.severity, "warning")

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
        self.assertEqual(len(config.rules()), 4)

    def test_artifact_signature_rules_accept_common_settings(self) -> None:
        """Configure enabled state and severity for artifact signature rules."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "config.toml"
            path.write_text(
                "[rules.unsigned-artifact]\nenabled = false\n"
                "[rules.invalid-artifact-signature]\nseverity = 'warning'\n"
            )

            config = load_config(path)

        self.assertFalse(config.unsigned_artifact.enabled)
        self.assertEqual(config.invalid_artifact_signature.severity, "warning")
        self.assertEqual(len(config.rules()), 4)

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
        self.assertEqual(len(config.rules()), 4)

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
