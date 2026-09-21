# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Load and validate lint rule settings from an explicit TOML file."""

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

from whatyouship.lint import LintRule
from whatyouship.model import Severity
from whatyouship.rules.build_artifacts import DEFAULT_EXTENSIONS, BuildArtifactRule
from whatyouship.rules.inconsistent_installation_scope import InconsistentInstallationScopeRule
from whatyouship.rules.invalid_artifact_signature import InvalidArtifactSignatureRule
from whatyouship.rules.unsigned_artifact import UnsignedArtifactRule
from whatyouship.rules.unsigned_binary import UnsignedBinaryRule


@dataclass(frozen=True)
class BuildArtifactSettings:
    """Configure the build artifact extension rule.

    :param enabled: Whether to run the rule.
    :param severity: Severity assigned to its findings.
    :param extensions: File extensions reported by the rule.
    """

    enabled: bool = True
    severity: Severity = "warning"
    extensions: frozenset[str] = DEFAULT_EXTENSIONS


@dataclass(frozen=True)
class UnsignedBinarySettings:
    """Configure the unsigned binary rule.

    :param enabled: Whether to run the rule.
    :param severity: Severity assigned to its findings.
    """

    enabled: bool = True
    severity: Severity = "warning"


@dataclass(frozen=True)
class ArtifactSignatureRuleSettings:
    """Configure a release artifact signature rule.

    :param enabled: Whether to run the rule.
    :param severity: Severity assigned to its findings.
    """

    enabled: bool = True
    severity: Severity = "warning"


@dataclass(frozen=True)
class InstallationScopeSettings:
    """Configure the installation scope consistency rule.

    :param enabled: Whether to run the rule.
    :param severity: Severity assigned to its findings.
    """

    enabled: bool = True
    severity: Severity = "warning"


@dataclass(frozen=True)
class LintConfiguration:
    """Collect settings for the available lint rules.

    :param build_artifacts: Build artifact extension rule settings.
    :param unsigned_binary: Unsigned binary rule settings.
    :param unsigned_artifact: Unsigned release artifact rule settings.
    :param invalid_artifact_signature: Invalid artifact signature rule settings.
    :param installation_scope: Installation scope rule settings.
    """

    build_artifacts: BuildArtifactSettings = field(default_factory=BuildArtifactSettings)
    unsigned_binary: UnsignedBinarySettings = field(default_factory=UnsignedBinarySettings)
    unsigned_artifact: ArtifactSignatureRuleSettings = field(
        default_factory=ArtifactSignatureRuleSettings
    )
    invalid_artifact_signature: ArtifactSignatureRuleSettings = field(
        default_factory=lambda: ArtifactSignatureRuleSettings(severity="error")
    )
    installation_scope: InstallationScopeSettings = field(
        default_factory=InstallationScopeSettings
    )

    def rules(self) -> list[LintRule]:
        """Create the enabled lint rules in their usual order.

        :returns: Configured rules for a lint engine.
        """
        rules: list[LintRule] = []
        if self.build_artifacts.enabled:
            rules.append(
                BuildArtifactRule(
                    extensions=self.build_artifacts.extensions,
                    severity=self.build_artifacts.severity,
                )
            )
        if self.unsigned_binary.enabled:
            rules.append(UnsignedBinaryRule(severity=self.unsigned_binary.severity))
        if self.unsigned_artifact.enabled:
            rules.append(UnsignedArtifactRule(severity=self.unsigned_artifact.severity))
        if self.invalid_artifact_signature.enabled:
            rules.append(
                InvalidArtifactSignatureRule(
                    severity=self.invalid_artifact_signature.severity
                )
            )
        if self.installation_scope.enabled:
            rules.append(
                InconsistentInstallationScopeRule(
                    severity=self.installation_scope.severity
                )
            )
        return rules


def _validate_keys(values: dict[str, object], allowed: set[str], location: str) -> None:
    """Reject unsupported keys in a configuration table.

    :param values: Table contents to validate.
    :param allowed: Supported keys in the table.
    :param location: Table name for an error message.
    :raises ValueError: If the table contains an unsupported key.
    """
    unknown = set(values) - allowed
    if unknown:
        raise ValueError(f"Unknown setting in {location}: {', '.join(sorted(unknown))}")


def _rule_settings(
    rule_id: str, values: object, allowed: set[str], default_severity: Severity = "warning"
) -> tuple[bool, Severity, dict[str, object]]:
    """Validate common rule settings and return the rule table.

    :param rule_id: ID of the rule being configured.
    :param values: Parsed TOML table for the rule.
    :param allowed: Supported keys for the rule.
    :param default_severity: Severity used when no value is configured.
    :returns: Enabled state, severity, and validated table.
    :raises ValueError: If the table or a setting is invalid.
    """
    if not isinstance(values, dict):
        raise ValueError(f"Rule '{rule_id}' must be a TOML table")
    _validate_keys(values, allowed, f"rule '{rule_id}'")
    enabled = values.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ValueError(f"Rule '{rule_id}' enabled must be a boolean")
    severity = values.get("severity", default_severity)
    if severity not in ("warning", "error"):
        raise ValueError(f"Invalid severity for rule '{rule_id}': {severity!r}")
    return enabled, cast(Severity, severity), values


def _extensions(values: object) -> frozenset[str]:
    """Validate and normalize configured file extensions.

    :param values: Parsed extension list.
    :returns: Lowercase file extensions.
    :raises ValueError: If the setting is not a list of extensions.
    """
    if not isinstance(values, list) or any(
        not isinstance(value, str)
        or len(value) < 2
        or not value.startswith(".")
        or "." in value[1:]
        or any(character.isspace() or character in "/\\" for character in value)
        for value in values
    ):
        raise ValueError(
            "Rule 'build-artifact-extension' extensions must be a list of file extensions"
        )
    return frozenset(value.lower() for value in values)


def load_config(path: Path) -> LintConfiguration:
    """Read and validate a TOML lint configuration file.

    :param path: Explicit configuration file path.
    :returns: Settings for the available lint rules.
    :raises FileNotFoundError: If the configuration file does not exist.
    :raises ValueError: If the TOML or its settings are invalid.
    """
    try:
        with path.open("rb") as stream:
            data = tomllib.load(stream)
    except FileNotFoundError as error:
        raise FileNotFoundError(f"Configuration file does not exist: {path}") from error
    except (tomllib.TOMLDecodeError, UnicodeError) as error:
        raise ValueError(f"Invalid TOML in configuration file '{path}': {error}") from error

    _validate_keys(data, {"rules"}, "configuration")
    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        raise ValueError("Configuration 'rules' must be a TOML table")
    unknown_rules = set(rules) - {
        "build-artifact-extension", "unsigned-binary", "unsigned-artifact",
        "invalid-artifact-signature",
        "inconsistent-installation-scope",
    }
    if unknown_rules:
        raise ValueError(f"Unknown rule ID: {', '.join(sorted(unknown_rules))}")

    build_enabled, build_severity, build_values = _rule_settings(
        "build-artifact-extension",
        rules.get("build-artifact-extension", {}),
        {"enabled", "severity", "extensions"},
    )
    unsigned_enabled, unsigned_severity, _ = _rule_settings(
        "unsigned-binary",
        rules.get("unsigned-binary", {}),
        {"enabled", "severity"},
    )
    artifact_enabled, artifact_severity, _ = _rule_settings(
        "unsigned-artifact", rules.get("unsigned-artifact", {}),
        {"enabled", "severity"},
    )
    invalid_enabled, invalid_severity, _ = _rule_settings(
        "invalid-artifact-signature", rules.get("invalid-artifact-signature", {}),
        {"enabled", "severity"}, "error",
    )
    scope_enabled, scope_severity, _ = _rule_settings(
        "inconsistent-installation-scope",
        rules.get("inconsistent-installation-scope", {}),
        {"enabled", "severity"},
    )
    extensions = (
        _extensions(build_values["extensions"])
        if "extensions" in build_values
        else DEFAULT_EXTENSIONS
    )
    return LintConfiguration(
        build_artifacts=BuildArtifactSettings(build_enabled, build_severity, extensions),
        unsigned_binary=UnsignedBinarySettings(unsigned_enabled, unsigned_severity),
        unsigned_artifact=ArtifactSignatureRuleSettings(
            artifact_enabled, artifact_severity
        ),
        invalid_artifact_signature=ArtifactSignatureRuleSettings(
            invalid_enabled, invalid_severity
        ),
        installation_scope=InstallationScopeSettings(scope_enabled, scope_severity),
    )
