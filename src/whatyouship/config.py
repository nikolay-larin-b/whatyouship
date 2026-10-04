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
from whatyouship.rules.debug_entitlement import DebugEntitlementRule
from whatyouship.rules.inconsistent_installation_scope import InconsistentInstallationScopeRule
from whatyouship.rules.invalid_app_bundle import InvalidAppBundleRule
from whatyouship.rules.invalid_app_bundle_signature import InvalidAppBundleSignatureRule
from whatyouship.rules.invalid_artifact_signature import InvalidArtifactSignatureRule
from whatyouship.rules.invalid_binary_signature import InvalidBinarySignatureRule
from whatyouship.rules.missing_license_agreement import MissingLicenseAgreementRule
from whatyouship.rules.untrusted_artifact_signature import UntrustedArtifactSignatureRule
from whatyouship.rules.untrusted_app_bundle_signature import UntrustedAppBundleSignatureRule
from whatyouship.rules.untrusted_binary_signature import UntrustedBinarySignatureRule
from whatyouship.rules.unsigned_artifact import UnsignedArtifactRule
from whatyouship.rules.unsigned_app_bundle import UnsignedAppBundleRule
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
class AppBundleSettings:
    """Configure the invalid application bundle rule.

    :param enabled: Whether to run the rule.
    :param severity: Severity assigned to its findings.
    """

    enabled: bool = True
    severity: Severity = "error"


@dataclass(frozen=True)
class DebugEntitlementSettings:
    """Configure the debug entitlement rule.

    :param enabled: Whether to run the rule.
    :param severity: Severity assigned to its findings.
    """

    enabled: bool = True
    severity: Severity = "error"


@dataclass(frozen=True)
class ArtifactSignatureRuleSettings:
    """Configure an artifact or application signature rule.

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
class LicenseAgreementSettings:
    """Configure the missing license agreement rule.

    :param enabled: Whether to run the rule.
    :param severity: Severity assigned to its findings.
    """

    enabled: bool = True
    severity: Severity = "error"


@dataclass(frozen=True)
class LintConfiguration:
    """Collect settings for the available lint rules.

    :param build_artifacts: Build artifact extension rule settings.
    :param app_bundle: Invalid application bundle rule settings.
    :param unsigned_app_bundle: Unsigned application bundle settings.
    :param untrusted_app_bundle_signature: Untrusted bundle signature settings.
    :param invalid_app_bundle_signature: Invalid bundle signature settings.
    :param debug_entitlement: Debug entitlement rule settings.
    :param unsigned_binary: Unsigned binary rule settings.
    :param untrusted_binary_signature: Untrusted binary signature settings.
    :param invalid_binary_signature: Invalid binary signature rule settings.
    :param unsigned_artifact: Unsigned release artifact rule settings.
    :param untrusted_artifact_signature: Untrusted artifact signature settings.
    :param invalid_artifact_signature: Invalid artifact signature rule settings.
    :param installation_scope: Installation scope rule settings.
    :param license_agreement: Missing license agreement rule settings.
    """

    build_artifacts: BuildArtifactSettings = field(default_factory=BuildArtifactSettings)
    app_bundle: AppBundleSettings = field(default_factory=AppBundleSettings)
    unsigned_app_bundle: ArtifactSignatureRuleSettings = field(
        default_factory=ArtifactSignatureRuleSettings
    )
    untrusted_app_bundle_signature: ArtifactSignatureRuleSettings = field(
        default_factory=ArtifactSignatureRuleSettings
    )
    invalid_app_bundle_signature: ArtifactSignatureRuleSettings = field(
        default_factory=lambda: ArtifactSignatureRuleSettings(severity="error")
    )
    debug_entitlement: DebugEntitlementSettings = field(
        default_factory=DebugEntitlementSettings
    )
    unsigned_binary: UnsignedBinarySettings = field(default_factory=UnsignedBinarySettings)
    untrusted_binary_signature: ArtifactSignatureRuleSettings = field(
        default_factory=ArtifactSignatureRuleSettings
    )
    invalid_binary_signature: ArtifactSignatureRuleSettings = field(
        default_factory=lambda: ArtifactSignatureRuleSettings(severity="error")
    )
    unsigned_artifact: ArtifactSignatureRuleSettings = field(
        default_factory=ArtifactSignatureRuleSettings
    )
    untrusted_artifact_signature: ArtifactSignatureRuleSettings = field(
        default_factory=ArtifactSignatureRuleSettings
    )
    invalid_artifact_signature: ArtifactSignatureRuleSettings = field(
        default_factory=lambda: ArtifactSignatureRuleSettings(severity="error")
    )
    installation_scope: InstallationScopeSettings = field(
        default_factory=InstallationScopeSettings
    )
    license_agreement: LicenseAgreementSettings = field(
        default_factory=LicenseAgreementSettings
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
        if self.app_bundle.enabled:
            rules.append(
                InvalidAppBundleRule(severity=self.app_bundle.severity)
            )
        if self.unsigned_app_bundle.enabled:
            rules.append(UnsignedAppBundleRule(
                severity=self.unsigned_app_bundle.severity
            ))
        if self.untrusted_app_bundle_signature.enabled:
            rules.append(UntrustedAppBundleSignatureRule(
                severity=self.untrusted_app_bundle_signature.severity
            ))
        if self.invalid_app_bundle_signature.enabled:
            rules.append(InvalidAppBundleSignatureRule(
                severity=self.invalid_app_bundle_signature.severity
            ))
        if self.debug_entitlement.enabled:
            rules.append(DebugEntitlementRule(
                severity=self.debug_entitlement.severity
            ))
        if self.unsigned_binary.enabled:
            rules.append(UnsignedBinaryRule(severity=self.unsigned_binary.severity))
        if self.untrusted_binary_signature.enabled:
            rules.append(UntrustedBinarySignatureRule(
                severity=self.untrusted_binary_signature.severity
            ))
        if self.invalid_binary_signature.enabled:
            rules.append(InvalidBinarySignatureRule(
                severity=self.invalid_binary_signature.severity
            ))
        if self.unsigned_artifact.enabled:
            rules.append(UnsignedArtifactRule(severity=self.unsigned_artifact.severity))
        if self.untrusted_artifact_signature.enabled:
            rules.append(
                UntrustedArtifactSignatureRule(
                    severity=self.untrusted_artifact_signature.severity
                )
            )
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
        if self.license_agreement.enabled:
            rules.append(
                MissingLicenseAgreementRule(
                    severity=self.license_agreement.severity
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
        "untrusted-binary-signature", "invalid-binary-signature",
        "untrusted-artifact-signature", "invalid-artifact-signature",
        "inconsistent-installation-scope", "missing-license-agreement",
        "invalid-app-bundle",
        "unsigned-app-bundle", "untrusted-app-bundle-signature",
        "invalid-app-bundle-signature",
        "debug-entitlement",
    }
    if unknown_rules:
        raise ValueError(f"Unknown rule ID: {', '.join(sorted(unknown_rules))}")

    build_enabled, build_severity, build_values = _rule_settings(
        "build-artifact-extension",
        rules.get("build-artifact-extension", {}),
        {"enabled", "severity", "extensions"},
    )
    bundle_enabled, bundle_severity, _ = _rule_settings(
        "invalid-app-bundle",
        rules.get("invalid-app-bundle", {}),
        {"enabled", "severity"},
        "error",
    )
    unsigned_bundle_enabled, unsigned_bundle_severity, _ = _rule_settings(
        "unsigned-app-bundle",
        rules.get("unsigned-app-bundle", {}),
        {"enabled", "severity"},
    )
    untrusted_bundle_enabled, untrusted_bundle_severity, _ = _rule_settings(
        "untrusted-app-bundle-signature",
        rules.get("untrusted-app-bundle-signature", {}),
        {"enabled", "severity"},
    )
    invalid_bundle_enabled, invalid_bundle_severity, _ = _rule_settings(
        "invalid-app-bundle-signature",
        rules.get("invalid-app-bundle-signature", {}),
        {"enabled", "severity"},
        "error",
    )
    debug_enabled, debug_severity, _ = _rule_settings(
        "debug-entitlement",
        rules.get("debug-entitlement", {}),
        {"enabled", "severity"},
        "error",
    )
    unsigned_enabled, unsigned_severity, _ = _rule_settings(
        "unsigned-binary",
        rules.get("unsigned-binary", {}),
        {"enabled", "severity"},
    )
    untrusted_binary_enabled, untrusted_binary_severity, _ = _rule_settings(
        "untrusted-binary-signature",
        rules.get("untrusted-binary-signature", {}),
        {"enabled", "severity"},
    )
    invalid_binary_enabled, invalid_binary_severity, _ = _rule_settings(
        "invalid-binary-signature",
        rules.get("invalid-binary-signature", {}),
        {"enabled", "severity"},
        "error",
    )
    artifact_enabled, artifact_severity, _ = _rule_settings(
        "unsigned-artifact", rules.get("unsigned-artifact", {}),
        {"enabled", "severity"},
    )
    untrusted_enabled, untrusted_severity, _ = _rule_settings(
        "untrusted-artifact-signature",
        rules.get("untrusted-artifact-signature", {}),
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
    license_enabled, license_severity, _ = _rule_settings(
        "missing-license-agreement",
        rules.get("missing-license-agreement", {}),
        {"enabled", "severity"},
        "error",
    )
    extensions = (
        _extensions(build_values["extensions"])
        if "extensions" in build_values
        else DEFAULT_EXTENSIONS
    )
    return LintConfiguration(
        build_artifacts=BuildArtifactSettings(build_enabled, build_severity, extensions),
        app_bundle=AppBundleSettings(bundle_enabled, bundle_severity),
        unsigned_app_bundle=ArtifactSignatureRuleSettings(
            unsigned_bundle_enabled, unsigned_bundle_severity
        ),
        untrusted_app_bundle_signature=ArtifactSignatureRuleSettings(
            untrusted_bundle_enabled, untrusted_bundle_severity
        ),
        invalid_app_bundle_signature=ArtifactSignatureRuleSettings(
            invalid_bundle_enabled, invalid_bundle_severity
        ),
        debug_entitlement=DebugEntitlementSettings(
            debug_enabled, debug_severity
        ),
        unsigned_binary=UnsignedBinarySettings(unsigned_enabled, unsigned_severity),
        untrusted_binary_signature=ArtifactSignatureRuleSettings(
            untrusted_binary_enabled, untrusted_binary_severity
        ),
        invalid_binary_signature=ArtifactSignatureRuleSettings(
            invalid_binary_enabled, invalid_binary_severity
        ),
        unsigned_artifact=ArtifactSignatureRuleSettings(
            artifact_enabled, artifact_severity
        ),
        untrusted_artifact_signature=ArtifactSignatureRuleSettings(
            untrusted_enabled, untrusted_severity
        ),
        invalid_artifact_signature=ArtifactSignatureRuleSettings(
            invalid_enabled, invalid_severity
        ),
        installation_scope=InstallationScopeSettings(scope_enabled, scope_severity),
        license_agreement=LicenseAgreementSettings(
            license_enabled, license_severity
        ),
    )
