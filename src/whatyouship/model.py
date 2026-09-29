# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Format-independent models for release artifacts."""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal


Severity = Literal["warning", "error"]
BinarySignatureType = Literal["ad-hoc", "certificate", "mixed"]
ArtifactSignatureStatus = Literal[
    "unsupported", "unsigned", "valid", "untrusted", "invalid"
]
InstallationScopeKind = Literal["per-user", "per-machine", "dual-purpose", "ambiguous"]


@dataclass(frozen=True)
class InstallationScopeConflict:
    """Describe one semantically identified installation scope conflict.

    :param identity: Stable rule-facing identity independent of display text.
    :param message: Human-readable explanation of the conflict.
    """

    identity: str
    message: str


@dataclass
class InstallationScope:
    """Describe an artifact's intended installation context and contradictions.

    :param kind: Statically inferred installation context.
    :param conflicts: Concrete contradictions found in the artifact.
    """

    kind: InstallationScopeKind
    conflicts: tuple[InstallationScopeConflict, ...] = ()


@dataclass
class ArtifactSignature:
    """Describe verification of a release artifact's own signature.

    :param status: Verification result, or ``unsupported`` when not applicable.
    :param signer: Signer certificate subject, when available.
    :param timestamp: Countersignature time, when available.
    :param team_id: Apple code-signing Team ID, when available.
    :param notarization_ticket: Whether a stapled notarization ticket is present.
    """

    status: ArtifactSignatureStatus = "unsupported"
    signer: str | None = None
    timestamp: datetime | None = None
    team_id: str | None = None
    notarization_ticket: bool | None = None


@dataclass(frozen=True)
class BinaryEntitlement:
    """Describe one code-signing entitlement.

    :param key: Entitlement property-list key.
    :param value: Canonical JSON representation of the entitlement value.
    """

    key: str
    value: str


@dataclass
class SignatureMetadata:
    """Describe a binary signature without assuming a specific format.

    :param present: Whether an embedded signature is present, or ``None`` if unknown.
    :param valid: Whether signature verification succeeded, or ``None`` if unknown.
    :param signer: Signer certificate subject, when available.
    :param timestamp: Whether a timestamp is present, or ``None`` if unknown.
    :param signature_type: Ad hoc, certificate, or mixed signature type.
    :param hardened_runtime: Whether every Mach-O slice enables Hardened Runtime.
    :param entitlements: Embedded code-signing entitlements.
    """

    present: bool | None
    valid: bool | None = None
    signer: str | None = None
    timestamp: bool | None = None
    signature_type: BinarySignatureType | None = None
    hardened_runtime: bool | None = None
    entitlements: tuple[BinaryEntitlement, ...] = ()


@dataclass(frozen=True)
class BinaryDependency:
    """Describe one dynamic library dependency declared by a binary.

    :param path: Loader path or absolute library install name.
    :param required: Whether the loader requires the library to be present.
    """

    path: str
    required: bool = True


@dataclass
class BinaryMetadata:
    """Describe identified binary properties without format-specific fields.

    :param format: Binary file format.
    :param architecture: Target architecture.
    :param kind: Executable, library, or other binary kind.
    :param file_version: Embedded file version, when available.
    :param product_version: Embedded product version, when available.
    :param signature: Embedded signature metadata, when available.
    :param minimum_os_version: Minimum operating system version required by
        the binary, when available.
    :param dependencies: Dynamic library dependencies declared by the binary.
    :param runtime_search_paths: Runtime library search paths.
    """

    format: str
    architecture: str
    kind: str
    file_version: str | None = None
    product_version: str | None = None
    signature: SignatureMetadata | None = None
    minimum_os_version: str | None = None
    dependencies: tuple[BinaryDependency, ...] = ()
    runtime_search_paths: tuple[str, ...] = ()


@dataclass
class ArtifactFile:
    """Describe one file contained in a release artifact.

    :param relative_path: Path relative to the root of the release artifact.
    :param size_bytes: File size in bytes.
    :param sha256: SHA-256 digest of the file contents.
    :param binary: Identified binary metadata, when available.
    """

    relative_path: Path
    size_bytes: int
    sha256: str
    binary: BinaryMetadata | None = None


@dataclass(frozen=True)
class BundleIssue:
    """Describe one structural application bundle problem.

    :param identity: Stable rule-facing identity.
    :param message: Human-readable explanation of the problem.
    """

    identity: str
    message: str


@dataclass
class AppBundleMetadata:
    """Describe a macOS application bundle.

    :param relative_path: Bundle path relative to the artifact root.
    :param identifier: ``CFBundleIdentifier`` value.
    :param name: Display name or bundle name.
    :param short_version: User-visible ``CFBundleShortVersionString`` value.
    :param bundle_version: Build ``CFBundleVersion`` value.
    :param executable: ``CFBundleExecutable`` value.
    :param executable_path: Main executable path relative to the artifact root.
    :param minimum_system_version: ``LSMinimumSystemVersion`` value.
    :param package_type: ``CFBundlePackageType`` value.
    :param issues: Structural or metadata problems found in the bundle.
    """

    relative_path: Path
    identifier: str | None = None
    name: str | None = None
    short_version: str | None = None
    bundle_version: str | None = None
    executable: str | None = None
    executable_path: Path | None = None
    minimum_system_version: str | None = None
    package_type: str | None = None
    issues: tuple[BundleIssue, ...] = ()


@dataclass
class ReleaseArtifact:
    """Describe a release artifact and the files it contains.

    :param source_path: Path to the original artifact being analyzed.
    :param files: Files contained in the artifact.
    :param signature: Signature of the release artifact itself.
    :param installation_scope: Installation context metadata, when supported.
    :param license_agreement_present: Whether the artifact embeds a license
        agreement, or ``None`` when the format does not expose that metadata.
    :param bundles: Application bundles found inside the artifact.
    """

    source_path: Path
    files: list[ArtifactFile] = field(default_factory=list)
    signature: ArtifactSignature = field(default_factory=ArtifactSignature)
    installation_scope: InstallationScope | None = None
    license_agreement_present: bool | None = None
    bundles: list[AppBundleMetadata] = field(default_factory=list)


@dataclass
class Finding:
    """Describe a condition reported by a lint rule.

    :param rule_id: Identifier of the rule that reported the finding.
    :param severity: Severity of the finding.
    :param relative_path: Affected file path, or ``.`` for the artifact itself.
    :param identity: Stable semantic identity assigned by the reporting rule.
    :param message: Short description of the condition.
    """

    rule_id: str
    severity: Severity
    relative_path: Path
    identity: str
    message: str
