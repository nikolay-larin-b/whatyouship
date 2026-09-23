# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Format-independent models for release artifacts."""

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal


Severity = Literal["warning", "error"]
ArtifactSignatureStatus = Literal["unsupported", "unsigned", "valid", "invalid"]
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
    """

    status: ArtifactSignatureStatus = "unsupported"
    signer: str | None = None
    timestamp: datetime | None = None


@dataclass
class SignatureMetadata:
    """Describe a binary signature without assuming a specific format.

    :param present: Whether an embedded signature is present, or ``None`` if unknown.
    :param valid: Whether signature verification succeeded, or ``None`` if unknown.
    :param signer: Signer certificate subject, when available.
    :param timestamp: Whether a timestamp is present, or ``None`` if unknown.
    """

    present: bool | None
    valid: bool | None = None
    signer: str | None = None
    timestamp: bool | None = None


@dataclass
class BinaryMetadata:
    """Describe identified binary properties without format-specific fields.

    :param format: Binary file format.
    :param architecture: Target architecture.
    :param kind: Executable, library, or other binary kind.
    :param file_version: Embedded file version, when available.
    :param product_version: Embedded product version, when available.
    :param signature: Embedded signature metadata, when available.
    """

    format: str
    architecture: str
    kind: str
    file_version: str | None = None
    product_version: str | None = None
    signature: SignatureMetadata | None = None


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


@dataclass
class ReleaseArtifact:
    """Describe a release artifact and the files it contains.

    :param source_path: Path to the original artifact being analyzed.
    :param files: Files contained in the artifact.
    :param signature: Signature of the release artifact itself.
    :param installation_scope: Installation context metadata, when supported.
    """

    source_path: Path
    files: list[ArtifactFile] = field(default_factory=list)
    signature: ArtifactSignature = field(default_factory=ArtifactSignature)
    installation_scope: InstallationScope | None = None


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
