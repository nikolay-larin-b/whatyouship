# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Verify DMG signatures with static, native, and cross-platform checks."""

import hashlib
import os
import shutil
import struct
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from whatyouship.model import ArtifactSignature, ArtifactSignatureStatus


_KOLY_SIZE = 512
_KOLY_SIGNATURE_OFFSET = 296
_KOLY_SIGNATURE_SIZE_OFFSET = 304
_MAX_SIGNATURE_SIZE = 64 * 1024 * 1024
_CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
_CSMAGIC_CODEDIRECTORY = 0xFADE0C02
_CSMAGIC_BLOBWRAPPER = 0xFADE0B01
_CSSLOT_CODEDIRECTORY = 0
_CSSLOT_SIGNATURE = 0x10000
_CSSLOT_TICKET = 0x10002
_DIGESTS = {
    1: ("sha1", 20),
    2: ("sha256", 32),
    3: ("sha256", 20),
    4: ("sha384", 48),
}


class _UnsupportedDmg(ValueError):
    """Indicate that a file has no readable DMG trailer."""


@dataclass(frozen=True)
class _DmgCodeSignature:
    """Hold statically validated DMG code-signature metadata."""

    code_directory: bytes
    content_valid: bool
    team_id: str | None
    ticket_present: bool
    cms_present: bool


@dataclass(frozen=True)
class _RcodesignMetadata:
    """Hold the subset of ``rcodesign`` YAML needed for verification."""

    cms_valid: bool
    code_directory_digest: str | None
    digest_algorithm: str | None
    signer: str | None
    trusted: bool
    timestamp: datetime | None
    timestamp_valid: bool


@dataclass(frozen=True)
class _CodesignMetadata:
    """Hold native macOS verification metadata for a signed DMG."""

    status: ArtifactSignatureStatus
    signer: str | None
    timestamp: datetime | None
    team_id: str | None


def _blob_header(content: bytes, offset: int) -> tuple[int, int] | None:
    """Read and validate an Apple code-signing blob header.

    :param content: Complete signature superblob.
    :param offset: Blob offset inside the superblob.
    :returns: Magic and length, or ``None`` for an invalid blob.
    """
    if offset < 0 or offset + 8 > len(content):
        return None
    magic, length = struct.unpack_from(">II", content, offset)
    if length < 8 or offset + length > len(content):
        return None
    return magic, length


def _superblob_entries(content: bytes) -> tuple[tuple[int, int, int, int], ...] | None:
    """Read bounded slot records from a DMG signature superblob.

    :param content: Complete signature superblob.
    :returns: Slot, offset, magic, and length records, or ``None`` if malformed.
    """
    header = _blob_header(content, 0)
    if (
        header is None
        or header[0] != _CSMAGIC_EMBEDDED_SIGNATURE
        or header[1] < 12
        or header[1] != len(content)
    ):
        return None
    length = header[1]
    count = struct.unpack_from(">I", content, 8)[0]
    if count > (length - 12) // 8:
        return None
    index_end = 12 + count * 8
    entries = []
    for index in range(count):
        slot, offset = struct.unpack_from(">II", content, 12 + index * 8)
        blob = _blob_header(content, offset)
        if blob is None or offset < index_end or offset + blob[1] > length:
            return None
        entries.append((slot, offset, blob[0], blob[1]))
    return tuple(entries)


def _null_terminated_text(content: bytes, offset: int) -> str | None:
    """Read a bounded UTF-8 string from a CodeDirectory blob.

    :param content: Complete CodeDirectory blob.
    :param offset: String offset inside the blob.
    :returns: Decoded string, or ``None`` when invalid.
    """
    if offset <= 0 or offset >= len(content):
        return None
    end = content.find(b"\x00", offset)
    if end < 0:
        return None
    try:
        return content[offset:end].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _validate_code_directory(
    source_path: Path,
    trailer: bytes,
    signature_offset: int,
    code_directory: bytes,
) -> tuple[bool, str | None]:
    """Validate DMG content and trailer digests recorded by CodeDirectory.

    :param source_path: DMG whose signed bytes should be hashed.
    :param trailer: Raw 512-byte ``koly`` trailer.
    :param signature_offset: Start of the signature superblob.
    :param code_directory: Primary CodeDirectory blob.
    :returns: Digest validity and embedded Team ID.
    """
    if len(code_directory) < 44:
        return False, None
    (
        magic,
        length,
        version,
        _flags,
        digest_offset,
        _identifier_offset,
        special_count,
        code_count,
        code_limit,
        digest_size,
        digest_type,
        _platform,
        _page_size,
        _spare,
    ) = struct.unpack_from(">9I4BI", code_directory, 0)
    if magic != _CSMAGIC_CODEDIRECTORY or length != len(code_directory):
        return False, None
    digest = _DIGESTS.get(digest_type)
    if digest is None or digest_size != digest[1] or code_count != 1:
        return False, None
    if code_limit != signature_offset or digest_offset > length:
        return False, None
    first_digest = digest_offset - special_count * digest_size
    digest_end = digest_offset + code_count * digest_size
    if first_digest < 0 or digest_end > length:
        return False, None

    team_id = None
    if version >= 0x20200:
        if len(code_directory) < 52:
            return False, None
        team_id = _null_terminated_text(
            code_directory, struct.unpack_from(">I", code_directory, 48)[0]
        )

    hasher = hashlib.new(digest[0])
    with source_path.open("rb") as stream:
        remaining = signature_offset
        while remaining:
            chunk = stream.read(min(1024 * 1024, remaining))
            if not chunk:
                return False, team_id
            hasher.update(chunk)
            remaining -= len(chunk)
    expected_content = code_directory[digest_offset:digest_offset + digest_size]
    content_valid = hasher.digest()[:digest_size] == expected_content

    trailer_copy = bytearray(trailer)
    plist_offset, plist_length = struct.unpack_from(">QQ", trailer_copy, 216)
    struct.pack_into(
        ">Q",
        trailer_copy,
        _KOLY_SIGNATURE_OFFSET,
        plist_offset + plist_length,
    )
    struct.pack_into(">Q", trailer_copy, _KOLY_SIGNATURE_SIZE_OFFSET, 0)
    rep_specific_valid = False
    if special_count >= 6:
        rep_specific_offset = digest_offset - 6 * digest_size
        expected_trailer = code_directory[
            rep_specific_offset:rep_specific_offset + digest_size
        ]
        trailer_digest = hashlib.new(digest[0], trailer_copy).digest()[:digest_size]
        rep_specific_valid = trailer_digest == expected_trailer
    return content_valid and rep_specific_valid, team_id


def _read_signature(source_path: Path) -> _DmgCodeSignature | None:
    """Read and statically validate an embedded DMG signature.

    :param source_path: DMG artifact to inspect.
    :returns: Signature metadata, or ``None`` for an unsigned image.
    :raises ValueError: If the trailer or embedded signature is malformed.
    """
    size = source_path.stat().st_size
    if size < _KOLY_SIZE:
        raise _UnsupportedDmg("DMG is too small to contain a koly trailer")
    with source_path.open("rb") as stream:
        stream.seek(-_KOLY_SIZE, os.SEEK_END)
        trailer = stream.read(_KOLY_SIZE)
        if len(trailer) != _KOLY_SIZE or trailer[:4] != b"koly":
            raise _UnsupportedDmg("DMG has no valid koly trailer")
        signature_offset, signature_size = struct.unpack_from(">QQ", trailer, 296)
        if signature_offset == 0 and signature_size == 0:
            return None
        if (
            signature_offset == 0
            or signature_size == 0
            or signature_size > _MAX_SIGNATURE_SIZE
            or signature_offset + signature_size + _KOLY_SIZE != size
        ):
            raise ValueError("DMG code-signature range is invalid")
        stream.seek(signature_offset)
        content = stream.read(signature_size)
    if len(content) != signature_size:
        raise ValueError("DMG code signature is truncated")
    entries = _superblob_entries(content)
    if entries is None:
        raise ValueError("DMG code-signature superblob is malformed")
    code_directories = [
        content[offset:offset + length]
        for slot, offset, magic, length in entries
        if slot == _CSSLOT_CODEDIRECTORY and magic == _CSMAGIC_CODEDIRECTORY
    ]
    if len(code_directories) != 1:
        raise ValueError("DMG signature has no unique primary CodeDirectory")
    content_valid, team_id = _validate_code_directory(
        source_path, trailer, signature_offset, code_directories[0]
    )
    return _DmgCodeSignature(
        code_directory=code_directories[0],
        content_valid=content_valid,
        team_id=team_id,
        ticket_present=any(
            slot == _CSSLOT_TICKET
            and magic == _CSMAGIC_BLOBWRAPPER
            and length > 8
            for slot, _offset, magic, length in entries
        ),
        cms_present=any(
            slot == _CSSLOT_SIGNATURE
            and magic == _CSMAGIC_BLOBWRAPPER
            and length > 8
            for slot, _offset, magic, length in entries
        ),
    )


def _parse_codesign_time(value: str) -> datetime | None:
    """Parse the stable C-locale timestamp emitted by ``codesign``.

    ``codesign`` displays signing times in UTC but omits the zone suffix.

    :param value: Timestamp text from verbose signature output.
    :returns: UTC timestamp, or ``None`` when the value is unrecognized.
    """
    months = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
    }
    parts = value.split()
    if len(parts) != 5 or parts[3] != "at" or parts[1] not in months:
        return None
    try:
        hour, minute, second = (int(component) for component in parts[4].split(":"))
        return datetime(
            int(parts[2]),
            months[parts[1]],
            int(parts[0]),
            hour,
            minute,
            second,
            tzinfo=timezone.utc,
        )
    except (ValueError, TypeError):
        return None


def _codesign(source_path: Path) -> _CodesignMetadata | None:
    """Verify a DMG with the native macOS code-signing service.

    Integrity and Apple trust are checked separately. This distinguishes a
    structurally valid signature made by an untrusted identity from damaged
    signed content.

    :param source_path: Signed DMG artifact.
    :returns: Native verification metadata, or ``None`` when unavailable.
    """
    executable = shutil.which("codesign")
    if executable is None:
        return None
    common = [
        executable,
        "--verify",
        "--strict=all",
        "--verbose=4",
    ]
    path = str(source_path.resolve())
    environment = {**os.environ, "LC_ALL": "C", "LANG": "C"}
    try:
        integrity = subprocess.run(
            [*common, path],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
        )
        trust = subprocess.run(
            [*common, "--test-requirement", "=anchor apple generic", path],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
        )
        display = subprocess.run(
            [executable, "--display", "--verbose=4", path],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
        )
    except OSError:
        return None

    status: ArtifactSignatureStatus
    if integrity.returncode != 0:
        status = "invalid"
    elif trust.returncode == 0:
        status = "valid"
    else:
        status = "untrusted"

    signer = None
    team_id = None
    timestamp = None
    output = display.stdout + "\n" + display.stderr
    for line in output.splitlines():
        if line.startswith("Authority=") and signer is None:
            value = line.split("=", 1)[1]
            if value and value != "(unavailable)":
                signer = value
        elif line.startswith("TeamIdentifier="):
            value = line.split("=", 1)[1]
            if value and value != "not set":
                team_id = value
        elif line.startswith("Timestamp="):
            value = line.split("=", 1)[1]
            if value.lower() != "none":
                timestamp = _parse_codesign_time(value)
    return _CodesignMetadata(status, signer, timestamp, team_id)


def _yaml_value(line: str) -> str:
    """Decode the simple scalar forms emitted by ``rcodesign``.

    :param line: YAML key/value line.
    :returns: Unquoted scalar value.
    """
    value = line.split(":", 1)[1].strip()
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1].replace("''", "'")
    if len(value) >= 2 and value[0] == value[-1] == '"':
        return value[1:-1]
    return value


def _parse_time(value: str) -> datetime | None:
    """Parse an RFC 3339 timestamp emitted by ``rcodesign``.

    :param value: Timestamp text.
    :returns: Parsed timestamp, or ``None`` when invalid.
    """
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _parse_rcodesign(output: str) -> _RcodesignMetadata | None:
    """Parse stable signature fields from ``rcodesign`` YAML output.

    :param output: Output of ``print-signature-info``.
    :returns: CMS verification metadata, or ``None`` for unsupported output.
    """
    signer = None
    trusted = False
    certificate_subject = None
    certificate_leaf = False
    certificate_trusted = False
    primary_valid: list[bool] = []
    primary_digest = None
    primary_algorithm = None
    timestamp = None
    timestamp_checks: list[bool] = []
    timestamp_seen = False

    def finish_certificate() -> None:
        nonlocal signer, trusted
        if certificate_subject is not None and certificate_leaf:
            signer = certificate_subject
            trusted = certificate_trusted

    for line in output.splitlines():
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if indent == 10 and stripped.startswith("- subject:"):
            finish_certificate()
            certificate_subject = _yaml_value(stripped)
            certificate_leaf = False
            certificate_trusted = False
        elif indent == 12 and stripped == "is_apple_root_ca: false":
            certificate_leaf = True
        elif indent == 12 and stripped == "is_apple_intermediate_ca: true":
            certificate_leaf = False
        elif indent == 12 and stripped == "chains_to_apple_root_ca: true":
            certificate_trusted = True
        elif indent == 10 and stripped == "signers:":
            finish_certificate()
            certificate_subject = None
        elif indent == 12 and stripped.startswith("digest_algorithm:"):
            primary_algorithm = _yaml_value(stripped)
        elif indent == 12 and stripped.startswith("message_digest:"):
            primary_digest = _yaml_value(stripped).lower()
        elif indent == 12 and stripped.startswith("signature_verifies:"):
            primary_valid.append(_yaml_value(stripped) == "true")
        elif indent == 12 and stripped == "time_stamp_token:":
            timestamp_seen = True
        elif indent == 16 and stripped.startswith("signing_time:"):
            timestamp = _parse_time(_yaml_value(stripped))
        elif indent == 16 and stripped.startswith("signature_verifies:"):
            timestamp_checks.append(_yaml_value(stripped) == "true")
    finish_certificate()
    if not primary_valid or primary_digest is None or primary_algorithm is None:
        return None
    return _RcodesignMetadata(
        cms_valid=bool(primary_valid) and all(primary_valid),
        code_directory_digest=primary_digest,
        digest_algorithm=primary_algorithm,
        signer=signer,
        trusted=trusted,
        timestamp=timestamp,
        timestamp_valid=(
            not timestamp_seen
            or (
                bool(timestamp_checks)
                and all(timestamp_checks)
                and timestamp is not None
            )
        ),
    )


def _rcodesign(source_path: Path) -> _RcodesignMetadata | None:
    """Inspect CMS metadata with an optional cross-platform tool.

    :param source_path: Signed DMG artifact.
    :returns: Parsed metadata, or ``None`` when the tool cannot inspect it.
    """
    executable = shutil.which("rcodesign") or shutil.which("rcodesign.exe")
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [
                executable,
                "-C",
                os.devnull,
                "print-signature-info",
                str(source_path.resolve()),
            ],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return _parse_rcodesign(result.stdout)


class DmgSignatureInspector:
    """Verify a DMG container signature with the best available backend."""

    def inspect(self, source_path: Path) -> ArtifactSignature:
        """Inspect the embedded DMG signature and notarization ticket.

        Static CodeDirectory digests are always checked. On macOS, ``codesign``
        verifies CMS integrity and Apple trust. Elsewhere, ``rcodesign`` can
        provide equivalent cross-platform metadata when available.

        :param source_path: DMG artifact to verify.
        :returns: Container signature metadata.
        """
        try:
            signature = _read_signature(source_path)
        except (OSError, _UnsupportedDmg):
            return ArtifactSignature(status="unsupported")
        except (ValueError, struct.error):
            return ArtifactSignature(status="invalid")
        if signature is None:
            return ArtifactSignature(status="unsigned", notarization_ticket=False)
        if not signature.content_valid:
            return ArtifactSignature(
                status="invalid",
                team_id=signature.team_id,
                notarization_ticket=signature.ticket_present,
            )
        native = _codesign(source_path)
        if native is not None:
            status = native.status
            if status == "valid" and not signature.cms_present:
                status = "untrusted"
            if (
                native.team_id is not None
                and signature.team_id is not None
                and native.team_id != signature.team_id
            ):
                status = "invalid"
            return ArtifactSignature(
                status=status,
                signer=native.signer,
                timestamp=native.timestamp,
                team_id=signature.team_id or native.team_id,
                notarization_ticket=signature.ticket_present,
            )
        metadata = _rcodesign(source_path)
        if metadata is None:
            return ArtifactSignature(
                status="unsupported",
                team_id=signature.team_id,
                notarization_ticket=signature.ticket_present,
            )
        algorithm = (metadata.digest_algorithm or "").lower().replace("-", "")
        try:
            actual_digest = hashlib.new(algorithm, signature.code_directory).hexdigest()
        except ValueError:
            actual_digest = None
        cryptographically_valid = (
            signature.cms_present
            and metadata.cms_valid
            and metadata.timestamp_valid
            and actual_digest is not None
            and actual_digest == metadata.code_directory_digest
        )
        status = (
            "invalid"
            if not cryptographically_valid
            else "valid" if metadata.trusted else "untrusted"
        )
        return ArtifactSignature(
            status=status,
            signer=metadata.signer,
            timestamp=metadata.timestamp,
            team_id=signature.team_id,
            notarization_ticket=signature.ticket_present,
        )
