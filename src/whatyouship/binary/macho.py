# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Read and verify Apple Mach-O metadata with LIEF and native tooling."""

import hashlib
import json
import os
import plistlib
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import lief

from whatyouship.model import (
    BinaryDependency,
    BinaryEntitlement,
    BinaryMetadata,
    BinarySignatureType,
    SignatureMetadata,
)


_MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xfe\xed\xfa\xcf",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xca\xfe\xba\xbf",
    b"\xbe\xba\xfe\xca",
    b"\xbf\xba\xfe\xca",
}

_ARCHITECTURES = {
    lief.MachO.Header.CPU_TYPE.X86: "x86",
    lief.MachO.Header.CPU_TYPE.X86_64: "x86_64",
    lief.MachO.Header.CPU_TYPE.ARM: "arm",
    lief.MachO.Header.CPU_TYPE.ARM64: "arm64",
    lief.MachO.Header.CPU_TYPE.POWERPC: "powerpc",
    lief.MachO.Header.CPU_TYPE.POWERPC64: "powerpc64",
}

_LIBRARY_TYPES = {
    lief.MachO.Header.FILE_TYPE.FVMLIB,
    lief.MachO.Header.FILE_TYPE.DYLIB,
    lief.MachO.Header.FILE_TYPE.BUNDLE,
    lief.MachO.Header.FILE_TYPE.DYLIB_STUB,
    lief.MachO.Header.FILE_TYPE.KEXT_BUNDLE,
    lief.MachO.Header.FILE_TYPE.GPU_DYLIB,
}

_EXECUTABLE_TYPES = {
    lief.MachO.Header.FILE_TYPE.EXECUTE,
    lief.MachO.Header.FILE_TYPE.GPU_EXECUTE,
}

_CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
_CSMAGIC_CODEDIRECTORY = 0xFADE0C02
_CSMAGIC_BLOBWRAPPER = 0xFADE0B01
_CSSLOT_CODEDIRECTORY = 0
_CSSLOT_ENTITLEMENTS = 5
_CSSLOT_SIGNATURESLOT = 0x10000
_CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
_CS_ADHOC = 0x00000002
_CS_RUNTIME = 0x00010000
_CS_SUPPORTS_SCATTER = 0x20100
_CS_SUPPORTS_TEAM_ID = 0x20200
_CS_SUPPORTS_CODE_LIMIT_64 = 0x20300
_CSSLOT_ALTERNATE_CODEDIRECTORIES = 0x1000
_CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT = 0x1005
_DIGESTS = {
    1: ("sha1", 20),
    2: ("sha256", 32),
    3: ("sha256", 20),
    4: ("sha384", 48),
}

_DEPENDENCY_COMMANDS = {
    lief.MachO.LoadCommand.TYPE.LAZY_LOAD_DYLIB,
    lief.MachO.LoadCommand.TYPE.LOAD_DYLIB,
    lief.MachO.LoadCommand.TYPE.LOAD_UPWARD_DYLIB,
    lief.MachO.LoadCommand.TYPE.LOAD_WEAK_DYLIB,
    lief.MachO.LoadCommand.TYPE.REEXPORT_DYLIB,
}


@dataclass(frozen=True)
class _StaticSignature:
    """Hold the result of validating one Mach-O architecture slice."""

    valid: bool | None
    team_id: str | None


@dataclass(frozen=True)
class _NativeSignature:
    """Hold native verification and display metadata for a Mach-O file."""

    trusted: bool | None
    signer: str | None
    timestamp: bool | None
    team_id: str | None


@dataclass(frozen=True)
class _CmsSignature:
    """Hold CMS integrity and signer metadata for one architecture slice."""

    valid: bool | None
    trusted: bool | None
    signer: str | None
    timestamp: bool | None


def _kind(file_type: lief.MachO.Header.FILE_TYPE) -> str:
    """Map a Mach-O file type to the format-independent binary kind.

    :param file_type: Mach-O header file type.
    :returns: ``executable``, ``library``, or ``other``.
    """
    if file_type in _EXECUTABLE_TYPES:
        return "executable"
    if file_type in _LIBRARY_TYPES:
        return "library"
    return "other"


def _blob_header(content: bytes, offset: int) -> tuple[int, int] | None:
    """Read and bounds-check an Apple code-signing blob header.

    :param content: Complete embedded signature payload.
    :param offset: Blob offset within the payload.
    :returns: Magic and length, or ``None`` for an invalid blob.
    """
    if offset < 0 or offset + 8 > len(content):
        return None
    magic, length = struct.unpack_from(">II", content, offset)
    if length < 8 or offset + length > len(content):
        return None
    return magic, length


def _code_directory_type(content: bytes, offset: int) -> BinarySignatureType | None:
    """Classify a bounded CodeDirectory blob.

    :param content: Complete embedded signature payload.
    :param offset: CodeDirectory offset within the payload.
    :returns: ``ad-hoc`` when its flag is present, otherwise ``None``.
    """
    header = _blob_header(content, offset)
    if (
        header is None
        or header[0] != _CSMAGIC_CODEDIRECTORY
        or header[1] < 16
    ):
        return None
    flags = struct.unpack_from(">I", content, offset + 12)[0]
    return "ad-hoc" if flags & _CS_ADHOC else None


def _superblob_entries(content: bytes) -> tuple[tuple[int, int, int, int], ...] | None:
    """Read validated slot records from an embedded signature superblob.

    :param content: Complete embedded signature payload.
    :returns: Slot, offset, magic, and length records, or ``None`` if invalid.
    """
    header = _blob_header(content, 0)
    if header is None or header[0] != _CSMAGIC_EMBEDDED_SIGNATURE or header[1] < 12:
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
        if (
            blob is None
            or offset < index_end
            or offset + blob[1] > length
        ):
            return None
        entries.append((slot, offset, blob[0], blob[1]))
    return tuple(entries)


def _null_terminated_text(content: bytes, offset: int) -> str | None:
    """Read a bounded UTF-8 string from a code-signing blob.

    :param content: Complete bounded blob.
    :param offset: String offset within the blob.
    :returns: Decoded text, or ``None`` when the string is invalid.
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


def _source_range(
    source: Path | bytes | memoryview,
    offset: int,
    length: int,
) -> bytes | None:
    """Read an exact byte range from a path or in-memory Mach-O file.

    :param source: Complete Mach-O source.
    :param offset: Absolute range offset.
    :param length: Number of bytes to read.
    :returns: Requested bytes, or ``None`` when the range is unavailable.
    """
    if offset < 0 or length < 0:
        return None
    if isinstance(source, Path):
        try:
            with source.open("rb") as stream:
                stream.seek(offset)
                data = stream.read(length)
        except OSError:
            return None
    else:
        data = bytes(source[offset:offset + length])
    return data if len(data) == length else None


def _code_directories(
    content: bytes,
) -> tuple[tuple[bytes, tuple[tuple[int, int, int, int], ...]], ...] | None:
    """Extract primary and alternate CodeDirectories from a signature.

    :param content: Raw bytes referenced by ``LC_CODE_SIGNATURE``.
    :returns: CodeDirectories with their superblob entries, or ``None`` if malformed.
    """
    header = _blob_header(content, 0)
    if header is None:
        return None
    if header[0] == _CSMAGIC_CODEDIRECTORY:
        return ((content[:header[1]], ()),)
    entries = _superblob_entries(content)
    if entries is None:
        return None
    directories = []
    directory_slots = []
    for slot, offset, magic, length in entries:
        if (
            magic == _CSMAGIC_CODEDIRECTORY
            and (
                slot == _CSSLOT_CODEDIRECTORY
                or _CSSLOT_ALTERNATE_CODEDIRECTORIES
                <= slot
                < _CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT
            )
        ):
            directories.append((content[offset:offset + length], entries))
            directory_slots.append(slot)
    if (
        directory_slots.count(_CSSLOT_CODEDIRECTORY) != 1
        or len(directory_slots) != len(set(directory_slots))
    ):
        return None
    return tuple(directories)


def _validate_code_directory(
    source: Path | bytes | memoryview,
    binary: lief.MachO.Binary,
    code_directory: bytes,
    entries: tuple[tuple[int, int, int, int], ...],
    signature_content: bytes,
) -> _StaticSignature:
    """Validate one CodeDirectory and all locally available signed slots.

    :param source: Complete thin or universal Mach-O source.
    :param binary: Architecture slice described by the CodeDirectory.
    :param code_directory: Bounded CodeDirectory blob.
    :param entries: Signature superblob entries.
    :param signature_content: Complete signature superblob.
    :returns: Static verification result and embedded Team ID.
    """
    if len(code_directory) < 44:
        return _StaticSignature(False, None)
    (
        magic,
        length,
        version,
        _flags,
        hash_offset,
        _identifier_offset,
        special_count,
        code_count,
        code_limit,
        hash_size,
        hash_type,
        _platform,
        page_size_power,
        _spare,
    ) = struct.unpack_from(">9I4BI", code_directory, 0)
    digest = _DIGESTS.get(hash_type)
    if (
        magic != _CSMAGIC_CODEDIRECTORY
        or length != len(code_directory)
        or digest is None
        or hash_size != digest[1]
    ):
        return _StaticSignature(False, None)

    if version >= _CS_SUPPORTS_SCATTER:
        if len(code_directory) < 48:
            return _StaticSignature(False, None)
        if struct.unpack_from(">I", code_directory, 44)[0] != 0:
            return _StaticSignature(None, None)

    team_id = None
    if version >= _CS_SUPPORTS_TEAM_ID:
        if len(code_directory) < 52:
            return _StaticSignature(False, None)
        team_offset = struct.unpack_from(">I", code_directory, 48)[0]
        if team_offset:
            team_id = _null_terminated_text(code_directory, team_offset)
            if team_id is None:
                return _StaticSignature(False, None)

    if version >= _CS_SUPPORTS_CODE_LIMIT_64:
        if len(code_directory) < 64:
            return _StaticSignature(False, team_id)
        code_limit_64 = struct.unpack_from(">Q", code_directory, 56)[0]
        if code_limit == 0:
            code_limit = code_limit_64

    if page_size_power > 30:
        return _StaticSignature(False, team_id)
    page_size = code_limit or 1 if page_size_power == 0 else 1 << page_size_power
    expected_count = (code_limit + page_size - 1) // page_size
    digest_start = hash_offset - special_count * hash_size
    digest_end = hash_offset + code_count * hash_size
    if (
        code_count != expected_count
        or digest_start < 0
        or hash_offset > length
        or digest_end > length
    ):
        return _StaticSignature(False, team_id)

    code_signature = getattr(binary, "code_signature", None)
    data_offset = getattr(code_signature, "data_offset", None)
    slice_offset = getattr(binary, "fat_offset", None)
    if not isinstance(data_offset, int) or not isinstance(slice_offset, int):
        return _StaticSignature(None, team_id)
    if code_limit != data_offset:
        return _StaticSignature(False, team_id)

    for index in range(code_count):
        chunk_offset = index * page_size
        chunk_length = min(page_size, code_limit - chunk_offset)
        chunk = _source_range(source, slice_offset + chunk_offset, chunk_length)
        if chunk is None:
            return _StaticSignature(None, team_id)
        actual = hashlib.new(digest[0], chunk).digest()[:hash_size]
        expected = code_directory[
            hash_offset + index * hash_size:hash_offset + (index + 1) * hash_size
        ]
        if actual != expected:
            return _StaticSignature(False, team_id)

    for slot, offset, _blob_magic, blob_length in entries:
        if not 0 < slot <= special_count:
            continue
        actual = hashlib.new(
            digest[0], signature_content[offset:offset + blob_length]
        ).digest()[:hash_size]
        expected_offset = hash_offset - slot * hash_size
        expected = code_directory[expected_offset:expected_offset + hash_size]
        if actual != expected:
            return _StaticSignature(False, team_id)
    return _StaticSignature(True, team_id)


def _static_signature(
    source: Path | bytes | memoryview,
    binary: lief.MachO.Binary,
    content: bytes,
) -> _StaticSignature:
    """Validate every CodeDirectory belonging to one architecture slice.

    :param source: Complete thin or universal Mach-O source.
    :param binary: Parsed architecture slice.
    :param content: Embedded code-signature payload.
    :returns: Aggregate static result for the slice.
    """
    directories = _code_directories(content)
    if directories is None:
        return _StaticSignature(False, None)
    results = [
        _validate_code_directory(source, binary, directory, entries, content)
        for directory, entries in directories
    ]
    valid = (
        False if any(result.valid is False for result in results)
        else True if all(result.valid is True for result in results)
        else None
    )
    team_ids = {result.team_id for result in results if result.team_id is not None}
    return _StaticSignature(valid, next(iter(team_ids)) if len(team_ids) == 1 else None)


def _code_directory_flags(content: bytes) -> int | None:
    """Read flags from the primary CodeDirectory.

    :param content: Raw bytes referenced by ``LC_CODE_SIGNATURE``.
    :returns: CodeDirectory flags, or ``None`` when unavailable.
    """
    header = _blob_header(content, 0)
    if header is not None and header[0] == _CSMAGIC_CODEDIRECTORY:
        return (
            struct.unpack_from(">I", content, 12)[0]
            if header[1] >= 16 else None
        )
    entries = _superblob_entries(content)
    if entries is None:
        return None
    for slot, offset, magic, length in entries:
        if slot == _CSSLOT_CODEDIRECTORY and magic == _CSMAGIC_CODEDIRECTORY:
            return struct.unpack_from(">I", content, offset + 12)[0] if length >= 16 else None
    return None


def _entitlements(content: bytes) -> tuple[BinaryEntitlement, ...]:
    """Parse XML entitlements from an embedded signature superblob.

    :param content: Raw bytes referenced by ``LC_CODE_SIGNATURE``.
    :returns: Entitlements ordered by key and canonical value.
    :raises ValueError: If an entitlement blob is malformed or unsupported.
    """
    entries = _superblob_entries(content)
    if entries is None:
        return ()
    entitlements: set[BinaryEntitlement] = set()
    for slot, offset, magic, length in entries:
        if slot != _CSSLOT_ENTITLEMENTS:
            continue
        if magic != _CSMAGIC_EMBEDDED_ENTITLEMENTS:
            raise ValueError("Invalid embedded entitlements blob")
        values = plistlib.loads(
            content[offset + 8:offset + length].rstrip(b"\x00")
        )
        if not isinstance(values, dict) or any(
            not isinstance(key, str) for key in values
        ):
            raise ValueError("Embedded entitlements must contain a dictionary")
        for key, value in values.items():
            try:
                serialized = json.dumps(
                    value,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            except (TypeError, ValueError) as error:
                raise ValueError(
                    f"Unsupported entitlement value for '{key}'"
                ) from error
            entitlements.add(BinaryEntitlement(key, serialized))
    return tuple(sorted(entitlements, key=lambda item: (item.key, item.value)))


def _signature_type(content: bytes) -> BinarySignatureType | Literal["unknown"]:
    """Classify one embedded Mach-O code-signature payload.

    :param content: Raw bytes referenced by ``LC_CODE_SIGNATURE``.
    :returns: Signature type, or ``unknown`` for an unsupported payload.
    """
    header = _blob_header(content, 0)
    if header is None:
        return "unknown"
    magic, length = header
    if magic == _CSMAGIC_CODEDIRECTORY:
        return _code_directory_type(content, 0) or "unknown"
    if magic != _CSMAGIC_EMBEDDED_SIGNATURE or length < 12:
        return "unknown"
    entries = _superblob_entries(content)
    if entries is None:
        return "unknown"
    code_directory_type: BinarySignatureType | None = None
    for slot, offset, blob_magic, blob_length in entries:
        if (
            slot == _CSSLOT_SIGNATURESLOT
            and blob_magic == _CSMAGIC_BLOBWRAPPER
            and blob_length > 8
            and content[offset + 8] == 0x30
        ):
            return "certificate"
        if slot == _CSSLOT_CODEDIRECTORY:
            code_directory_type = _code_directory_type(content, offset)
    return code_directory_type or "unknown"


def _cms_signature(content: bytes) -> _CmsSignature:
    """Verify the detached CMS signature over the primary CodeDirectory.

    OpenSSL performs the cryptographic CMS check without making a trust
    decision. Trust is evaluated separately by the native code-signing service.

    :param content: Raw bytes referenced by ``LC_CODE_SIGNATURE``.
    :returns: CMS integrity, leaf certificate subject, and timestamp presence.
    """
    executable = shutil.which("openssl")
    directories = _code_directories(content)
    entries = _superblob_entries(content)
    if executable is None or directories is None or entries is None:
        return _CmsSignature(None, None, None, None)
    primary = next((
        content[offset:offset + length]
        for slot, offset, magic, length in entries
        if slot == _CSSLOT_CODEDIRECTORY and magic == _CSMAGIC_CODEDIRECTORY
    ), None)
    wrapper = next((
        content[offset + 8:offset + length]
        for slot, offset, magic, length in entries
        if slot == _CSSLOT_SIGNATURESLOT
        and magic == _CSMAGIC_BLOBWRAPPER
        and length > 8
    ), None)
    if primary is None or wrapper is None:
        return _CmsSignature(False, None, None, None)

    try:
        with tempfile.TemporaryDirectory(prefix="whatyouship-cms-") as temporary:
            root = Path(temporary)
            code_directory_path = root / "CodeDirectory"
            cms_path = root / "signature.cms"
            signer_path = root / "signer.pem"
            code_directory_path.write_bytes(primary)
            cms_path.write_bytes(wrapper)
            verification = subprocess.run(
                [
                    executable,
                    "cms",
                    "-verify",
                    "-binary",
                    "-inform",
                    "DER",
                    "-content",
                    str(code_directory_path),
                    "-in",
                    str(cms_path),
                    "-noverify",
                    "-out",
                    os.devnull,
                    "-signer",
                    str(signer_path),
                ],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            if verification.returncode != 0:
                return _CmsSignature(False, None, None, None)
            subject = subprocess.run(
                [
                    executable,
                    "x509",
                    "-in",
                    str(signer_path),
                    "-noout",
                    "-subject",
                    "-nameopt",
                    "RFC2253",
                ],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            cms_dump = subprocess.run(
                [
                    executable,
                    "cms",
                    "-cmsout",
                    "-print",
                    "-inform",
                    "DER",
                    "-in",
                    str(cms_path),
                ],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            trusted = None
            security = shutil.which("security")
            root_keychain = Path(
                "/System/Library/Keychains/SystemRootCertificates.keychain"
            )
            if security is not None and root_keychain.is_file():
                roots = subprocess.run(
                    [
                        security,
                        "find-certificate",
                        "-a",
                        "-p",
                        str(root_keychain),
                    ],
                    capture_output=True,
                    check=False,
                )
                if roots.returncode == 0 and b"BEGIN CERTIFICATE" in roots.stdout:
                    roots_path = root / "system-roots.pem"
                    roots_path.write_bytes(roots.stdout)
                    trust = subprocess.run(
                        [
                            executable,
                            "cms",
                            "-verify",
                            "-binary",
                            "-inform",
                            "DER",
                            "-content",
                            str(code_directory_path),
                            "-in",
                            str(cms_path),
                            "-CAfile",
                            str(roots_path),
                            "-out",
                            os.devnull,
                        ],
                        capture_output=True,
                        check=False,
                    )
                    trusted = trust.returncode == 0
    except OSError:
        return _CmsSignature(None, None, None, None)
    signer = None
    if subject.returncode == 0:
        signer_text = subject.stdout.strip()
        signer = signer_text.split("=", 1)[1].strip() if "=" in signer_text else None
    timestamp = (
        "id-smime-aa-timestamptoken" in cms_dump.stdout.lower()
        or "1.2.840.113549.1.9.16.2.14" in cms_dump.stdout
    ) if cms_dump.returncode == 0 else None
    return _CmsSignature(True, trusted, signer, timestamp)


def _native_signature(source: Path) -> _NativeSignature | None:
    """Verify a Mach-O file with the native macOS code-signing service.

    :param source: Mach-O file to verify.
    :returns: Native verification metadata, or ``None`` off macOS or on tool failure.
    """
    executable = shutil.which("codesign")
    if executable is None:
        return None
    try:
        verification = subprocess.run(
            [
                executable,
                "--verify",
                "--all-architectures",
                "--strict=all",
                "--verbose=4",
                str(source.resolve()),
            ],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        display = subprocess.run(
            [
                executable,
                "--display",
                "--all-architectures",
                "--verbose=4",
                str(source.resolve()),
            ],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError:
        return None
    verification_output = verification.stdout + "\n" + verification.stderr
    display_output = display.stdout + "\n" + display.stderr
    trust_errors = (
        "cssmerr_tp_not_trusted",
        "cssmerr_tp_cert_expired",
        "cssmerr_tp_cert_revoked",
        "certificate is not trusted",
        "unable to build chain",
    )
    untrusted = any(error in verification_output.lower() for error in trust_errors)
    authorities = []
    team_ids = set()
    timestamp: bool | None = None
    for line in display_output.splitlines():
        if line.startswith("Authority="):
            authority = line.split("=", 1)[1]
            if authority and authority != "(unavailable)":
                authorities.append(authority)
        elif line.startswith("TeamIdentifier="):
            team_id = line.split("=", 1)[1]
            if team_id and team_id != "not set":
                team_ids.add(team_id)
        elif line.startswith("Timestamp="):
            timestamp = line.split("=", 1)[1].lower() not in {"", "none"}
    return _NativeSignature(
        trusted=(
            True if verification.returncode == 0
            else False if untrusted
            else None
        ),
        signer=authorities[0] if authorities else None,
        timestamp=timestamp,
        team_id=next(iter(team_ids)) if len(team_ids) == 1 else None,
    )


def _signature(
    source: Path | bytes | memoryview,
    slices: list[lief.MachO.Binary],
) -> SignatureMetadata:
    """Combine signature presence and type across all architecture slices.

    :param source: Complete thin or universal Mach-O source.
    :param slices: Parsed slices from one thin or universal Mach-O file.
    :returns: Aggregate signature metadata for the complete file.
    """
    types: set[BinarySignatureType] = set()
    missing = False
    unknown = False
    hardened_states: list[bool] = []
    hardened_unknown = False
    entitlements: set[BinaryEntitlement] = set()
    static_results: list[_StaticSignature] = []
    cms_results: list[_CmsSignature] = []
    for binary in slices:
        code_signature = binary.code_signature
        if code_signature is None:
            missing = True
            hardened_unknown = True
            continue
        content = bytes(code_signature.content)
        static_results.append(_static_signature(source, binary, content))
        signature_type = _signature_type(content)
        if signature_type == "unknown":
            unknown = True
        else:
            types.add(signature_type)
            if signature_type == "certificate":
                cms_results.append(_cms_signature(content))
        flags = _code_directory_flags(content)
        if flags is None:
            hardened_unknown = True
        else:
            hardened_states.append(bool(flags & _CS_RUNTIME))
        try:
            entitlements.update(_entitlements(content))
        except ValueError:
            pass

    aggregate_type: BinarySignatureType | None
    if len(types) == 1 and not missing and not unknown:
        aggregate_type = next(iter(types))
    elif types:
        aggregate_type = "mixed"
    else:
        aggregate_type = None

    hardened_runtime = (
        None
        if hardened_unknown or not hardened_states
        else all(hardened_states)
    )
    signature_entitlements = tuple(sorted(
        entitlements,
        key=lambda item: (item.key, item.value),
    ))
    static_valid = (
        False if any(result.valid is False for result in static_results)
        else True if static_results and all(
            result.valid is True for result in static_results
        )
        else None
    )
    static_team_ids = {
        result.team_id for result in static_results if result.team_id is not None
    }
    team_id = next(iter(static_team_ids)) if len(static_team_ids) == 1 else None
    cms_valid = (
        False if any(result.valid is False for result in cms_results)
        else True if cms_results and all(result.valid is True for result in cms_results)
        else None
    )
    cms_signers = {result.signer for result in cms_results if result.signer is not None}
    cms_signer = next(iter(cms_signers)) if len(cms_signers) == 1 else None
    cms_trusted = (
        False if any(result.trusted is False for result in cms_results)
        else True if cms_results and all(
            result.trusted is True for result in cms_results
        )
        else None
    )
    cms_timestamp = (
        False if any(result.timestamp is False for result in cms_results)
        else True if cms_results and all(
            result.timestamp is True for result in cms_results
        )
        else None
    )

    if missing:
        return SignatureMetadata(
            present=False,
            valid=False if static_valid is False else None,
            signature_type=aggregate_type,
            hardened_runtime=hardened_runtime,
            entitlements=signature_entitlements,
        )
    if unknown:
        return SignatureMetadata(
            present=None,
            valid=False if static_valid is False else None,
            team_id=team_id,
            signature_type=aggregate_type,
            hardened_runtime=hardened_runtime,
            entitlements=signature_entitlements,
        )
    native = _native_signature(source) if isinstance(source, Path) else None
    if static_valid is False or cms_valid is False:
        valid = False
        trusted = None
    elif aggregate_type == "ad-hoc":
        valid = static_valid
        trusted = False if static_valid is True else None
    else:
        valid = (
            True if static_valid is True and (
                cms_valid is True
                or native is not None and native.trusted is True
            )
            else None
        )
        trusted = (
            True
            if valid is True and (
                cms_trusted is True
                or native is not None and native.trusted is True
            )
            else False
            if valid is True and cms_trusted is False
            else native.trusted
            if valid is True and native is not None
            else None
        )
    if "ad-hoc" in types and valid is True:
        trusted = False
    return SignatureMetadata(
        present=True,
        valid=valid,
        trusted=trusted,
        signer=(
            cms_signer
            if cms_signer is not None
            else native.signer if native is not None else None
        ),
        timestamp=(
            False if aggregate_type == "ad-hoc"
            else cms_timestamp
            if cms_timestamp is not None
            else native.timestamp if native is not None else None
        ),
        team_id=(
            native.team_id
            if native is not None and native.team_id is not None
            else team_id
        ),
        signature_type=aggregate_type,
        hardened_runtime=hardened_runtime,
        entitlements=signature_entitlements,
    )


def _minimum_os_components(binary: lief.MachO.Binary) -> tuple[int, ...] | None:
    """Read the macOS deployment target from one architecture slice.

    :param binary: Parsed Mach-O architecture slice.
    :returns: Numeric version components, or ``None`` when unavailable.
    """
    build_version = getattr(binary, "build_version", None)
    if (
        build_version is not None
        and build_version.platform == lief.MachO.BuildVersion.PLATFORMS.MACOS
    ):
        return tuple(int(component) for component in build_version.minos)

    for command in getattr(binary, "commands", ()):
        if (
            isinstance(command, lief.MachO.VersionMin)
            and command.command
            == lief.MachO.LoadCommand.TYPE.VERSION_MIN_MACOSX
        ):
            return tuple(int(component) for component in command.version)
    return None


def _format_version(components: tuple[int, ...]) -> str:
    """Format numeric version components without a redundant patch zero.

    :param components: Numeric version components.
    :returns: Dotted version with at least major and minor components.
    """
    normalized = list(components)
    while len(normalized) > 2 and normalized[-1] == 0:
        normalized.pop()
    return ".".join(str(component) for component in normalized)


def _minimum_os_version(slices: list[lief.MachO.Binary]) -> str | None:
    """Combine deployment targets across all architecture slices.

    The highest target is the earliest macOS release capable of running every
    slice. A missing target in any slice makes the aggregate unknown.

    :param slices: Parsed slices from one thin or universal Mach-O file.
    :returns: Effective minimum macOS version, or ``None`` when unavailable.
    """
    versions = [_minimum_os_components(binary) for binary in slices]
    if not versions or any(version is None for version in versions):
        return None
    return _format_version(max(version for version in versions if version is not None))


def _current_library_version(slices: list[lief.MachO.Binary]) -> str | None:
    """Read one consistent ``LC_ID_DYLIB`` current version.

    Every architecture slice must identify itself as a dynamic library and
    carry the same version. Reporting no version is safer than selecting one
    value from an internally inconsistent universal binary.

    :param slices: Parsed slices from one thin or universal Mach-O file.
    :returns: Dotted current-library version, or ``None`` when unavailable or
        inconsistent.
    """
    versions: list[tuple[int, ...]] = []
    for binary in slices:
        identifiers = [
            library
            for library in binary.libraries
            if library.command == lief.MachO.LoadCommand.TYPE.ID_DYLIB
        ]
        if len(identifiers) != 1:
            return None
        versions.append(
            tuple(int(component) for component in identifiers[0].current_version)
        )
    if not versions or any(version != versions[0] for version in versions[1:]):
        return None
    return ".".join(str(component) for component in versions[0])


def _dependencies(slices: list[lief.MachO.Binary]) -> tuple[BinaryDependency, ...]:
    """Combine imported dynamic libraries across architecture slices.

    :param slices: Parsed slices from one thin or universal Mach-O file.
    :returns: Unique dependencies sorted by install name.
    """
    required_by_path: dict[str, bool] = {}
    required_architectures_by_path: dict[str, set[str]] = {}
    for binary in slices:
        architecture = _ARCHITECTURES.get(
            binary.header.cpu_type,
            binary.header.cpu_type.name.lower(),
        )
        for library in binary.libraries:
            if library.command not in _DEPENDENCY_COMMANDS or not library.name:
                continue
            required = (
                library.command
                != lief.MachO.LoadCommand.TYPE.LOAD_WEAK_DYLIB
            )
            required_by_path[library.name] = (
                required_by_path.get(library.name, False) or required
            )
            if required:
                required_architectures_by_path.setdefault(
                    library.name, set()
                ).add(architecture)
    return tuple(
        BinaryDependency(
            path,
            required_by_path[path],
            tuple(sorted(required_architectures_by_path.get(path, ()))),
        )
        for path in sorted(required_by_path)
    )


def _runtime_search_paths(slices: list[lief.MachO.Binary]) -> tuple[str, ...]:
    """Combine runtime search paths across architecture slices.

    :param slices: Parsed slices from one thin or universal Mach-O file.
    :returns: Unique runtime search paths in lexical order.
    """
    return tuple(sorted({command.path for binary in slices for command in binary.rpaths}))


class MachOInspector:
    """Identify thin and universal Mach-O binaries."""

    def inspect(self, source: Path | bytes | memoryview) -> BinaryMetadata | None:
        """Inspect a path or in-memory payload when it contains Mach-O code.

        :param source: Path or bytes of a potential Mach-O file.
        :returns: Mach-O metadata, or ``None`` for non-Mach-O or unreadable files.
        """
        try:
            if isinstance(source, Path):
                with source.open("rb") as stream:
                    if stream.read(4) not in _MACHO_MAGICS:
                        return None
                parse_source = source
            else:
                if bytes(source[:4]) not in _MACHO_MAGICS:
                    return None
                parse_source = bytes(source)

            with lief.logging.level_scope(lief.logging.LEVEL.OFF):
                fat_binary = lief.MachO.parse(parse_source)
            if fat_binary is None:
                return None

            slices = list(fat_binary)
            if not slices:
                return None
            architectures = {
                _ARCHITECTURES.get(
                    binary.header.cpu_type,
                    binary.header.cpu_type.name.lower(),
                )
                for binary in slices
            }
            kinds = {_kind(binary.header.file_type) for binary in slices}
            try:
                signature = _signature(source, slices)
            except Exception:
                signature = SignatureMetadata(present=None)
            try:
                minimum_os_version = _minimum_os_version(slices)
            except Exception:
                minimum_os_version = None
            try:
                file_version = _current_library_version(slices)
            except Exception:
                file_version = None
            try:
                dependencies = _dependencies(slices)
                runtime_search_paths = _runtime_search_paths(slices)
            except Exception:
                dependencies = ()
                runtime_search_paths = ()
            return BinaryMetadata(
                format="Mach-O",
                architecture="+".join(sorted(architectures)),
                kind=kinds.pop() if len(kinds) == 1 else "other",
                file_version=file_version,
                signature=signature,
                minimum_os_version=minimum_os_version,
                dependencies=dependencies,
                runtime_search_paths=runtime_search_paths,
            )
        except Exception:
            return None
