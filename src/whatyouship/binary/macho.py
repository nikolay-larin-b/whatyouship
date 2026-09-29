# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Read basic Apple Mach-O metadata with LIEF."""

import struct
from pathlib import Path
from typing import Literal

import lief

from whatyouship.model import BinaryMetadata, BinarySignatureType, SignatureMetadata


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
_CSSLOT_SIGNATURESLOT = 0x10000
_CS_ADHOC = 0x00000002


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

    count = struct.unpack_from(">I", content, 8)[0]
    if count > (length - 12) // 8:
        return "unknown"
    code_directory_type: BinarySignatureType | None = None
    for index in range(count):
        slot, offset = struct.unpack_from(">II", content, 12 + index * 8)
        blob = _blob_header(content, offset)
        if blob is None:
            return "unknown"
        blob_magic, blob_length = blob
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


def _signature(slices: list[lief.MachO.Binary]) -> SignatureMetadata:
    """Combine signature presence and type across all architecture slices.

    :param slices: Parsed slices from one thin or universal Mach-O file.
    :returns: Aggregate signature metadata for the complete file.
    """
    types: set[BinarySignatureType] = set()
    missing = False
    unknown = False
    for binary in slices:
        code_signature = binary.code_signature
        if code_signature is None:
            missing = True
            continue
        signature_type = _signature_type(bytes(code_signature.content))
        if signature_type == "unknown":
            unknown = True
        else:
            types.add(signature_type)

    aggregate_type: BinarySignatureType | None
    if len(types) == 1 and not missing and not unknown:
        aggregate_type = next(iter(types))
    elif types:
        aggregate_type = "mixed"
    else:
        aggregate_type = None

    if missing:
        return SignatureMetadata(
            present=False,
            signature_type=aggregate_type,
        )
    if unknown:
        return SignatureMetadata(
            present=None,
            signature_type=aggregate_type,
        )
    return SignatureMetadata(
        present=True,
        signature_type=aggregate_type,
    )


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
                signature = _signature(slices)
            except Exception:
                signature = SignatureMetadata(present=None)
            return BinaryMetadata(
                format="Mach-O",
                architecture="+".join(sorted(architectures)),
                kind=kinds.pop() if len(kinds) == 1 else "other",
                signature=signature,
            )
        except Exception:
            return None
