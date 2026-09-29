# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Read basic Apple Mach-O metadata with LIEF."""

import struct
from pathlib import Path
from typing import Literal

import lief

from whatyouship.model import (
    BinaryDependency,
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
_CSSLOT_SIGNATURESLOT = 0x10000
_CS_ADHOC = 0x00000002

_DEPENDENCY_COMMANDS = {
    lief.MachO.LoadCommand.TYPE.LAZY_LOAD_DYLIB,
    lief.MachO.LoadCommand.TYPE.LOAD_DYLIB,
    lief.MachO.LoadCommand.TYPE.LOAD_UPWARD_DYLIB,
    lief.MachO.LoadCommand.TYPE.LOAD_WEAK_DYLIB,
    lief.MachO.LoadCommand.TYPE.REEXPORT_DYLIB,
}


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


def _dependencies(slices: list[lief.MachO.Binary]) -> tuple[BinaryDependency, ...]:
    """Combine imported dynamic libraries across architecture slices.

    :param slices: Parsed slices from one thin or universal Mach-O file.
    :returns: Unique dependencies sorted by install name.
    """
    required_by_path: dict[str, bool] = {}
    for binary in slices:
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
    return tuple(
        BinaryDependency(path, required_by_path[path])
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
                signature = _signature(slices)
            except Exception:
                signature = SignatureMetadata(present=None)
            try:
                minimum_os_version = _minimum_os_version(slices)
            except Exception:
                minimum_os_version = None
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
                signature=signature,
                minimum_os_version=minimum_os_version,
                dependencies=dependencies,
                runtime_search_paths=runtime_search_paths,
            )
        except Exception:
            return None
