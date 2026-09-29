# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Read basic Apple Mach-O metadata with LIEF."""

from pathlib import Path

import lief

from whatyouship.model import BinaryMetadata


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
            return BinaryMetadata(
                format="Mach-O",
                architecture="+".join(sorted(architectures)),
                kind=kinds.pop() if len(kinds) == 1 else "other",
            )
        except Exception:
            return None
