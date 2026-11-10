# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Read basic ELF metadata with LIEF on any supported host platform."""

from pathlib import Path

import lief

from whatyouship.binary.errors import BinaryAnalysisError
from whatyouship.model import BinaryMetadata


_ARCHITECTURES = {
    lief.ELF.ARCH.I386: "x86",
    lief.ELF.ARCH.X86_64: "x86_64",
    lief.ELF.ARCH.ARM: "arm",
    lief.ELF.ARCH.AARCH64: "arm64",
    lief.ELF.ARCH.PPC: "ppc",
    lief.ELF.ARCH.PPC64: "ppc64",
}


class ElfInspector:
    """Identify ELF files and read architecture and binary kind."""

    def inspect(self, source: Path | bytes | memoryview) -> BinaryMetadata | None:
        """Inspect a path or in-memory ELF without executing its contents.

        :param source: Path or bytes of a potential ELF file.
        :returns: Basic ELF metadata, or ``None`` for unrecognized content.
        :raises BinaryAnalysisError: If recognized ELF content cannot be analyzed.
        :raises OSError: If a source file cannot be read.
        """
        if isinstance(source, Path):
            with source.open("rb") as stream:
                header = stream.read(64)
        else:
            header = bytes(source[:64])
        if header[:4] != b"\x7fELF":
            return None
        if (
            len(header) < 16
            or header[4] not in (1, 2)
            or header[5] not in (1, 2)
            or header[6] != 1
        ):
            raise BinaryAnalysisError("ELF", "Incomplete or unsupported ELF identification")
        if len(header) < (52 if header[4] == 1 else 64):
            raise BinaryAnalysisError("ELF", "Truncated ELF header")

        try:
            with lief.logging.level_scope(lief.logging.LEVEL.OFF):
                binary = lief.ELF.parse(source if isinstance(source, Path) else bytes(source))
            if binary is None:
                raise BinaryAnalysisError("ELF", "LIEF could not parse the file")
            machine = binary.header.machine_type
            bits = 32 if header[4] == 1 else 64
            if machine in (lief.ELF.ARCH.RISCV, lief.ELF.ARCH.MIPS, lief.ELF.ARCH.LOONGARCH):
                architecture = f"{machine.name.lower()}{bits}"
            elif machine == lief.ELF.ARCH.S390:
                architecture = "s390x" if bits == 64 else "s390"
            else:
                architecture = _ARCHITECTURES.get(
                    machine, machine.name.lower() if isinstance(machine, lief.ELF.ARCH)
                    else f"unknown-{int(machine)}",
                )
            kind = "other"
            if binary.header.file_type == lief.ELF.Header.FILE_TYPE.EXEC:
                kind = "executable"
            elif binary.header.file_type == lief.ELF.Header.FILE_TYPE.DYN:
                flags = binary.get(lief.ELF.DynamicEntry.TAG.FLAGS_1)
                pie = isinstance(flags, lief.ELF.DynamicEntryFlags) and flags.has(
                    lief.ELF.DynamicEntryFlags.FLAG.PIE
                )
                kind = "executable" if binary.has_interpreter or pie else "library"
            return BinaryMetadata(format="ELF", architecture=architecture, kind=kind)
        except (RuntimeError, ValueError) as error:
            raise BinaryAnalysisError("ELF", str(error) or type(error).__name__) from error
