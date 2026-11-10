# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Read ELF architecture, binary kind, and loader metadata with LIEF."""

from pathlib import Path

import lief

from whatyouship.binary.errors import BinaryAnalysisError
from whatyouship.model import BinaryDependency, BinaryMetadata


_ARCHITECTURES = {
    lief.ELF.ARCH.I386: "x86",
    lief.ELF.ARCH.X86_64: "x86_64",
    lief.ELF.ARCH.ARM: "arm",
    lief.ELF.ARCH.AARCH64: "arm64",
    lief.ELF.ARCH.PPC: "ppc",
    lief.ELF.ARCH.PPC64: "ppc64",
}


def _text(value: str | bytes) -> str:
    """Convert LIEF strings to reportable text without interpreting loader tokens.

    :param value: Text or raw bytes returned by LIEF.
    :returns: Text with invalid UTF-8 bytes represented as escape sequences.
    """
    return value.decode("utf-8", errors="backslashreplace") if isinstance(value, bytes) else value


class ElfInspector:
    """Identify ELF files and read architecture, kind, and loader declarations."""

    def inspect(self, source: Path | bytes | memoryview) -> BinaryMetadata | None:
        """Inspect a path or in-memory ELF without executing its contents.

        :param source: Path or bytes of a potential ELF file.
        :returns: ELF metadata, or ``None`` for unrecognized content.
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
            dependencies = []
            rpaths = []
            runpaths = []
            library_name = None
            for entry in binary.dynamic_entries:
                if isinstance(entry, lief.ELF.DynamicEntryLibrary):
                    dependencies.append(BinaryDependency(_text(entry.name)))
                elif isinstance(entry, lief.ELF.DynamicEntryRpath):
                    rpaths.extend(_text(entry.rpath).split(":"))
                elif isinstance(entry, lief.ELF.DynamicEntryRunPath):
                    runpaths.extend(_text(entry.runpath).split(":"))
                elif isinstance(entry, lief.ELF.DynamicSharedObject) and library_name is None:
                    library_name = _text(entry.name)
            return BinaryMetadata(
                format="ELF",
                architecture=architecture,
                kind=kind,
                dependencies=tuple(dependencies),
                runtime_search_paths=tuple(rpaths),
                runtime_run_paths=tuple(runpaths),
                interpreter=_text(binary.interpreter) if binary.has_interpreter else None,
                library_name=library_name,
            )
        except (RuntimeError, ValueError) as error:
            raise BinaryAnalysisError("ELF", str(error) or type(error).__name__) from error
