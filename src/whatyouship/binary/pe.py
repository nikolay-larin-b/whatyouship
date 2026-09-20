# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Read basic Windows PE metadata with LIEF."""

from pathlib import Path

import lief

from whatyouship.model import BinaryMetadata


_ARCHITECTURES = {
    lief.PE.Header.MACHINE_TYPES.I386: "x86",
    lief.PE.Header.MACHINE_TYPES.AMD64: "x86_64",
    lief.PE.Header.MACHINE_TYPES.ARM: "arm",
    lief.PE.Header.MACHINE_TYPES.ARMNT: "arm",
    lief.PE.Header.MACHINE_TYPES.ARM64: "arm64",
    lief.PE.Header.MACHINE_TYPES.ARM64EC: "arm64ec",
}


def _fixed_version(high: int, low: int) -> str:
    """Format an embedded four-part PE version number.

    :param high: Most significant 32 bits of the version.
    :param low: Least significant 32 bits of the version.
    :returns: Dotted four-part version string.
    """
    return f"{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}"


class PeInspector:
    """Identify PE files and read basic header and version metadata."""

    def inspect(self, source: Path | bytes | memoryview) -> BinaryMetadata | None:
        """Inspect a path or in-memory payload when it contains a PE file.

        :param source: Path or bytes of a potential PE file.
        :returns: PE metadata, or ``None`` for non-PE or unreadable files.
        """
        try:
            if isinstance(source, Path):
                with source.open("rb") as stream:
                    if stream.read(2) != b"MZ":
                        return None
                parse_source = source
            else:
                if bytes(source[:2]) != b"MZ":
                    return None
                parse_source = bytes(source)

            with lief.logging.level_scope(lief.logging.LEVEL.OFF):
                binary = lief.PE.parse(parse_source)
            if binary is None:
                return None

            header = binary.header
            machine = header.machine
            architecture = _ARCHITECTURES.get(machine, machine.name.lower())
            if header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL):
                kind = "dll"
            elif header.has_characteristic(lief.PE.Header.CHARACTERISTICS.EXECUTABLE_IMAGE):
                kind = "executable"
            else:
                kind = "other"

            file_version, product_version = self._versions(binary)
            return BinaryMetadata(
                format="PE",
                architecture=architecture,
                kind=kind,
                file_version=file_version,
                product_version=product_version,
            )
        except Exception:
            return None

    def _versions(self, binary: lief.PE.Binary) -> tuple[str | None, str | None]:
        """Read string and fixed versions from a PE version resource.

        :param binary: Parsed PE binary.
        :returns: File and product versions when available.
        """
        try:
            if not binary.has_resources:
                return None, None
            manager = binary.resources_manager
            if not manager.has_version:
                return None, None
            version = next(iter(manager.version), None)
            if version is None:
                return None, None

            file_version: str | None = None
            product_version: str | None = None
            string_info = version.string_file_info
            if string_info is not None:
                for table in string_info.children:
                    file_version = file_version or table.get("FileVersion")
                    product_version = product_version or table.get("ProductVersion")
        except Exception:
            return None, None

        if file_version is None or product_version is None:
            try:
                fixed = version.file_info
                file_version = file_version or _fixed_version(
                    fixed.file_version_ms, fixed.file_version_ls
                )
                product_version = product_version or _fixed_version(
                    fixed.product_version_ms, fixed.product_version_ls
                )
            except Exception:
                pass
        return file_version, product_version
