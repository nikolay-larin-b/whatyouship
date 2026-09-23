# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Identify NSIS installers without executing or extracting them."""

import struct
from pathlib import Path


_NSIS_FIRST_HEADER_SIGNATURE = b"\xef\xbe\xad\xdeNullsoftInst"


def is_nsis_installer(source_path: Path) -> bool:
    """Return whether a PE overlay starts with an NSIS first header.

    :param source_path: Candidate Windows executable.
    :returns: ``True`` only for a structurally valid PE with the NSIS signature.
    """
    try:
        with source_path.open("rb") as stream:
            if stream.read(2) != b"MZ":
                return False
            stream.seek(0x3C)
            pe_offset_data = stream.read(4)
            if len(pe_offset_data) != 4:
                return False
            pe_offset = struct.unpack("<I", pe_offset_data)[0]
            stream.seek(pe_offset)
            if stream.read(4) != b"PE\0\0":
                return False
            coff_header = stream.read(20)
            if len(coff_header) != 20:
                return False
            number_of_sections = struct.unpack_from("<H", coff_header, 2)[0]
            optional_header_size = struct.unpack_from("<H", coff_header, 16)[0]
            if number_of_sections == 0:
                return False

            stream.seek(optional_header_size, 1)
            overlay_offset = 0
            for _ in range(number_of_sections):
                section_header = stream.read(40)
                if len(section_header) != 40:
                    return False
                raw_size = struct.unpack_from("<I", section_header, 16)[0]
                raw_offset = struct.unpack_from("<I", section_header, 20)[0]
                overlay_offset = max(overlay_offset, raw_offset + raw_size)

            stream.seek(overlay_offset + 4)
            return stream.read(len(_NSIS_FIRST_HEADER_SIGNATURE)) == _NSIS_FIRST_HEADER_SIGNATURE
    except (OSError, OverflowError, struct.error):
        return False
