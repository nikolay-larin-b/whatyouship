# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Identify Inno Setup installers without executing or extracting them."""

import struct
from pathlib import Path
from typing import BinaryIO


_LEGACY_BOOTSTRAP_MAGIC = 0x6F6E6E49  # "Inno"
_RESOURCE_TYPE_DATA = 10
_RESOURCE_NAME_INSTALLER = 11111
_LOADER_SIGNATURES = {
    b"rDlPtS02\x87eVx",
    b"rDlPtS04\x87eVx",
    b"rDlPtS05\x87eVx",
    b"rDlPtS06\x87eVx",
    b"rDlPtS07\x87eVx",
    b"rDlPtS\xcd\xe6\xd7{\x0b*",
    b"nS5W7dT\x83\xaa\x1b\x0fj",
}


def _read_at(stream: BinaryIO, offset: int, size: int) -> bytes:
    """Read an exact byte range or return an empty value.

    :param stream: Candidate installer stream.
    :param offset: Absolute file offset.
    :param size: Number of bytes to read.
    :returns: Requested bytes, or ``b""`` when unavailable.
    """
    if offset < 0 or size < 0:
        return b""
    stream.seek(offset)
    value = stream.read(size)
    return value if len(value) == size else b""


def _resource_entry(
    stream: BinaryIO,
    resource_base: int,
    resource_size: int,
    directory_offset: int,
    target_id: int | None,
) -> int | None:
    """Find a numeric PE resource entry or select the first entry.

    :param stream: Candidate installer stream.
    :param resource_base: File offset of the resource directory root.
    :param resource_size: Size of the PE resource directory.
    :param directory_offset: Directory offset relative to the root.
    :param target_id: Numeric resource ID, or ``None`` for the first entry.
    :returns: Raw resource entry offset and directory flag.
    """
    if directory_offset < 0 or directory_offset + 16 > resource_size:
        return None
    header = _read_at(stream, resource_base + directory_offset, 16)
    if not header:
        return None
    named_count, id_count = struct.unpack_from("<HH", header, 12)
    entries_offset = resource_base + directory_offset + 16
    if directory_offset + 16 + (named_count + id_count) * 8 > resource_size:
        return None
    for index in range(named_count + id_count):
        entry = _read_at(stream, entries_offset + index * 8, 8)
        if not entry:
            return None
        name, offset = struct.unpack("<II", entry)
        if target_id is None or (
            name & 0x80000000 == 0 and name == target_id
        ):
            return offset
    return None


def _inno_resource_signature(stream: BinaryIO, pe_offset: int) -> bytes:
    """Read the Inno loader signature from PE resource ``RCDATA/11111``.

    :param stream: Candidate installer stream.
    :param pe_offset: File offset of the PE signature.
    :returns: Loader signature, or ``b""`` when the resource is absent.
    """
    coff_header = _read_at(stream, pe_offset + 4, 20)
    if not coff_header:
        return b""
    section_count = struct.unpack_from("<H", coff_header, 2)[0]
    optional_size = struct.unpack_from("<H", coff_header, 16)[0]
    optional = _read_at(stream, pe_offset + 24, optional_size)
    if len(optional) < 112:
        return b""
    magic = struct.unpack_from("<H", optional)[0]
    if magic == 0x10B:
        count_offset, directories_offset = 92, 96
    elif magic == 0x20B:
        count_offset, directories_offset = 108, 112
    else:
        return b""
    if len(optional) < directories_offset + 24:
        return b""
    if struct.unpack_from("<I", optional, count_offset)[0] < 3:
        return b""
    resource_rva, resource_size = struct.unpack_from(
        "<II", optional, directories_offset + 16
    )
    if resource_rva == 0 or resource_size < 16 or section_count == 0:
        return b""

    sections_offset = pe_offset + 24 + optional_size
    sections: list[tuple[int, int, int]] = []
    for index in range(section_count):
        section = _read_at(stream, sections_offset + index * 40, 40)
        if not section:
            return b""
        _virtual_size, virtual_address, raw_size, raw_address = struct.unpack_from(
            "<IIII", section, 8
        )
        sections.append((virtual_address, raw_size, raw_address))

    def file_offset(rva: int, size: int) -> int | None:
        """Translate an RVA using the candidate's PE section table.

        :param rva: Relative virtual address.
        :param size: Number of bytes that must be backed by file data.
        :returns: Corresponding file offset, or ``None``.
        """
        for virtual_address, raw_size, raw_address in sections:
            relative = rva - virtual_address
            if relative >= 0 and relative + size <= raw_size:
                return raw_address + rva - virtual_address
        return None

    resource_base = file_offset(resource_rva, resource_size)
    if resource_base is None:
        return b""
    type_entry = _resource_entry(
        stream, resource_base, resource_size, 0, _RESOURCE_TYPE_DATA
    )
    if type_entry is None or type_entry & 0x80000000 == 0:
        return b""
    name_entry = _resource_entry(
        stream,
        resource_base,
        resource_size,
        type_entry & 0x7FFFFFFF,
        _RESOURCE_NAME_INSTALLER,
    )
    if name_entry is None or name_entry & 0x80000000 == 0:
        return b""
    language_entry = _resource_entry(
        stream,
        resource_base,
        resource_size,
        name_entry & 0x7FFFFFFF,
        None,
    )
    if language_entry is None or language_entry & 0x80000000:
        return b""
    if language_entry + 16 > resource_size:
        return b""
    data_entry = _read_at(stream, resource_base + language_entry, 16)
    if not data_entry:
        return b""
    data_rva, data_size = struct.unpack_from("<II", data_entry)
    data_offset = file_offset(data_rva, 12)
    if data_offset is None or data_size < 12:
        return b""
    return _read_at(stream, data_offset, 12)


def is_inno_installer(source_path: Path) -> bool:
    """Return whether an executable has a recognized Inno loader header.

    :param source_path: Candidate Windows executable.
    :returns: ``True`` only for a structurally identified Inno Setup installer.
    """
    try:
        with source_path.open("rb") as stream:
            if _read_at(stream, 0, 2) != b"MZ":
                return False
            pe_offset_data = _read_at(stream, 0x3C, 4)
            if not pe_offset_data:
                return False
            pe_offset = struct.unpack("<I", pe_offset_data)[0]
            if _read_at(stream, pe_offset, 4) != b"PE\0\0":
                return False

            legacy = _read_at(stream, 0x30, 12)
            if legacy:
                magic, loader_offset, complement = struct.unpack("<III", legacy)
                if (
                    magic == _LEGACY_BOOTSTRAP_MAGIC
                    and loader_offset == ~complement & 0xFFFFFFFF
                    and _read_at(stream, loader_offset, 12) in _LOADER_SIGNATURES
                ):
                    return True
            return _inno_resource_signature(stream, pe_offset) in _LOADER_SIGNATURES
    except (OSError, OverflowError, struct.error):
        return False
