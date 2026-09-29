# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for Mach-O binary inspection."""

import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import lief

from whatyouship.binary.macho import MachOInspector
from whatyouship.inspectors.directory import DirectoryInspector


_CPU_X86_64 = 0x01000007
_CPU_ARM64 = 0x0100000C
_FILE_EXECUTE = 0x2
_FILE_DYLIB = 0x6
_FILE_OBJECT = 0x1


def _make_thin_macho(cpu_type: int, file_type: int) -> bytes:
    """Create a minimal 64-bit little-endian Mach-O payload.

    :param cpu_type: Mach-O CPU type value.
    :param file_type: Mach-O file type value.
    :returns: Serialized Mach-O header.
    """
    cpu_subtype = 3 if cpu_type == _CPU_X86_64 else 0
    return struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        cpu_type,
        cpu_subtype,
        file_type,
        0,
        0,
        0,
        0,
    )


def _make_universal_macho() -> bytes:
    """Create a minimal universal executable with two slices.

    :returns: Serialized fat Mach-O payload.
    """
    x86_64 = _make_thin_macho(_CPU_X86_64, _FILE_EXECUTE)
    arm64 = _make_thin_macho(_CPU_ARM64, _FILE_EXECUTE)
    x86_64_offset = 0x100
    arm64_offset = 0x200
    header = struct.pack(">II", 0xCAFEBABE, 2)
    architectures = b"".join(
        (
            struct.pack(
                ">IIIII",
                _CPU_X86_64,
                3,
                x86_64_offset,
                len(x86_64),
                8,
            ),
            struct.pack(
                ">IIIII",
                _CPU_ARM64,
                0,
                arm64_offset,
                len(arm64),
                8,
            ),
        )
    )
    payload = header + architectures
    payload += bytes(x86_64_offset - len(payload)) + x86_64
    payload += bytes(arm64_offset - len(payload)) + arm64
    return payload


class MachOInspectorTests(unittest.TestCase):
    """Verify thin and universal Mach-O metadata extraction."""

    def test_inspects_thin_executable_from_path_and_bytes(self) -> None:
        """Identify an arm64 executable from both supported input forms."""
        payload = _make_thin_macho(_CPU_ARM64, _FILE_EXECUTE)
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "application"
            path.write_bytes(payload)

            from_path = MachOInspector().inspect(path)
            from_bytes = MachOInspector().inspect(payload)

        self.assertEqual(from_path, from_bytes)
        self.assertIsNotNone(from_path)
        self.assertEqual(from_path.format, "Mach-O")
        self.assertEqual(from_path.architecture, "arm64")
        self.assertEqual(from_path.kind, "executable")
        self.assertIsNone(from_path.file_version)
        self.assertIsNone(from_path.product_version)
        self.assertIsNone(from_path.signature)

    def test_inspects_universal_binary_with_canonical_architecture_order(self) -> None:
        """Combine and sort architecture names from all universal slices."""
        metadata = MachOInspector().inspect(_make_universal_macho())

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.architecture, "arm64+x86_64")
        self.assertEqual(metadata.kind, "executable")

    def test_maps_dynamic_library_and_other_file_types(self) -> None:
        """Map Mach-O header types to format-independent binary kinds."""
        library = MachOInspector().inspect(
            _make_thin_macho(_CPU_X86_64, _FILE_DYLIB)
        )
        other = MachOInspector().inspect(
            _make_thin_macho(_CPU_X86_64, _FILE_OBJECT)
        )

        self.assertIsNotNone(library)
        self.assertIsNotNone(other)
        self.assertEqual(library.kind, "library")
        self.assertEqual(other.kind, "other")

    def test_directory_inspector_attaches_macho_metadata(self) -> None:
        """Analyze Mach-O files through the shared directory pipeline."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "application").write_bytes(_make_universal_macho())

            artifact = DirectoryInspector().inspect(root)

        self.assertEqual(artifact.files[0].binary.format, "Mach-O")
        self.assertEqual(artifact.files[0].binary.architecture, "arm64+x86_64")

    def test_skips_other_files_and_parse_failures(self) -> None:
        """Return no metadata for non-Mach-O and malformed payloads."""
        self.assertIsNone(MachOInspector().inspect(b"plain text"))
        with patch(
            "whatyouship.binary.macho.lief.MachO.parse",
            side_effect=RuntimeError("bad Mach-O"),
        ):
            self.assertIsNone(
                MachOInspector().inspect(_make_thin_macho(_CPU_ARM64, _FILE_EXECUTE))
            )

    def test_mixed_slice_kinds_are_other(self) -> None:
        """Do not choose an arbitrary kind for inconsistent universal slices."""
        executable = type("Binary", (), {})()
        executable.header = type("Header", (), {
            "cpu_type": lief.MachO.Header.CPU_TYPE.X86_64,
            "file_type": lief.MachO.Header.FILE_TYPE.EXECUTE,
        })()
        library = type("Binary", (), {})()
        library.header = type("Header", (), {
            "cpu_type": lief.MachO.Header.CPU_TYPE.ARM64,
            "file_type": lief.MachO.Header.FILE_TYPE.DYLIB,
        })()

        with patch(
            "whatyouship.binary.macho.lief.MachO.parse",
            return_value=[executable, library],
        ):
            metadata = MachOInspector().inspect(_make_universal_macho())

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.kind, "other")


if __name__ == "__main__":
    unittest.main()
