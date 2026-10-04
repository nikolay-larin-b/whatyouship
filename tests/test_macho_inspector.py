# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for Mach-O binary inspection."""

import struct
import plistlib
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import lief

from whatyouship.binary.macho import MachOInspector
from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.model import BinaryDependency, BinaryEntitlement
from whatyouship.rules.unsigned_binary import UnsignedBinaryRule


_CPU_X86_64 = 0x01000007
_CPU_ARM64 = 0x0100000C
_FILE_EXECUTE = 0x2
_FILE_DYLIB = 0x6
_FILE_OBJECT = 0x1


def _packed_version(version: tuple[int, int, int]) -> int:
    """Encode a Mach-O load-command version.

    :param version: Major, minor, and patch components.
    :returns: Packed Mach-O version integer.
    """
    major, minor, patch = version
    return major << 16 | minor << 8 | patch


def _make_thin_macho(
    cpu_type: int,
    file_type: int,
    minimum_os_version: tuple[int, int, int] | None = None,
    *,
    legacy_version_command: bool = False,
) -> bytes:
    """Create a minimal 64-bit little-endian Mach-O payload.

    :param cpu_type: Mach-O CPU type value.
    :param file_type: Mach-O file type value.
    :param minimum_os_version: Optional macOS deployment target.
    :param legacy_version_command: Whether to use ``LC_VERSION_MIN_MACOSX``.
    :returns: Serialized Mach-O header.
    """
    cpu_subtype = 3 if cpu_type == _CPU_X86_64 else 0
    command = b""
    if minimum_os_version is not None:
        encoded_version = _packed_version(minimum_os_version)
        if legacy_version_command:
            command = struct.pack(
                "<IIII",
                0x24,
                16,
                encoded_version,
                _packed_version((14, 4, 0)),
            )
        else:
            command = struct.pack(
                "<IIIIII",
                0x32,
                24,
                1,
                encoded_version,
                _packed_version((14, 4, 0)),
                0,
            )
    header = struct.pack(
        "<IIIIIIII",
        0xFEEDFACF,
        cpu_type,
        cpu_subtype,
        file_type,
        1 if command else 0,
        len(command),
        0,
        0,
    )
    return header + command


def _make_universal_macho(
    x86_64_minimum: tuple[int, int, int] | None = None,
    arm64_minimum: tuple[int, int, int] | None = None,
) -> bytes:
    """Create a minimal universal executable with two slices.

    :param x86_64_minimum: Optional x86-64 macOS deployment target.
    :param arm64_minimum: Optional arm64 macOS deployment target.
    :returns: Serialized fat Mach-O payload.
    """
    x86_64 = _make_thin_macho(
        _CPU_X86_64, _FILE_EXECUTE, x86_64_minimum
    )
    arm64 = _make_thin_macho(_CPU_ARM64, _FILE_EXECUTE, arm64_minimum)
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


def _make_embedded_signature(
    signature_type: str,
    *,
    hardened_runtime: bool = False,
    entitlements: dict[str, object] | None = None,
) -> bytes:
    """Create a minimal ad hoc or certificate signature superblob.

    :param signature_type: ``ad-hoc`` or ``certificate``.
    :param hardened_runtime: Whether to set the CodeDirectory runtime flag.
    :param entitlements: Optional embedded entitlement property list.
    :returns: Serialized embedded signature payload.
    """
    flags = 0x2 if signature_type == "ad-hoc" else 0
    if hardened_runtime:
        flags |= 0x10000
    code_directory = struct.pack(
        ">9I4BI",
        0xFADE0C02,
        44,
        0x20001,
        flags,
        44,
        0,
        0,
        0,
        0,
        32,
        2,
        0,
        0,
        0,
    )
    entries = [(0, code_directory)]
    if entitlements is not None:
        payload = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)
        entries.append((5, struct.pack(">II", 0xFADE7171, len(payload) + 8) + payload))
    if signature_type == "certificate":
        entries.append((0x10000, struct.pack(">II", 0xFADE0B01, 9) + b"\x30"))
    offset = 12 + 8 * len(entries)
    indexes = []
    blobs = []
    for slot, blob in entries:
        indexes.append(struct.pack(">II", slot, offset))
        blobs.append(blob)
        offset += len(blob)
    return (
        struct.pack(">III", 0xFADE0CC0, offset, len(entries))
        + b"".join(indexes)
        + b"".join(blobs)
    )


def _mock_slice(
    cpu_type: lief.MachO.Header.CPU_TYPE,
    file_type: lief.MachO.Header.FILE_TYPE,
    signature: bytes | None,
    dependencies: tuple[
        tuple[str, lief.MachO.LoadCommand.TYPE], ...
    ] = (),
    runtime_search_paths: tuple[str, ...] = (),
    *,
    data_offset: int | None = None,
    fat_offset: int | None = None,
) -> SimpleNamespace:
    """Build the Mach-O slice interface used by the inspector.

    :param cpu_type: Slice architecture.
    :param file_type: Slice binary kind.
    :param signature: Embedded signature payload, or ``None``.
    :param dependencies: Library names and load-command types.
    :param runtime_search_paths: Runtime search paths.
    :param data_offset: Optional slice-relative signature offset.
    :param fat_offset: Optional slice offset in a universal file.
    :returns: Minimal parsed-slice replacement.
    """
    code_signature = None if signature is None else SimpleNamespace(
        content=signature,
        data_offset=data_offset,
    )
    return SimpleNamespace(
        header=SimpleNamespace(cpu_type=cpu_type, file_type=file_type),
        code_signature=code_signature,
        fat_offset=fat_offset,
        libraries=[
            SimpleNamespace(name=name, command=command)
            for name, command in dependencies
        ],
        rpaths=[SimpleNamespace(path=path) for path in runtime_search_paths],
    )


def _make_verifiable_signature(
    signed_content: bytes,
    signature_type: str,
    team_id: str = "TEAM123456",
) -> bytes:
    """Create a signature with a valid SHA-256 code-slot digest.

    :param signed_content: Slice bytes covered by the CodeDirectory.
    :param signature_type: ``ad-hoc`` or ``certificate``.
    :param team_id: Team identifier embedded in the CodeDirectory.
    :returns: Serialized embedded signature payload.
    """
    identifier = b"com.example.sample\x00"
    team = team_id.encode("utf-8") + b"\x00"
    hash_offset = 52 + len(identifier) + len(team)
    flags = 0x2 if signature_type == "ad-hoc" else 0
    code_directory = struct.pack(
        ">9I4BIII",
        0xFADE0C02,
        hash_offset + 32,
        0x20200,
        flags,
        hash_offset,
        52,
        0,
        1,
        len(signed_content),
        32,
        2,
        0,
        12,
        0,
        0,
        52 + len(identifier),
    )
    code_directory += identifier + team + hashlib.sha256(signed_content).digest()
    entries = [(0, code_directory)]
    if signature_type == "certificate":
        entries.append((0x10000, struct.pack(">II", 0xFADE0B01, 9) + b"\x30"))
    offset = 12 + 8 * len(entries)
    indexes = []
    blobs = []
    for slot, blob in entries:
        indexes.append(struct.pack(">II", slot, offset))
        blobs.append(blob)
        offset += len(blob)
    return (
        struct.pack(">III", 0xFADE0CC0, offset, len(entries))
        + b"".join(indexes)
        + b"".join(blobs)
    )


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
        self.assertIsNotNone(from_path.signature)
        self.assertFalse(from_path.signature.present)
        self.assertIsNone(from_path.signature.signature_type)

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

    def test_reads_modern_and_legacy_macos_deployment_targets(self) -> None:
        """Read both deployment-target load commands without macOS tools."""
        modern = MachOInspector().inspect(
            _make_thin_macho(
                _CPU_ARM64,
                _FILE_EXECUTE,
                (13, 2, 0),
            )
        )
        legacy = MachOInspector().inspect(
            _make_thin_macho(
                _CPU_X86_64,
                _FILE_EXECUTE,
                (10, 15, 7),
                legacy_version_command=True,
            )
        )

        self.assertIsNotNone(modern)
        self.assertIsNotNone(legacy)
        self.assertEqual(modern.minimum_os_version, "13.2")
        self.assertEqual(legacy.minimum_os_version, "10.15.7")

    def test_uses_highest_complete_universal_deployment_target(self) -> None:
        """Require every universal slice and report their highest target."""
        complete = MachOInspector().inspect(
            _make_universal_macho((11, 0, 0), (12, 3, 0))
        )
        incomplete = MachOInspector().inspect(
            _make_universal_macho((11, 0, 0), None)
        )

        self.assertIsNotNone(complete)
        self.assertIsNotNone(incomplete)
        self.assertEqual(complete.minimum_os_version, "12.3")
        self.assertIsNone(incomplete.minimum_os_version)

    def test_combines_dependencies_and_runtime_search_paths(self) -> None:
        """Merge slice imports while excluding each library's install ID."""
        load = lief.MachO.LoadCommand.TYPE.LOAD_DYLIB
        weak = lief.MachO.LoadCommand.TYPE.LOAD_WEAK_DYLIB
        identifier = lief.MachO.LoadCommand.TYPE.ID_DYLIB
        slices = [
            _mock_slice(
                lief.MachO.Header.CPU_TYPE.X86_64,
                lief.MachO.Header.FILE_TYPE.DYLIB,
                None,
                (
                    ("@rpath/libShared.dylib", weak),
                    ("@rpath/libOptional.dylib", weak),
                    ("@rpath/libX86.dylib", load),
                    ("@rpath/libSelf.dylib", identifier),
                ),
                ("@loader_path/../Frameworks",),
            ),
            _mock_slice(
                lief.MachO.Header.CPU_TYPE.ARM64,
                lief.MachO.Header.FILE_TYPE.DYLIB,
                None,
                (
                    ("@rpath/libArm.dylib", load),
                    ("@rpath/libShared.dylib", load),
                ),
                ("@loader_path",),
            ),
        ]
        with patch(
            "whatyouship.binary.macho.lief.MachO.parse",
            return_value=slices,
        ):
            metadata = MachOInspector().inspect(_make_universal_macho())

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.dependencies, (
            BinaryDependency("@rpath/libArm.dylib"),
            BinaryDependency("@rpath/libOptional.dylib", required=False),
            BinaryDependency("@rpath/libShared.dylib"),
            BinaryDependency("@rpath/libX86.dylib"),
        ))
        self.assertEqual(
            metadata.runtime_search_paths,
            ("@loader_path", "@loader_path/../Frameworks"),
        )

    def test_directory_inspector_attaches_macho_metadata(self) -> None:
        """Analyze and lint Mach-O files through the shared directory pipeline."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "application").write_bytes(_make_universal_macho())

            artifact = DirectoryInspector().inspect(root)

        self.assertEqual(artifact.files[0].binary.format, "Mach-O")
        self.assertEqual(artifact.files[0].binary.architecture, "arm64+x86_64")
        findings = UnsignedBinaryRule().check(artifact)
        self.assertEqual(
            [finding.relative_path for finding in findings],
            [Path("application")],
        )

    def test_classifies_ad_hoc_and_certificate_signatures(self) -> None:
        """Distinguish ad hoc CodeDirectory flags from CMS signatures."""
        for signature_type in ("ad-hoc", "certificate"):
            with (
                self.subTest(signature_type=signature_type),
                patch(
                    "whatyouship.binary.macho.lief.MachO.parse",
                    return_value=[
                        _mock_slice(
                            lief.MachO.Header.CPU_TYPE.ARM64,
                            lief.MachO.Header.FILE_TYPE.EXECUTE,
                            _make_embedded_signature(signature_type),
                        )
                    ],
                ),
                patch(
                    "whatyouship.binary.macho._cms_signature",
                    return_value=SimpleNamespace(
                        valid=None,
                        trusted=None,
                        signer=None,
                        timestamp=None,
                    ),
                ),
            ):
                metadata = MachOInspector().inspect(
                    _make_thin_macho(_CPU_ARM64, _FILE_EXECUTE)
                )

            self.assertIsNotNone(metadata)
            self.assertTrue(metadata.signature.present)
            self.assertEqual(metadata.signature.signature_type, signature_type)
            self.assertIsNone(metadata.signature.valid)

    def test_validates_ad_hoc_code_directory_page_hashes(self) -> None:
        """Validate signed ranges without relying on native macOS services."""
        payload = _make_thin_macho(_CPU_ARM64, _FILE_EXECUTE)
        signature = _make_verifiable_signature(payload, "ad-hoc")
        binary = _mock_slice(
            lief.MachO.Header.CPU_TYPE.ARM64,
            lief.MachO.Header.FILE_TYPE.EXECUTE,
            signature,
            data_offset=len(payload),
            fat_offset=0,
        )
        with patch(
            "whatyouship.binary.macho.lief.MachO.parse",
            return_value=[binary],
        ):
            valid = MachOInspector().inspect(payload)
            invalid = MachOInspector().inspect(payload[:-1] + b"\x01")

        self.assertIsNotNone(valid)
        self.assertTrue(valid.signature.valid)
        self.assertFalse(valid.signature.trusted)
        self.assertEqual(valid.signature.team_id, "TEAM123456")
        self.assertIsNotNone(invalid)
        self.assertFalse(invalid.signature.valid)

    def test_reads_native_certificate_verification_metadata(self) -> None:
        """Combine static hashes with native CMS and trust verification."""
        payload = _make_thin_macho(_CPU_ARM64, _FILE_EXECUTE)
        signature = _make_verifiable_signature(payload, "certificate")
        binary = _mock_slice(
            lief.MachO.Header.CPU_TYPE.ARM64,
            lief.MachO.Header.FILE_TYPE.EXECUTE,
            signature,
            data_offset=len(payload),
            fat_offset=0,
        )
        native = SimpleNamespace(
            valid=True,
            trusted=True,
            signer="Developer ID Application: Example",
            timestamp=True,
            team_id="TEAM123456",
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "application"
            path.write_bytes(payload)
            with (
                patch(
                    "whatyouship.binary.macho.lief.MachO.parse",
                    return_value=[binary],
                ),
                patch(
                    "whatyouship.binary.macho._native_signature",
                    return_value=native,
                ),
                patch(
                    "whatyouship.binary.macho._cms_signature",
                    return_value=SimpleNamespace(
                        valid=True,
                        trusted=True,
                        signer="Developer ID Application: Example",
                        timestamp=True,
                    ),
                ),
            ):
                metadata = MachOInspector().inspect(path)

        self.assertIsNotNone(metadata)
        self.assertTrue(metadata.signature.valid)
        self.assertTrue(metadata.signature.trusted)
        self.assertEqual(
            metadata.signature.signer,
            "Developer ID Application: Example",
        )
        self.assertTrue(metadata.signature.timestamp)
        self.assertEqual(metadata.signature.team_id, "TEAM123456")

    def test_reads_hardened_runtime_and_embedded_entitlements(self) -> None:
        """Extract release-signing metadata without invoking macOS tools."""
        signature = _make_embedded_signature(
            "certificate",
            hardened_runtime=True,
            entitlements={
                "com.apple.security.app-sandbox": True,
                "com.apple.security.network.client": True,
                "com.example.groups": ["first", "second"],
            },
        )
        with patch(
            "whatyouship.binary.macho.lief.MachO.parse",
            return_value=[_mock_slice(
                lief.MachO.Header.CPU_TYPE.ARM64,
                lief.MachO.Header.FILE_TYPE.EXECUTE,
                signature,
            )],
        ):
            metadata = MachOInspector().inspect(
                _make_thin_macho(_CPU_ARM64, _FILE_EXECUTE)
            )

        self.assertIsNotNone(metadata)
        self.assertTrue(metadata.signature.hardened_runtime)
        self.assertEqual(metadata.signature.entitlements, (
            BinaryEntitlement("com.apple.security.app-sandbox", "true"),
            BinaryEntitlement("com.apple.security.network.client", "true"),
            BinaryEntitlement("com.example.groups", '["first","second"]'),
        ))

    def test_requires_hardened_runtime_in_every_universal_slice(self) -> None:
        """Aggregate Hardened Runtime conservatively across slices."""
        slices = [
            _mock_slice(
                lief.MachO.Header.CPU_TYPE.X86_64,
                lief.MachO.Header.FILE_TYPE.EXECUTE,
                _make_embedded_signature("certificate", hardened_runtime=True),
            ),
            _mock_slice(
                lief.MachO.Header.CPU_TYPE.ARM64,
                lief.MachO.Header.FILE_TYPE.EXECUTE,
                _make_embedded_signature("certificate"),
            ),
        ]
        with patch(
            "whatyouship.binary.macho.lief.MachO.parse",
            return_value=slices,
        ):
            metadata = MachOInspector().inspect(_make_universal_macho())

        self.assertIsNotNone(metadata)
        self.assertFalse(metadata.signature.hardened_runtime)

    def test_requires_every_universal_slice_to_be_signed(self) -> None:
        """Treat a partially signed universal binary as unsigned."""
        slices = [
            _mock_slice(
                lief.MachO.Header.CPU_TYPE.X86_64,
                lief.MachO.Header.FILE_TYPE.DYLIB,
                _make_embedded_signature("certificate"),
            ),
            _mock_slice(
                lief.MachO.Header.CPU_TYPE.ARM64,
                lief.MachO.Header.FILE_TYPE.DYLIB,
                None,
            ),
        ]
        with patch(
            "whatyouship.binary.macho.lief.MachO.parse",
            return_value=slices,
        ):
            metadata = MachOInspector().inspect(_make_universal_macho())

        self.assertIsNotNone(metadata)
        self.assertFalse(metadata.signature.present)
        self.assertEqual(metadata.signature.signature_type, "mixed")

    def test_preserves_metadata_when_signature_type_is_unreadable(self) -> None:
        """Keep Mach-O properties when a signature payload is malformed."""
        binary = _mock_slice(
            lief.MachO.Header.CPU_TYPE.ARM64,
            lief.MachO.Header.FILE_TYPE.EXECUTE,
            b"invalid signature",
        )
        with patch(
            "whatyouship.binary.macho.lief.MachO.parse",
            return_value=[binary],
        ):
            metadata = MachOInspector().inspect(
                _make_thin_macho(_CPU_ARM64, _FILE_EXECUTE)
            )

        self.assertIsNotNone(metadata)
        self.assertIsNone(metadata.signature.present)
        self.assertIsNone(metadata.signature.signature_type)

    def test_preserves_metadata_when_deployment_target_is_unreadable(self) -> None:
        """Keep other Mach-O properties when target extraction fails."""
        with patch(
            "whatyouship.binary.macho._minimum_os_version",
            side_effect=RuntimeError("bad deployment target"),
        ):
            metadata = MachOInspector().inspect(
                _make_thin_macho(_CPU_ARM64, _FILE_EXECUTE)
            )

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.architecture, "arm64")
        self.assertIsNone(metadata.minimum_os_version)

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
        executable = _mock_slice(
            lief.MachO.Header.CPU_TYPE.X86_64,
            lief.MachO.Header.FILE_TYPE.EXECUTE,
            None,
        )
        library = _mock_slice(
            lief.MachO.Header.CPU_TYPE.ARM64,
            lief.MachO.Header.FILE_TYPE.DYLIB,
            None,
        )

        with patch(
            "whatyouship.binary.macho.lief.MachO.parse",
            return_value=[executable, library],
        ):
            metadata = MachOInspector().inspect(_make_universal_macho())

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.kind, "other")


if __name__ == "__main__":
    unittest.main()
