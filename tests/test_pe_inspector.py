# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for PE binary inspection."""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import lief

from whatyouship.binary.pe import PeInspector
from whatyouship.inspectors.directory import DirectoryInspector


def _make_pe(kind: str) -> bytes:
    """Create a small PE payload for inspection tests.

    :param kind: ``executable`` or ``dll``.
    :returns: Serialized PE bytes.
    """
    with lief.logging.level_scope(lief.logging.LEVEL.OFF):
        factory = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)
        section = lief.PE.Section(".text")
        section.content = [0xC3]
        factory.add_section(section)
        binary = factory.get()
        characteristic = (
            lief.PE.Header.CHARACTERISTICS.DLL
            if kind == "dll"
            else lief.PE.Header.CHARACTERISTICS.EXECUTABLE_IMAGE
        )
        binary.header.add_characteristic(characteristic)
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "sample.exe"
            binary.write(path)
            return path.read_bytes()


class PeInspectorTests(unittest.TestCase):
    """Verify PE identification, metadata, and parse error isolation."""

    def test_inspects_executable_from_path_and_bytes(self) -> None:
        """Identify a generated x86-64 executable from both input forms."""
        payload = _make_pe("executable")
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "sample.exe"
            path.write_bytes(payload)

            from_path = PeInspector().inspect(path)
            from_bytes = PeInspector().inspect(payload)

        self.assertEqual(from_path, from_bytes)
        self.assertIsNotNone(from_path)
        self.assertEqual(from_path.format, "PE")
        self.assertEqual(from_path.architecture, "x86_64")
        self.assertEqual(from_path.kind, "executable")
        self.assertIsNone(from_path.file_version)
        self.assertIsNone(from_path.product_version)
        self.assertFalse(from_path.signature.present)

    def test_identifies_dll(self) -> None:
        """Distinguish a generated DLL from an executable."""
        metadata = PeInspector().inspect(_make_pe("dll"))

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.kind, "dll")

    def test_directory_inspector_attaches_pe_metadata(self) -> None:
        """Attach PE metadata by content and skip a non-PE executable file."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "app.exe").write_bytes(_make_pe("executable"))
            (root / "fake.exe").write_bytes(b"plain text")

            artifact = DirectoryInspector().inspect(root)

            self.assertEqual(artifact.files[0].binary.format, "PE")
            self.assertEqual(artifact.files[0].binary.kind, "executable")
            self.assertIsNone(artifact.files[1].binary)

    def test_reads_embedded_versions(self) -> None:
        """Prefer embedded version strings when the resource provides them."""
        table = Mock()
        table.get.side_effect = {"FileVersion": "1.2.3", "ProductVersion": "4.5.6"}.get
        version = SimpleNamespace(
            string_file_info=SimpleNamespace(children=[table]),
            file_info=SimpleNamespace(
                file_version_ms=0,
                file_version_ls=0,
                product_version_ms=0,
                product_version_ls=0,
            ),
        )
        header = Mock()
        header.machine = lief.PE.Header.MACHINE_TYPES.I386
        header.has_characteristic.side_effect = [False, True]
        binary = SimpleNamespace(
            header=header,
            has_resources=True,
            resources_manager=SimpleNamespace(has_version=True, version=[version]),
        )

        with patch("whatyouship.binary.pe.lief.PE.parse", return_value=binary):
            metadata = PeInspector().inspect(b"MZsynthetic")

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.architecture, "x86")
        self.assertEqual(metadata.file_version, "1.2.3")
        self.assertEqual(metadata.product_version, "4.5.6")

    def test_uses_fixed_versions_when_strings_are_absent(self) -> None:
        """Format numeric file and product versions from a version resource."""
        version = SimpleNamespace(
            string_file_info=None,
            file_info=SimpleNamespace(
                file_version_ms=(1 << 16) | 2,
                file_version_ls=(3 << 16) | 4,
                product_version_ms=(5 << 16) | 6,
                product_version_ls=(7 << 16) | 8,
            ),
        )
        header = Mock()
        header.machine = lief.PE.Header.MACHINE_TYPES.AMD64
        header.has_characteristic.side_effect = [False, True]
        binary = SimpleNamespace(
            header=header,
            has_resources=True,
            resources_manager=SimpleNamespace(has_version=True, version=[version]),
        )

        with patch("whatyouship.binary.pe.lief.PE.parse", return_value=binary):
            metadata = PeInspector().inspect(b"MZsynthetic")

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.file_version, "1.2.3.4")
        self.assertEqual(metadata.product_version, "5.6.7.8")

    def test_preserves_string_version_when_fixed_info_is_unavailable(self) -> None:
        """Keep an available string version if fixed version data is absent."""
        table = Mock()
        table.get.side_effect = {"FileVersion": "1.2.3"}.get
        version = SimpleNamespace(
            string_file_info=SimpleNamespace(children=[table]),
            file_info=None,
        )
        header = Mock()
        header.machine = lief.PE.Header.MACHINE_TYPES.I386
        header.has_characteristic.side_effect = [False, True]
        binary = SimpleNamespace(
            header=header,
            has_resources=True,
            resources_manager=SimpleNamespace(has_version=True, version=[version]),
        )

        with patch("whatyouship.binary.pe.lief.PE.parse", return_value=binary):
            metadata = PeInspector().inspect(b"MZsynthetic")

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.file_version, "1.2.3")
        self.assertIsNone(metadata.product_version)

    def test_skips_non_pe_and_parse_failures(self) -> None:
        """Return no metadata for other files and failed PE parses."""
        self.assertIsNone(PeInspector().inspect(b"plain text"))
        with patch("whatyouship.binary.pe.lief.PE.parse", side_effect=RuntimeError("bad PE")):
            self.assertIsNone(PeInspector().inspect(b"MZbroken"))

    def test_reads_signed_pe_metadata(self) -> None:
        """Read verification result, signer subject, and timestamp presence."""
        signer = SimpleNamespace(
            cert=SimpleNamespace(subject="CN=Example Publisher"),
            unauthenticated_attributes=[Mock(spec=lief.PE.PKCS9CounterSignature)],
        )
        signature = SimpleNamespace(signers=[signer])
        header = Mock()
        header.machine = lief.PE.Header.MACHINE_TYPES.AMD64
        header.has_characteristic.side_effect = [False, True]
        binary = SimpleNamespace(
            header=header,
            has_resources=False,
            signatures=[signature],
            verify_signature=Mock(return_value=lief.PE.Signature.VERIFICATION_FLAGS.OK),
        )

        with patch("whatyouship.binary.pe.lief.PE.parse", return_value=binary):
            metadata = PeInspector().inspect(b"MZsynthetic")

        self.assertIsNotNone(metadata)
        self.assertTrue(metadata.signature.present)
        self.assertTrue(metadata.signature.valid)
        self.assertEqual(metadata.signature.signer, "CN=Example Publisher")
        self.assertTrue(metadata.signature.timestamp)
        binary.verify_signature.assert_called_once_with(signature)

    def test_signature_verification_failure_preserves_pe_metadata(self) -> None:
        """Keep PE properties when signature verification raises an error."""
        signer = SimpleNamespace(cert=None, unauthenticated_attributes=[])
        header = Mock()
        header.machine = lief.PE.Header.MACHINE_TYPES.AMD64
        header.has_characteristic.side_effect = [False, True]
        binary = SimpleNamespace(
            header=header,
            has_resources=False,
            signatures=[SimpleNamespace(signers=[signer])],
            verify_signature=Mock(side_effect=RuntimeError("verification failed")),
        )

        with patch("whatyouship.binary.pe.lief.PE.parse", return_value=binary):
            metadata = PeInspector().inspect(b"MZsynthetic")

        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.kind, "executable")
        self.assertTrue(metadata.signature.present)
        self.assertIsNone(metadata.signature.valid)
        self.assertFalse(metadata.signature.timestamp)

    def test_invalid_signature_is_reported(self) -> None:
        """Keep a present signature distinct from a valid signature."""
        header = Mock()
        header.machine = lief.PE.Header.MACHINE_TYPES.AMD64
        header.has_characteristic.side_effect = [False, True]
        binary = SimpleNamespace(
            header=header,
            has_resources=False,
            signatures=[SimpleNamespace(signers=[])],
            verify_signature=Mock(return_value=lief.PE.Signature.VERIFICATION_FLAGS.BAD_DIGEST),
        )

        with patch("whatyouship.binary.pe.lief.PE.parse", return_value=binary):
            metadata = PeInspector().inspect(b"MZsynthetic")

        self.assertIsNotNone(metadata)
        self.assertTrue(metadata.signature.present)
        self.assertFalse(metadata.signature.valid)

    def test_signature_read_error_does_not_mark_pe_unsigned(self) -> None:
        """Treat an inaccessible signature list as unknown."""
        header = Mock()
        header.machine = lief.PE.Header.MACHINE_TYPES.AMD64
        header.has_characteristic.side_effect = [False, True]
        binary = SimpleNamespace(header=header, has_resources=False)

        with patch("whatyouship.binary.pe.lief.PE.parse", return_value=binary):
            metadata = PeInspector().inspect(b"MZsynthetic")

        self.assertIsNotNone(metadata)
        self.assertIsNone(metadata.signature.present)


if __name__ == "__main__":
    unittest.main()
