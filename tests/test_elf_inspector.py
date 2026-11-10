# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Portable tests for ELF content recognition and basic artifact analysis."""

import contextlib
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from whatyouship.binary.elf import ElfInspector
from whatyouship.binary.errors import BinaryAnalysisError
from whatyouship.inspectors.msi import MsiInspector
from whatyouship.model import ArtifactSignature, InstallationScope
from whatyouship.operations import inspect, lint
from whatyouship.renderers import render_report


def _make_elf(
    machine: int = 62,
    file_type: int = 2,
    *,
    bits: int = 64,
    endian: str = "<",
    interpreter: bool = False,
    static_pie: bool = False,
) -> bytes:
    """Construct an ELF header and optional loader segments without a compiler.

    :param machine: ELF machine number.
    :param file_type: ELF type, such as executable, shared object, or relocatable.
    :param bits: ELF class, 32 or 64 bits.
    :param endian: Struct byte order, little or big endian.
    :param interpreter: Whether to include a PT_INTERP segment.
    :param static_pie: Whether to include DF_1_PIE without requiring PT_INTERP.
    :returns: Serialized ELF bytes suitable for real LIEF parsing on any host.
    """
    identification = b"\x7fELF" + bytes((1 if bits == 32 else 2, 1 if endian == "<" else 2, 1)) + bytes(9)
    header_size, segment_size = (52, 32) if bits == 32 else (64, 56)
    count = 1 + int(interpreter) + int(static_pie) if interpreter or static_pie else 0
    offset = header_size + count * segment_size
    loader = b"/lib/test-loader.so\0" if interpreter else b""
    dynamic = (
        struct.pack(endian + ("IIII" if bits == 32 else "QQQQ"), 0x6FFFFFFB, 0x08000000, 0, 0)
        if static_pie else b""
    )
    header = struct.pack(
        endian + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"),
        file_type, machine, 1, 0, header_size if count else 0, 0, 0,
        header_size, segment_size, count, 40 if bits == 32 else 64, 0, 0,
    )
    segments = []
    if count:
        total_size = offset + len(loader) + len(dynamic)
        entries = [(1, 0, total_size)]
        if interpreter:
            entries.append((3, offset, len(loader)))
        if static_pie:
            entries.append((2, offset + len(loader), len(dynamic)))
        for kind, position, size in entries:
            values = (
                (kind, position, position, position, size, size, 4, 1)
                if bits == 32 else (kind, 4, position, position, position, size, size, 1)
            )
            segments.append(struct.pack(endian + ("IIIIIIII" if bits == 32 else "IIQQQQQQ"), *values))
    return identification + header + b"".join(segments) + loader + dynamic


class ElfInspectorTests(unittest.TestCase):
    """Exercise real ELF parsing with portable generated inputs."""

    def test_architectures_classes_and_byte_orders(self) -> None:
        """Normalize common ELF machine names across both ELF classes and byte orders."""
        cases = (
            (3, 32, "<", "x86"), (62, 64, "<", "x86_64"),
            (40, 32, "<", "arm"), (183, 64, "<", "arm64"),
            (20, 32, ">", "ppc"), (21, 64, ">", "ppc64"),
            (243, 32, "<", "riscv32"), (243, 64, "<", "riscv64"),
            (8, 32, ">", "mips32"), (8, 64, ">", "mips64"),
            (22, 64, ">", "s390x"), (258, 64, "<", "loongarch64"),
            (43, 64, ">", "sparcv9"),
        )
        for machine, bits, endian, expected in cases:
            with self.subTest(machine=machine, bits=bits, endian=endian):
                metadata = ElfInspector().inspect(_make_elf(machine, bits=bits, endian=endian))
                assert metadata is not None
                self.assertEqual(metadata.format, "ELF")
                self.assertEqual(metadata.architecture, expected)

    def test_binary_kinds_and_pie(self) -> None:
        """Distinguish executables, shared objects, dynamic PIE, and static PIE."""
        for bits, machine in ((32, 3), (64, 62)):
            for file_type, interpreter, pie, expected in (
                (2, False, False, "executable"),
                (3, False, False, "library"),
                (3, True, False, "executable"),
                (3, False, True, "executable"),
                (1, False, False, "other"),
                (4, False, False, "other"),
            ):
                with self.subTest(bits=bits, file_type=file_type, interpreter=interpreter, pie=pie):
                    metadata = ElfInspector().inspect(_make_elf(
                        machine, file_type, bits=bits, interpreter=interpreter, static_pie=pie,
                    ))
                    assert metadata is not None
                    self.assertEqual(metadata.kind, expected)
                    self.assertIsNone(metadata.signature)

    def test_accepts_path_bytes_and_memoryview(self) -> None:
        """Recognize an extensionless ELF identically in all supported input forms."""
        payload = _make_elf()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "program"
            path.write_bytes(payload)
            expected = ElfInspector().inspect(path)
        self.assertEqual(ElfInspector().inspect(payload), expected)
        self.assertEqual(ElfInspector().inspect(memoryview(payload)), expected)

    def test_non_elf_does_not_call_parser(self) -> None:
        """Do not infer ELF from a filename or an incomplete magic prefix."""
        with patch("whatyouship.binary.elf.lief.ELF.parse") as parser:
            for payload in (b"", b"\x7fEL", b"plain text", b"MZ", b"\xcf\xfa\xed\xfe"):
                self.assertIsNone(ElfInspector().inspect(payload))
            with tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "fake.so"
                path.write_bytes(b"plain text")
                self.assertIsNone(ElfInspector().inspect(path))
        parser.assert_not_called()

    def test_malformed_identification_and_truncated_headers(self) -> None:
        """Turn confidently recognized but incomplete ELF files into diagnostics."""
        payload = _make_elf()
        candidates = [payload[:size] for size in (4, 15, 16, 51, 63)]
        for position, value in ((4, 0), (4, 3), (5, 0), (5, 3), (6, 0)):
            malformed = bytearray(payload)
            malformed[position] = value
            candidates.append(bytes(malformed))
        for candidate in candidates:
            with self.subTest(candidate=candidate), self.assertRaises(BinaryAnalysisError) as raised:
                ElfInspector().inspect(candidate)
            self.assertEqual(raised.exception.binary_format, "ELF")
            self.assertTrue(raised.exception.reason)

    def test_parser_failures_are_normalized(self) -> None:
        """Isolate expected LIEF failures while preserving unexpected defects."""
        for error in (RuntimeError("broken"), ValueError("invalid")):
            with self.subTest(error=error), patch("whatyouship.binary.elf.lief.ELF.parse", side_effect=error):
                with self.assertRaises(BinaryAnalysisError):
                    ElfInspector().inspect(_make_elf())
        with patch("whatyouship.binary.elf.lief.ELF.parse", return_value=None):
            with self.assertRaisesRegex(BinaryAnalysisError, "LIEF could not parse"):
                ElfInspector().inspect(_make_elf())
        with patch("whatyouship.binary.elf.lief.ELF.parse", side_effect=TypeError("defect")):
            with self.assertRaises(TypeError):
                ElfInspector().inspect(_make_elf())

    def test_directory_zip_reports_and_lint(self) -> None:
        """Expose ELF metadata and diagnostics through normal artifact operations."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "payload"
            directory.mkdir()
            (directory / "program").write_bytes(_make_elf())
            (directory / "broken").write_bytes(b"\x7fELF")
            archive = root / "release.zip"
            with zipfile.ZipFile(archive, "w") as stream:
                stream.writestr("program", _make_elf())
                stream.writestr("broken", b"\x7fELF")
            for source in (directory, archive):
                with self.subTest(source=source):
                    report = inspect(source)
                    self.assertIsNone(report.artifact.files[0].binary)
                    self.assertEqual(report.artifact.files[1].binary.format, "ELF")
                    self.assertEqual(report.artifact.binary_diagnostics[0].format, "ELF")
                    self.assertIn("ELF", render_report(report, "text"))
                    data = json.loads(render_report(report, "json"))
                    self.assertEqual(data["artifact"]["files"][1]["binary"]["architecture"], "x86_64")
                    self.assertIn("ELF,x86_64,executable", render_report(report, "csv"))
                    self.assertEqual(lint(source).findings, [])

    def test_msi_payloads_receive_elf_analysis(self) -> None:
        """Analyze ELF payloads through MSI's specialized file traversal too."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "release.msi"
            source.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
            payload = root / "program"
            payload.write_bytes(_make_elf())
            cached = SimpleNamespace(relative_path=Path("program"), payload_path=payload,
                                     size_bytes=payload.stat().st_size, sha256="digest")
            with (
                patch("whatyouship.inspectors.msi.MsiPayloadCache.load_or_populate", return_value=[cached]),
                patch("whatyouship.inspectors.msi.MsiSignatureInspector.inspect", return_value=ArtifactSignature()),
                patch("whatyouship.inspectors.msi.MsiScopeInspector.inspect", return_value=InstallationScope("per-user")),
            ):
                report = MsiInspector().inspect(source)
                self.assertEqual(report.files[0].binary.format, "ELF")
                payload.write_bytes(b"\x7fELF")
                report = MsiInspector().inspect(source)
                self.assertIsNone(report.files[0].binary)
                self.assertEqual(report.binary_diagnostics[0].format, "ELF")

    def test_analysis_stays_quiet(self) -> None:
        """Keep successful parsing and recognized failures out of console output."""
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            ElfInspector().inspect(_make_elf())
            with self.assertRaises(BinaryAnalysisError):
                ElfInspector().inspect(b"\x7fELF")
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), "")
