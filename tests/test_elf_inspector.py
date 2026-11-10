# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Portable tests for ELF content recognition and basic artifact analysis."""

import contextlib
import csv
import io
import json
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from whatyouship.cli import main
from whatyouship.binary.elf import ElfInspector
from whatyouship.binary.errors import BinaryAnalysisError
from whatyouship.inspectors.msi import MsiInspector
from whatyouship.model import ArtifactSignature, BinaryDependency, InstallationScope
from whatyouship.operations import compare, inspect, lint
from whatyouship.renderers import render_report


def _make_elf(
    machine: int = 62,
    file_type: int = 2,
    *,
    bits: int = 64,
    endian: str = "<",
    interpreter: bool | str = False,
    static_pie: bool = False,
    dependencies: tuple[str, ...] = (),
    rpath: str | None = None,
    runpath: str | None = None,
    soname: str | None = None,
) -> bytes:
    """Construct an ELF header and optional loader segments without a compiler.

    :param machine: ELF machine number.
    :param file_type: ELF type, such as executable, shared object, or relocatable.
    :param bits: ELF class, 32 or 64 bits.
    :param endian: Struct byte order, little or big endian.
    :param interpreter: Whether to include PT_INTERP, or its explicit value.
    :param static_pie: Whether to include DF_1_PIE without requiring PT_INTERP.
    :param dependencies: DT_NEEDED library names in declaration order.
    :param rpath: Optional DT_RPATH string, including empty path elements.
    :param runpath: Optional DT_RUNPATH string, including empty path elements.
    :param soname: Optional DT_SONAME library identity.
    :returns: Serialized ELF bytes suitable for real LIEF parsing on any host.
    """
    identification = b"\x7fELF" + bytes((1 if bits == 32 else 2, 1 if endian == "<" else 2, 1)) + bytes(9)
    header_size, segment_size = (52, 32) if bits == 32 else (64, 56)
    strings = bytearray(b"\0")
    dynamic_entries = []
    for tag, value in (
        *((1, name) for name in dependencies),
        (15, rpath), (29, runpath), (14, soname),
    ):
        if value is not None:
            dynamic_entries.append((tag, len(strings)))
            strings.extend(value.encode("utf-8") + b"\0")
    if static_pie:
        dynamic_entries.append((0x6FFFFFFB, 0x08000000))
    has_dynamic = bool(dynamic_entries)
    count = 1 + int(bool(interpreter)) + int(has_dynamic) if interpreter or has_dynamic else 0
    offset = header_size + count * segment_size
    loader = (
        (interpreter if isinstance(interpreter, str) else "/lib/test-loader.so").encode("utf-8") + b"\0"
        if interpreter else b""
    )
    dynamic = b""
    if has_dynamic:
        entry_size = 8 if bits == 32 else 16
        string_offset = offset + len(loader) + (len(dynamic_entries) + 3) * entry_size
        dynamic = b"".join(
            struct.pack(endian + ("II" if bits == 32 else "QQ"), tag, value)
            for tag, value in [(5, string_offset), (10, len(strings)), *dynamic_entries, (0, 0)]
        )
    header = struct.pack(
        endian + ("HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"),
        file_type, machine, 1, 0, header_size if count else 0, 0, 0,
        header_size, segment_size, count, 40 if bits == 32 else 64, 0, 0,
    )
    segments = []
    if count:
        total_size = offset + len(loader) + len(dynamic) + (len(strings) if has_dynamic else 0)
        entries = [(1, 0, total_size)]
        if interpreter:
            entries.append((3, offset, len(loader)))
        if has_dynamic:
            entries.append((2, offset + len(loader), len(dynamic)))
        for kind, position, size in entries:
            values = (
                (kind, position, position, position, size, size, 4, 1)
                if bits == 32 else (kind, 4, position, position, position, size, size, 1)
            )
            segments.append(struct.pack(endian + ("IIIIIIII" if bits == 32 else "IIQQQQQQ"), *values))
    return identification + header + b"".join(segments) + loader + dynamic + (bytes(strings) if has_dynamic else b"")


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

    def test_loader_metadata_across_classes_and_byte_orders(self) -> None:
        """Read actual loader declarations without merging paths or expanding tokens."""
        for bits, machine in ((32, 3), (64, 62)):
            for endian in ("<", ">"):
                with self.subTest(bits=bits, endian=endian):
                    payload = _make_elf(
                        machine if endian == "<" else (20 if bits == 32 else 21),
                        bits=bits, endian=endian,
                        interpreter="/lib/custom-loader.so",
                        dependencies=("libz.so.1", "libc.so.6", "libz.so.1"),
                        rpath=":$ORIGIN/../lib::/opt/vendor/lib:",
                        runpath="${ORIGIN}/lib:$LIB/$PLATFORM:",
                        soname="libsample.so.2",
                    )
                    metadata = ElfInspector().inspect(payload)
                    assert metadata is not None
                    self.assertEqual(metadata.dependencies, (
                        BinaryDependency("libz.so.1"), BinaryDependency("libc.so.6"),
                        BinaryDependency("libz.so.1"),
                    ))
                    self.assertEqual(metadata.runtime_search_paths, ("", "$ORIGIN/../lib", "", "/opt/vendor/lib", ""))
                    self.assertEqual(metadata.runtime_run_paths, ("${ORIGIN}/lib", "$LIB/$PLATFORM", ""))
                    self.assertEqual(metadata.interpreter, "/lib/custom-loader.so")
                    self.assertEqual(metadata.library_name, "libsample.so.2")
                    with tempfile.TemporaryDirectory() as temporary:
                        path = Path(temporary) / "program"
                        path.write_bytes(payload)
                        self.assertEqual(ElfInspector().inspect(path), metadata)
                    self.assertEqual(ElfInspector().inspect(memoryview(payload)), metadata)

    def test_absent_and_empty_loader_paths(self) -> None:
        """Keep absent path tags distinct from present tags containing an empty path."""
        absent = ElfInspector().inspect(_make_elf())
        empty = ElfInspector().inspect(_make_elf(rpath="", runpath=""))
        assert absent is not None and empty is not None
        self.assertEqual(absent.dependencies, ())
        self.assertEqual(absent.runtime_search_paths, ())
        self.assertEqual(absent.runtime_run_paths, ())
        self.assertIsNone(absent.interpreter)
        self.assertIsNone(absent.library_name)
        self.assertEqual(empty.runtime_search_paths, ("",))
        self.assertEqual(empty.runtime_run_paths, ("",))
        self.assertIsNone(empty.signature)

    def test_lint_checks_both_path_tags_without_duplicate_findings(self) -> None:
        """Report declared developer and absolute paths once across both ELF tags."""
        payload = _make_elf(
            rpath="/home/build/lib:/opt/vendor/lib:/home/build/lib",
            runpath="/tmp/build/lib:/usr/local/lib:/home/build/lib:/opt/vendor/lib",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "program").write_bytes(payload)
            report = lint(root)
        self.assertEqual(
            [(finding.rule_id, finding.severity, finding.identity) for finding in report.findings],
            [
                ("developer-runtime-search-path", "error", "runtime-search-path:/home/build/lib"),
                ("developer-runtime-search-path", "error", "runtime-search-path:/tmp/build/lib"),
                ("absolute-runtime-search-path", "warning", "runtime-search-path:/opt/vendor/lib"),
                ("absolute-runtime-search-path", "warning", "runtime-search-path:/usr/local/lib"),
            ],
        )
        self.assertTrue(all(finding.relative_path == Path("program") for finding in report.findings))

    def test_lint_accepts_literal_origin_and_relative_paths(self) -> None:
        """Do not expand loader tokens against the host or flag relative paths as absolute."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "program").write_bytes(_make_elf(
                rpath="$ORIGIN/../lib:${ORIGIN}/lib:$ORIGIN/home/build/lib",
                runpath="${ORIGIN}/${LIB}/$PLATFORM:relative/lib::",
            ))
            self.assertEqual(lint(root).findings, [])

    def test_lint_does_not_exempt_absolute_paths_containing_loader_tokens(self) -> None:
        """Keep developer and absolute prefixes actionable even with embedded tokens."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "program").write_bytes(_make_elf(
                rpath="/home/build/$LIB", runpath="/opt/vendor/${PLATFORM}",
            ))
            report = lint(root)
        self.assertEqual([finding.identity for finding in report.findings], [
            "runtime-search-path:/home/build/$LIB",
            "runtime-search-path:/opt/vendor/${PLATFORM}",
        ])

    def test_lint_signature_rules_accept_unavailable_elf_signatures(self) -> None:
        """Keep all signature rules silent for ELF programs, libraries, and PIE."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for file_type, interpreter, static_pie in (
                (2, False, False), (3, False, False),
                (3, True, False), (3, False, True),
            ):
                with self.subTest(file_type=file_type, interpreter=interpreter, static_pie=static_pie):
                    (root / "binary").write_bytes(_make_elf(
                        file_type=file_type, interpreter=interpreter, static_pie=static_pie,
                        runpath="$ORIGIN/../lib",
                    ))
                    report = lint(root)
                    self.assertIsNone(report.artifact.files[0].binary.signature)
                    self.assertEqual(report.findings, [])

    def test_elf_path_suppressions_and_baseline_identity(self) -> None:
        """Apply TOML exceptions to both artifacts and preserve identities across path tags."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new = root / "old", root / "new"
            for directory in (old, new):
                (directory / "vendor").mkdir(parents=True)
                (directory / "vendor" / "helper").write_bytes(_make_elf(runpath="/tmp/vendor/lib"))
            (old / "program").write_bytes(_make_elf(rpath="/home/build/lib"))
            (new / "program").write_bytes(_make_elf(runpath="/home/build/lib"))
            config = root / "config.toml"
            config.write_text(
                '[[ignore]]\nrule = "developer-runtime-search-path"\n'
                'path = "vendor/**"\nreason = "Approved vendor payload."\n',
                encoding="utf-8",
            )
            report = lint(new, baseline=old, config=config)
        comparison = report.baseline_comparison
        assert comparison is not None
        self.assertEqual(comparison.new, [])
        self.assertEqual(comparison.resolved, [])
        self.assertEqual(len(comparison.existing), 1)
        self.assertEqual(comparison.existing[0].identity, "runtime-search-path:/home/build/lib")
        self.assertEqual(len(report.suppressed_findings), 1)
        self.assertEqual(len(report.baseline_suppressed_findings), 1)
        self.assertEqual(report.suppressed_findings[0].ignore.reason, "Approved vendor payload.")
        self.assertEqual(report.suppressed_findings[0].finding.relative_path, Path("vendor/helper"))

    def test_elf_lint_cli_thresholds_settings_and_suppression_reports(self) -> None:
        """Gate active ELF path findings while honoring settings, exceptions, and baselines."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload, baseline = root / "payload", root / "baseline"
            for directory in (payload, baseline):
                (directory / "vendor").mkdir(parents=True)
                (directory / "vendor" / "helper").write_bytes(_make_elf(runpath="/home/vendor/lib"))
                (directory / "program").write_bytes(_make_elf(runpath="/opt/vendor/lib"))
            config = root / "config.toml"
            output = root / "lint.json"
            ignore = (
                '[[ignore]]\nrule = "developer-runtime-search-path"\n'
                'path = "vendor/helper"\nreason = "Approved vendor tool."\n'
            )
            for settings, arguments, expected in (
                ("", [], 0),
                ("", ["--fail-on", "warning"], 1),
                ("", ["--fail-on", "never"], 0),
                ('[rules.absolute-runtime-search-path]\nseverity = "error"\n', [], 1),
                ('[rules.absolute-runtime-search-path]\nenabled = false\n', ["--fail-on", "warning"], 0),
                ("", ["--baseline", str(baseline), "--fail-on", "warning"], 0),
            ):
                with self.subTest(settings=settings, arguments=arguments):
                    config.write_text(settings + ignore, encoding="utf-8")
                    self.assertEqual(main([
                        "lint", str(payload), "--config", str(config), "-o", str(output), *arguments,
                    ]), expected)
                    data = json.loads(output.read_text(encoding="utf-8"))
                    self.assertEqual(len(data["suppressed_findings"]), 1)
                    self.assertEqual(data["suppressed_findings"][0]["ignore"]["reason"], "Approved vendor tool.")

    def test_loader_metadata_in_artifact_reports(self) -> None:
        """Preserve loader metadata in Python, text, JSON, and CSV for directory and ZIP inputs."""
        payload = _make_elf(
            dependencies=("libsample.so.2",), interpreter=True,
            rpath="$ORIGIN/old", runpath="$ORIGIN/new:", soname="libidentity.so.1",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / "payload"
            directory.mkdir()
            (directory / "program").write_bytes(payload)
            archive = root / "release.zip"
            with zipfile.ZipFile(archive, "w") as stream:
                stream.writestr("program", payload)
            for source in (directory, archive):
                with self.subTest(source=source):
                    report = inspect(source)
                    text = render_report(report, "text")
                    self.assertIn("RPATH: $ORIGIN/old", text)
                    self.assertIn("RUNPATH: $ORIGIN/new", text)
                    self.assertIn("Interpreter: /lib/test-loader.so", text)
                    self.assertIn("Library name: libidentity.so.1", text)
                    self.assertIn("Dependency: libsample.so.2 | required", text)
                    data = json.loads(render_report(report, "json"))["artifact"]["files"][0]["binary"]
                    self.assertEqual(data["runtime_search_paths"], ["$ORIGIN/old"])
                    self.assertEqual(data["runtime_run_paths"], ["$ORIGIN/new", ""])
                    self.assertEqual(data["interpreter"], "/lib/test-loader.so")
                    self.assertEqual(data["library_name"], "libidentity.so.1")
                    rows = list(csv.DictReader(io.StringIO(render_report(report, "csv"))))
                    self.assertEqual(json.loads(rows[0]["runtime_search_paths"]), data["runtime_search_paths"])
                    self.assertEqual(json.loads(rows[0]["runtime_run_paths"]), data["runtime_run_paths"])
                    self.assertEqual(json.loads(rows[0]["dependencies"]), data["dependencies"])
                    self.assertEqual(rows[0]["interpreter"], data["interpreter"])
                    self.assertEqual(rows[0]["library_name"], data["library_name"])

    def test_compare_elf_loader_changes_in_python_and_cli_reports(self) -> None:
        """Compare real ELF declarations through directory and ZIP operations and CLI reports."""
        old_payload = _make_elf(
            dependencies=("liba.so.1", "libb.so.1"),
            rpath="$ORIGIN/lib:", interpreter="/lib/old-loader.so", soname="libold.so.1",
        )
        new_payload = _make_elf(
            dependencies=("libb.so.1", "liba.so.1"),
            runpath="$ORIGIN/lib:", interpreter="/lib/new-loader.so", soname="libnew.so.2",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new = root / "old", root / "new"
            old.mkdir()
            new.mkdir()
            (old / "program").write_bytes(old_payload)
            (new / "program").write_bytes(new_payload)
            archive = root / "release.zip"
            with zipfile.ZipFile(archive, "w") as stream:
                stream.writestr("program", new_payload)
            for current in (new, archive):
                with self.subTest(current=current):
                    report = compare(old, current)
                    self.assertEqual(report.comparison.changed, [Path("program")])
                    differences = report.comparison.semantic_differences
                    self.assertEqual([item.field for item in differences], [
                        "Dynamic dependencies", "RPATH", "RUNPATH", "Interpreter", "Library name",
                    ])
                    by_field = {item.field: item for item in differences}
                    self.assertEqual(json.loads(by_field["Dynamic dependencies"].new_value), ["libb.so.1", "liba.so.1"])
                    self.assertEqual(json.loads(by_field["RPATH"].old_value), ["$ORIGIN/lib", ""])
                    self.assertEqual(json.loads(by_field["RPATH"].new_value), [])
                    self.assertEqual(json.loads(by_field["RUNPATH"].old_value), [])
                    self.assertEqual(json.loads(by_field["RUNPATH"].new_value), ["$ORIGIN/lib", ""])
                    text = render_report(report, "text")
                    self.assertIn("RPATH", text)
                    self.assertIn("RUNPATH", text)
                    self.assertIn("/lib/new-loader.so", text)
                    self.assertIn("libnew.so.2", text)
                    output = root / "compare.json"
                    self.assertEqual(main(["compare", str(old), str(current), "-o", str(output)]), 0)
                    data = json.loads(output.read_text(encoding="utf-8"))
                    self.assertEqual(data["changed"], ["program"])
                    self.assertEqual([item["field"] for item in data["semantic_differences"]],
                                     [item.field for item in differences])
                    self.assertTrue(all(item["severity"] is None for item in data["semantic_differences"]))

    def test_compare_elf_empty_path_tags_and_identical_inputs(self) -> None:
        """Distinguish empty path elements from missing tags and avoid changes for identical ELF."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new = root / "old", root / "new"
            old.mkdir()
            new.mkdir()
            (old / "program").write_bytes(_make_elf())
            (new / "program").write_bytes(_make_elf(rpath="", runpath=""))
            report = compare(old, new)
            self.assertEqual(
                [(item.field, item.old_value, item.new_value) for item in report.comparison.semantic_differences],
                [("RPATH", "[]", '[""]'), ("RUNPATH", "[]", '[""]')],
            )
            same = compare(new, new)
            self.assertEqual(same.comparison.unchanged, [Path("program")])
            self.assertEqual(same.comparison.semantic_differences, [])

    def test_compare_elf_parse_failures_remain_diagnostics(self) -> None:
        """Do not reinterpret an unreadable ELF as removal of its loader declarations."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new = root / "old", root / "new"
            old.mkdir()
            new.mkdir()
            (old / "program").write_bytes(_make_elf(runpath="$ORIGIN/lib", soname="libsample.so.1"))
            (new / "program").write_bytes(b"\x7fELF")
            report = compare(old, new)
        self.assertEqual(report.comparison.changed, [Path("program")])
        self.assertEqual(report.comparison.semantic_differences, [])
        self.assertEqual(report.old_artifact.binary_diagnostics, [])
        self.assertEqual(report.new_artifact.binary_diagnostics[0].format, "ELF")

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
