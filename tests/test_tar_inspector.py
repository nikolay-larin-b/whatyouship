# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Portable TAR extraction, artifact operation, and cache lifecycle tests."""

import contextlib
import csv
import io
import json
import struct
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.cache import clear_cache, inspect_cache
from whatyouship.cli import main
from whatyouship.exceptions import ArtifactExtractionError
from whatyouship.inspectors.tar import TarInspector
from whatyouship.inspectors.tar_cache import TAR_SUFFIXES, TarExtractionCache
from whatyouship.operations import compare, inspect, lint
from whatyouship.paths import cache_root_directory, cache_scope
from whatyouship.renderers import render_report


def _member(
    name: str, payload: bytes = b"", *, kind: bytes = tarfile.REGTYPE,
    target: str = "", mode: int = 0o644,
) -> tuple[tarfile.TarInfo, bytes]:
    """Describe a portable TAR fixture member.

    :param name: Archive-relative member name.
    :param payload: Contents for a regular file.
    :param kind: TAR member type.
    :param target: Link target, if applicable.
    :param mode: Original POSIX permission bits.
    :returns: Header and contents for the archive fixture.
    """
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = len(payload) if info.isfile() else 0
    info.linkname = target
    info.mode = mode
    return info, payload


def _write_tar(
    path: Path, members: list[tuple[tarfile.TarInfo, bytes]], *,
    mode: str = "w", archive_format: int = tarfile.PAX_FORMAT,
) -> None:
    """Write a TAR fixture using only standard-library tooling.

    :param path: Destination path.
    :param members: Headers and file contents in archive order.
    :param mode: TAR write mode and compression.
    :param archive_format: USTAR, GNU, or PAX representation.
    """
    with tarfile.open(path, mode, format=archive_format) as archive:
        for member, payload in members:
            archive.addfile(member, io.BytesIO(payload) if member.isfile() else None)


class TarInspectorTests(unittest.TestCase):
    """Verify TAR integration without native links, compilers, or external tools."""

    def test_compression_aliases_and_formats(self) -> None:
        """Inspect supported extensions and all standard TAR header formats."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for suffix in TAR_SUFFIXES:
                mode = (
                    "w:gz" if suffix in (".tgz", ".tar.gz") else
                    "w:xz" if suffix in (".txz", ".tar.xz") else
                    "w:bz2" if suffix in (".tbz", ".tbz2", ".tar.bz2") else "w"
                )
                for archive_format in (tarfile.USTAR_FORMAT, tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
                    with self.subTest(suffix=suffix, archive_format=archive_format):
                        path = root / ("release" + suffix.upper())
                        _write_tar(path, [_member("./" , kind=tarfile.DIRTYPE),
                                          _member("./bin/program", b"content", mode=0o755)],
                                   mode=mode, archive_format=archive_format)
                        report = inspect(path)
                        self.assertEqual(report.artifact.source_path, path)
                        self.assertEqual(report.artifact.files[0].relative_path, Path("bin/program"))
                        self.assertEqual(report.artifact.files[0].size_bytes, 7)
                        self.assertEqual(report.artifact.files[0].posix_mode, 0o755)

    def test_empty_archive_and_long_member_names(self) -> None:
        """Accept empty archives and GNU/PAX extended names."""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.tar"
            _write_tar(path, [])
            self.assertEqual(inspect(path).artifact.files, [])
            name = "a" * 101 + ".txt"
            for archive_format in (tarfile.GNU_FORMAT, tarfile.PAX_FORMAT):
                with self.subTest(archive_format=archive_format):
                    _write_tar(path, [_member(name, b"payload")], archive_format=archive_format)
                    self.assertEqual(inspect(path).artifact.files[0].relative_path.as_posix(), name)

    def test_symbolic_links_are_metadata_only(self) -> None:
        """Retain relative, external, dangling, and cyclic symbolic links without creating them."""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.tar"
            _write_tar(path, [
                _member("lib/libreal.so.1", b"library"),
                _member("lib/libreal.so", kind=tarfile.SYMTYPE, target="libreal.so.1"),
                _member("external", kind=tarfile.SYMTYPE, target="/usr/lib/library.so"),
                _member("escape", kind=tarfile.SYMTYPE, target="../../outside"),
                _member("dangling", kind=tarfile.SYMTYPE, target="missing"),
                _member("cycle", kind=tarfile.SYMTYPE, target="cycle"),
            ])
            with cache_scope(persistent=False):
                report = inspect(path)
                cache = cache_root_directory()
                self.assertFalse(any(item.is_symlink() for item in cache.rglob("*")))
                self.assertFalse(any(item.name == "external" for item in cache.rglob("*")))
            self.assertEqual(len(report.artifact.files), 1)
            links = {link.relative_path.as_posix(): link for link in report.artifact.symbolic_links}
            self.assertEqual(links["lib/libreal.so"].target, "libreal.so.1")
            self.assertFalse(links["lib/libreal.so"].external)
            self.assertTrue(links["external"].external)
            self.assertTrue(links["escape"].external)
            self.assertEqual(links["cycle"].target, "cycle")

    def test_forward_and_chained_hard_links(self) -> None:
        """Resolve hard links to regular archive members without host hard-link support."""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.tar"
            _write_tar(path, [
                _member("first", kind=tarfile.LNKTYPE, target="second"),
                _member("second", kind=tarfile.LNKTYPE, target="./original"),
                _member("original", b"data", mode=0o751),
            ])
            files = inspect(path).artifact.files
        self.assertEqual([file.relative_path.as_posix() for file in files], ["first", "original", "second"])
        self.assertEqual(len({file.sha256 for file in files}), 1)
        self.assertTrue(all(file.size_bytes == 4 and file.posix_mode == 0o751 for file in files))

    def test_rejects_unsafe_paths_and_special_members(self) -> None:
        """Reject traversal, Windows aliases, devices, and unsupported special files."""
        cases = [
            [_member(name, b"payload")]
            for name in ("../escape", "/absolute", "a/../escape", "C:/escape", "C:escape",
                         "a\\escape", "a:stream", "NUL", "a/COM1.txt", "trailing.", "trailing ")
        ]
        cases.extend([_member("special", kind=kind)] for kind in (
            tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE,
        ))
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.tar"
            for members in cases:
                with self.subTest(name=members[0][0].name, kind=members[0][0].type):
                    _write_tar(path, members)
                    with self.assertRaises(ArtifactExtractionError):
                        inspect(path)

    def test_rejects_conflicting_paths_and_invalid_hard_links(self) -> None:
        """Prevent link traversal, duplicate writes, missing targets, and hard-link cycles."""
        cases = (
            [_member("a", b"one"), _member("./a", b"two")],
            [_member("a", b"file"), _member("a/child", b"child")],
            [_member("a/child", b"child"), _member("a", kind=tarfile.SYMTYPE, target="/tmp")],
            [_member("a", kind=tarfile.SYMTYPE, target="/tmp"), _member("a/child", b"child")],
            [_member("a", kind=tarfile.LNKTYPE, target="missing")],
            [_member("a", kind=tarfile.LNKTYPE, target="../escape")],
            [_member("a", kind=tarfile.LNKTYPE, target="/absolute")],
            [_member("a", kind=tarfile.LNKTYPE, target="b"), _member("b", kind=tarfile.LNKTYPE, target="a")],
            [_member("a", kind=tarfile.LNKTYPE, target="b"), _member("b", kind=tarfile.DIRTYPE)],
            [_member("a", kind=tarfile.LNKTYPE, target="b"), _member("b", kind=tarfile.SYMTYPE, target="outside")],
            [_member("a", kind=tarfile.SYMTYPE)],
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.tar"
            for members in cases:
                with self.subTest(members=[member.name for member, _ in members]):
                    _write_tar(path, members)
                    with self.assertRaises(ArtifactExtractionError):
                        inspect(path)

    def test_invalid_and_truncated_archives(self) -> None:
        """Translate corrupt headers and incomplete payloads into public extraction errors."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "release.tar"
            for data in (b"not a TAR", b"", b"\x28\xb5\x2f\xfdunsupported-zstd"):
                path.write_bytes(data)
                with self.subTest(data=data), self.assertRaises(ArtifactExtractionError):
                    inspect(path)
            _write_tar(path, [_member("payload", b"x" * 2048)])
            path.write_bytes(path.read_bytes()[:600])
            with self.assertRaises(ArtifactExtractionError):
                inspect(path)

    def test_compressed_payload_corruption_is_public_error(self) -> None:
        """Normalize decompressor failures after opening compressed TAR streams."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for mode, suffix in (("w:gz", ".tar.gz"), ("w:bz2", ".tar.bz2"), ("w:xz", ".tar.xz")):
                with self.subTest(mode=mode):
                    path = root / ("release" + suffix)
                    _write_tar(path, [_member("payload", bytes(range(256)) * 1000)], mode=mode)
                    data = bytearray(path.read_bytes())
                    data[len(data) // 2] ^= 0xFF
                    path.write_bytes(data)
                    with self.assertRaises(ArtifactExtractionError):
                        inspect(path)

    def test_shared_binary_analysis_lint_baseline_and_cli(self) -> None:
        """Run ELF analysis, diagnostics, lint exceptions, and baseline gating on TAR contents."""
        elf = b"\x7fELF" + bytes((2, 1, 1)) + bytes(9) + struct.pack(
            "<HHIQQQIHHHHHH", 2, 62, 1, 0, 0, 0, 0, 64, 56, 0, 64, 0, 0,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new = root / "old.tar", root / "new.tar.gz"
            members = [_member("program", elf, mode=0o755), _member("build.obj", b"object"),
                       _member("broken", b"\x7fELF")]
            _write_tar(old, members)
            _write_tar(new, members, mode="w:gz")
            report = inspect(new)
            self.assertEqual(report.artifact.files[-1].binary.format, "ELF")
            self.assertEqual(report.artifact.binary_diagnostics[0].format, "ELF")
            baseline = lint(new, baseline=old).baseline_comparison
            assert baseline is not None
            self.assertEqual(len(baseline.existing), 1)
            self.assertEqual(baseline.new, [])
            output = root / "report.json"
            self.assertEqual(main(["lint", str(new), "--fail-on", "warning", "-o", str(output)]), 1)
            self.assertEqual(main(["lint", str(new), "--baseline", str(old), "--fail-on", "warning", "-o", str(output)]), 0)
            config = root / "config.toml"
            config.write_text('[[ignore]]\nrule = "build-artifact-extension"\npath = "build.obj"\n', encoding="utf-8")
            self.assertEqual(main(["lint", str(new), "--config", str(config), "--fail-on", "warning", "-o", str(output)]), 0)
            self.assertEqual(len(json.loads(output.read_text(encoding="utf-8"))["suppressed_findings"]), 1)

    def test_reports_and_permission_only_comparison(self) -> None:
        """Report original archive modes and detect mode changes independently of file hashes."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new = root / "old.tar", root / "new.tar.xz"
            _write_tar(old, [_member("program", b"program", mode=0o755)])
            _write_tar(new, [_member("program", b"program", mode=0o644)], mode="w:xz")
            report = inspect(old)
            self.assertIn("POSIX mode: 0755", render_report(report, "text"))
            self.assertEqual(json.loads(render_report(report, "json"))["artifact"]["files"][0]["posix_mode"], 0o755)
            rows = list(csv.DictReader(io.StringIO(render_report(report, "csv"))))
            self.assertEqual(rows[0]["posix_mode"], "0755")
            result = compare(old, new).comparison
            self.assertEqual(result.unchanged, [Path("program")])
            self.assertEqual([(item.field, item.old_value, item.new_value) for item in result.semantic_differences],
                             [("POSIX mode", "0755", "0644")])
            directory = root / "directory"
            directory.mkdir()
            (directory / "program").write_bytes(b"program")
            self.assertEqual(compare(old, directory).comparison.semantic_differences, [])

    def test_cache_reuse_and_recovery(self) -> None:
        """Reuse entries and reextract after file or metadata corruption."""
        with tempfile.TemporaryDirectory() as temporary, cache_scope(persistent=False):
            path = Path(temporary) / "release.tar"
            _write_tar(path, [_member("program", b"program", mode=0o755)])
            original = TarExtractionCache._extract
            with patch.object(TarExtractionCache, "_extract", autospec=True, side_effect=original) as extract:
                first = inspect(path)
                self.assertEqual(inspect(path), first)
                self.assertEqual(extract.call_count, 1)
                cache = cache_root_directory() / "tar" / "v1"
                entry = next(cache.iterdir())
                (entry / "files" / "program").write_bytes(b"wrong-size")
                self.assertEqual(inspect(path), first)
                self.assertEqual(extract.call_count, 2)
                manifest = entry / "manifest.json"
                data = json.loads(manifest.read_text(encoding="utf-8"))
                data["files"][0]["posix_mode"] = -1
                manifest.write_text(json.dumps(data), encoding="utf-8")
                self.assertEqual(inspect(path), first)
                self.assertEqual(extract.call_count, 3)

    def test_failed_extraction_cleans_staging(self) -> None:
        """Remove partial extraction and avoid publishing invalid archives."""
        with tempfile.TemporaryDirectory() as temporary, cache_scope(persistent=False):
            path = Path(temporary) / "release.tar"
            _write_tar(path, [_member("safe", b"safe"), _member("bad", kind=tarfile.LNKTYPE, target="missing")])
            with self.assertRaises(ArtifactExtractionError):
                inspect(path)
            self.assertEqual(list((cache_root_directory() / "tar" / "v1").iterdir()), [])

    def test_default_cache_cleanup_and_persistent_management(self) -> None:
        """Clean default caches and expose explicit persistent TAR entries to cache commands."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "release.tar"
            _write_tar(path, [_member("program", b"data")])
            selected = []
            original = TarExtractionCache._extract

            def extract(cache: TarExtractionCache, source: Path, entry: Path) -> None:
                """Record the active cache and invoke normal extraction.

                :param cache: TAR cache instance.
                :param source: Archive path.
                :param entry: Staging entry.
                """
                selected.append(cache_root_directory())
                original(cache, source, entry)

            with patch.object(TarExtractionCache, "_extract", extract):
                inspect(path)
            self.assertFalse(selected[0].exists())
            with patch("whatyouship.paths.user_data_directory", return_value=root / "user-data"):
                inspect(path, cache=True)
                info = inspect_cache()
                self.assertEqual([item.format_name for item in info.formats], ["tar"])
                self.assertEqual(info.formats[0].entries, 1)
                self.assertEqual(clear_cache(("tar",)).failures, ())
                self.assertEqual(inspect_cache().formats, ())

    def test_cli_extraction_error_and_missing_source(self) -> None:
        """Report unsupported TAR contents with exit 2 and retain source-path errors."""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release.tar"
            with self.assertRaises(FileNotFoundError):
                TarInspector().inspect(path)
            with self.assertRaises(IsADirectoryError):
                TarInspector().inspect(path.parent)
            path.write_bytes(b"invalid")
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["inspect", str(path)])
            self.assertEqual(raised.exception.code, 2)
