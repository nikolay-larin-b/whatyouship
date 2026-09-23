# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for Inno Setup detection, extraction, caching, and analysis."""

import contextlib
import hashlib
import io
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.cli import main
from whatyouship.inspectors import inspect_artifact
from whatyouship.inspectors.inno import InnoInspector
from whatyouship.inspectors.inno_cache import find_innoextract
from whatyouship.inspectors.inno_detection import is_inno_installer
from whatyouship.inspectors.nsis_detection import is_nsis_installer
from whatyouship.model import ArtifactSignature


_INNO_LOADER_SIGNATURE = b"rDlPtS\xcd\xe6\xd7{\x0b*"


def _write_inno_exe(path: Path, inno: bool = True) -> None:
    """Write a minimal PE with an optional Inno Setup loader resource.

    :param path: File to create.
    :param inno: Whether to include the ``RCDATA/11111`` loader resource.
    """
    content = bytearray(0x400)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", content, 0x86, 1)
    struct.pack_into("<H", content, 0x94, 0xE0)

    optional = 0x98
    struct.pack_into("<H", content, optional, 0x10B)
    struct.pack_into("<I", content, optional + 92, 16)
    if inno:
        struct.pack_into("<II", content, optional + 112, 0x1000, 0x200)

    section = optional + 0xE0
    content[section:section + 8] = b".rsrc\0\0\0"
    struct.pack_into("<IIII", content, section + 8, 0x200, 0x1000, 0x200, 0x200)
    if inno:
        resource = 0x200
        struct.pack_into("<HH", content, resource + 12, 0, 1)
        struct.pack_into("<II", content, resource + 16, 10, 0x80000020)
        struct.pack_into("<HH", content, resource + 0x20 + 12, 0, 1)
        struct.pack_into(
            "<II", content, resource + 0x20 + 16, 11111, 0x80000040
        )
        struct.pack_into("<HH", content, resource + 0x40 + 12, 0, 1)
        struct.pack_into("<II", content, resource + 0x40 + 16, 1033, 0x60)
        struct.pack_into("<IIII", content, resource + 0x60, 0x1080, 12, 0, 0)
        content[resource + 0x80:resource + 0x8C] = _INNO_LOADER_SIGNATURE
    path.write_bytes(content)


def _write_legacy_inno_exe(path: Path) -> None:
    """Write a minimal PE using the legacy Inno Setup bootstrap header.

    :param path: File to create.
    """
    content = bytearray(0x200)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    loader_offset = 0x120
    struct.pack_into(
        "<III", content, 0x30, 0x6F6E6E49, loader_offset, ~loader_offset & 0xFFFFFFFF
    )
    content[loader_offset:loader_offset + 12] = _INNO_LOADER_SIGNATURE
    path.write_bytes(content)


def _write_nsis_exe(path: Path) -> None:
    """Write a minimal PE-shaped file with an NSIS overlay header.

    :param path: File to create.
    """
    content = bytearray(0x120)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", content, 0x86, 1)
    struct.pack_into("<H", content, 0x94, 0)
    struct.pack_into("<I", content, 0x98 + 16, 0x20)
    struct.pack_into("<I", content, 0x98 + 20, 0x100)
    content.extend(b"\x00\x00\x00\x00\xef\xbe\xad\xdeNullsoftInstpayload")
    path.write_bytes(content)


class InnoInspectorTests(unittest.TestCase):
    """Verify Inno routing, extraction, and generic analysis reuse."""

    def setUp(self) -> None:
        """Use disposable source and cache directories."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache_root = self.root / "cache" / "inno" / "v1"
        cache_patch = patch(
            "whatyouship.inspectors.inno_cache.cache_directory",
            return_value=self.cache_root,
        )
        cache_patch.start()
        self.addCleanup(cache_patch.stop)
        self.signature_patch = patch.object(
            InnoInspector,
            "_signature",
            return_value=ArtifactSignature(status="unsupported"),
        )
        self.signature_patch.start()
        self.addCleanup(self.signature_patch.stop)

    def _source(self, name: str = "release.exe") -> Path:
        """Create and return a synthetic Inno Setup installer.

        :param name: Installer file name.
        :returns: Path to the installer.
        """
        source = self.root / name
        _write_inno_exe(source)
        return source

    def _entry(self, source: Path) -> Path:
        """Return the source's content-addressed cache entry.

        :param source: Installer whose digest names the entry.
        :returns: Expected final cache path.
        """
        return self.cache_root / hashlib.sha256(source.read_bytes()).hexdigest()

    def _successful_run(self, files: dict[str, bytes]) -> object:
        """Create an innoextract runner that materializes a payload.

        :param files: Relative payload paths and contents.
        :returns: Callable suitable as ``subprocess.run`` side effect.
        """
        def run(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            """Write payload files below the requested output directory.

            :param command: innoextract command line.
            :param kwargs: Subprocess options supplied by the cache.
            :returns: Successful completed process.
            """
            self.assertTrue(kwargs["capture_output"])
            self.assertTrue(kwargs["text"])
            output = Path(command[command.index("--output-dir") + 1])
            for name, content in files.items():
                target = output / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            return subprocess.CompletedProcess(command, 0, "innoextract output", "")

        return run

    def test_detection_accepts_modern_and_legacy_inno_installers(self) -> None:
        """Recognize both supported Inno Setup loader storage schemes."""
        modern = self._source()
        legacy = self.root / "legacy.exe"
        plain = self.root / "plain.exe"
        invalid = self.root / "invalid.exe"
        _write_legacy_inno_exe(legacy)
        _write_inno_exe(plain, inno=False)
        invalid.write_bytes(b"not a PE")

        self.assertTrue(is_inno_installer(modern))
        self.assertTrue(is_inno_installer(legacy))
        self.assertFalse(is_inno_installer(plain))
        self.assertFalse(is_inno_installer(invalid))

    def test_nsis_and_inno_detection_do_not_overlap(self) -> None:
        """Distinguish the two installer formats before extraction."""
        inno = self._source("inno.exe")
        nsis = self.root / "nsis.exe"
        _write_nsis_exe(nsis)

        self.assertTrue(is_inno_installer(inno))
        self.assertFalse(is_nsis_installer(inno))
        self.assertTrue(is_nsis_installer(nsis))
        self.assertFalse(is_inno_installer(nsis))

    def test_find_innoextract_uses_path_only(self) -> None:
        """Find innoextract only through ``shutil.which``."""
        with patch(
            "whatyouship.inspectors.inno_cache.shutil.which",
            return_value=r"C:\\tools\\innoextract.exe",
        ) as which:
            executable = find_innoextract()

        self.assertEqual(executable, r"C:\\tools\\innoextract.exe")
        which.assert_called_once_with("innoextract")

    def test_missing_innoextract_reports_actionable_error(self) -> None:
        """Explain the PATH dependency without attempting extraction."""
        source = self._source()

        with (
            patch("whatyouship.inspectors.inno_cache.shutil.which", return_value=None),
            patch("whatyouship.inspectors.inno_cache.subprocess.run") as run,
            self.assertRaisesRegex(
                ValueError,
                "Inno Setup extraction requires innoextract. "
                "Add 'innoextract' to PATH.",
            ),
        ):
            inspect_artifact(source)

        run.assert_not_called()
        self.assertFalse(self._entry(source).exists())

    def test_successful_extraction_publishes_payload_and_stays_quiet(self) -> None:
        """Capture innoextract output and inspect the extracted payload tree."""
        source = self._source()
        output = io.StringIO()

        with (
            patch(
                "whatyouship.inspectors.inno_cache.shutil.which",
                return_value="innoextract",
            ),
            patch(
                "whatyouship.inspectors.inno_cache.subprocess.run",
                side_effect=self._successful_run({"app/bin.txt": b"payload"}),
            ) as run,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            artifact = inspect_artifact(source)

        self.assertEqual(output.getvalue(), "")
        self.assertEqual(artifact.source_path, source)
        self.assertEqual(artifact.signature.status, "unsupported")
        self.assertEqual(
            [file.relative_path for file in artifact.files], [Path("app/bin.txt")]
        )
        extracted = self._entry(source) / "files" / "app" / "bin.txt"
        self.assertEqual(extracted.read_bytes(), b"payload")
        command = run.call_args.args[0]
        self.assertEqual(command[:4], [
            "innoextract", "--extract", "--silent", "--output-dir"
        ])
        self.assertEqual(command[5], "--")
        self.assertEqual(Path(command[4]).name, "files")
        self.assertTrue(Path(command[4]).parent.name.startswith(".tmp-"))
        self.assertEqual(Path(command[-1]), source)

    def test_cache_hit_skips_lookup_and_extraction(self) -> None:
        """Reuse a valid content-addressed entry without innoextract."""
        source = self._source()
        with (
            patch(
                "whatyouship.inspectors.inno_cache.shutil.which",
                return_value="innoextract",
            ),
            patch(
                "whatyouship.inspectors.inno_cache.subprocess.run",
                side_effect=self._successful_run({"app.txt": b"same"}),
            ) as first_run,
        ):
            first = inspect_artifact(source)

        with (
            patch("whatyouship.inspectors.inno_cache.shutil.which") as which,
            patch("whatyouship.inspectors.inno_cache.subprocess.run") as second_run,
        ):
            second = inspect_artifact(source)

        self.assertEqual(first, second)
        self.assertEqual(first_run.call_count, 1)
        which.assert_not_called()
        second_run.assert_not_called()

    def test_extraction_failure_removes_staging_and_final_entry(self) -> None:
        """Keep failed extraction output out of the valid cache namespace."""
        source = self._source()
        failure = subprocess.CompletedProcess(
            ["innoextract"], 2, "ordinary output", "Setup data is corrupted"
        )

        with (
            patch(
                "whatyouship.inspectors.inno_cache.shutil.which",
                return_value="innoextract",
            ),
            patch(
                "whatyouship.inspectors.inno_cache.subprocess.run",
                return_value=failure,
            ),
            self.assertRaisesRegex(
                ValueError, "innoextract failed with exit code 2: Setup data is corrupted"
            ),
        ):
            inspect_artifact(source)

        self.assertFalse(self._entry(source).exists())
        self.assertEqual(list(self.cache_root.iterdir()), [])

    def test_extraction_failure_reports_cause_instead_of_summary(self) -> None:
        """Expose useful extractor diagnostics rather than its final counter."""
        source = self._source()
        failure = subprocess.CompletedProcess(
            ["innoextract"],
            2,
            "",
            "\n".join((
                "Warning: Unexpected setup data version: 6.4.0",
                "Stream error while parsing setup headers!",
                "error reason: iostream error",
                "If you are sure the setup file is not corrupted, consider",
                "filing a bug report at https://innoextract.constexpr.org/issues",
                "Done with 1 error and 1 warning.",
            )),
        )

        with (
            patch(
                "whatyouship.inspectors.inno_cache.shutil.which",
                return_value="innoextract",
            ),
            patch(
                "whatyouship.inspectors.inno_cache.subprocess.run",
                return_value=failure,
            ),
            self.assertRaisesRegex(
                ValueError,
                "Unexpected setup data version: 6.4.0 .* iostream error",
            ) as raised,
        ):
            inspect_artifact(source)

        self.assertNotIn("Done with", str(raised.exception))

    def test_plain_exe_is_rejected_without_extractors(self) -> None:
        """Do not treat an arbitrary executable as either installer format."""
        source = self.root / "application.exe"
        _write_inno_exe(source, inno=False)

        with (
            patch("whatyouship.inspectors.nsis_cache.shutil.which") as seven_zip,
            patch("whatyouship.inspectors.inno_cache.shutil.which") as innoextract,
            self.assertRaisesRegex(
                ValueError,
                "Unsupported EXE artifact .*not an NSIS or Inno Setup installer",
            ),
        ):
            inspect_artifact(source)

        seven_zip.assert_not_called()
        innoextract.assert_not_called()

    def test_existing_lint_rule_applies_to_extracted_payload(self) -> None:
        """Run generic lint rules against Inno Setup payload paths."""
        source = self._source()
        output = io.StringIO()

        with (
            patch(
                "whatyouship.inspectors.inno_cache.shutil.which",
                return_value="innoextract",
            ),
            patch(
                "whatyouship.inspectors.inno_cache.subprocess.run",
                side_effect=self._successful_run({"app/module.obj": b"object"}),
            ),
            contextlib.redirect_stdout(output),
        ):
            result = main(["lint", str(source)])

        self.assertEqual(result, 0)
        self.assertIn(
            f"build-artifact-extension | warning | {Path('app/module.obj')}",
            output.getvalue(),
        )

    def test_compare_two_inno_payloads(self) -> None:
        """Use generic comparison for two extracted Inno Setup releases."""
        old = self._source("old.exe")
        new = self._source("new.exe")
        new.write_bytes(new.read_bytes() + b"different digest")
        payloads = [
            {"removed.txt": b"old", "changed.txt": b"old", "same.txt": b"same"},
            {"added.txt": b"new", "changed.txt": b"new", "same.txt": b"same"},
        ]
        output = io.StringIO()

        def run(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            """Extract the payload selected by installer path.

            :param command: innoextract command line.
            :param kwargs: Subprocess options supplied by the cache.
            :returns: Successful completed process.
            """
            files = payloads[0] if Path(command[-1]) == old else payloads[1]
            return self._successful_run(files)(command, **kwargs)

        with (
            patch(
                "whatyouship.inspectors.inno_cache.shutil.which",
                return_value="innoextract",
            ),
            patch(
                "whatyouship.inspectors.inno_cache.subprocess.run", side_effect=run
            ),
            contextlib.redirect_stdout(output),
        ):
            result = main(["compare", str(old), str(new)])

        self.assertEqual(result, 0)
        self.assertIn(
            "Added: 1\nRemoved: 1\nChanged: 1\nUnchanged: 1", output.getvalue()
        )

    def test_windows_outer_signature_uses_authenticode_backend(self) -> None:
        """Verify the original installer separately on Windows."""
        source = self._source()
        expected = ArtifactSignature(status="valid")
        self.signature_patch.stop()
        with (
            patch("whatyouship.inspectors.inno.sys.platform", "win32"),
            patch(
                "whatyouship.inspectors.windows_authenticode."
                "WindowsAuthenticodeVerifier.verify",
                return_value=expected,
            ) as verify,
        ):
            actual = InnoInspector()._signature(source)

        self.assertEqual(actual, expected)
        verify.assert_called_once_with(source)


if __name__ == "__main__":
    unittest.main()
