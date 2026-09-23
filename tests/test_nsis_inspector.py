# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for NSIS detection, extraction, caching, and generic analysis."""

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
from whatyouship.inspectors.nsis import NsisInspector
from whatyouship.inspectors.nsis_cache import NsisExtractionCache, find_7zip
from whatyouship.inspectors.nsis_detection import is_nsis_installer
from whatyouship.model import ArtifactSignature


def _write_exe(path: Path, nsis: bool = True) -> None:
    """Write a minimal PE-shaped file with an optional NSIS overlay header.

    :param path: File to create.
    :param nsis: Whether to append the canonical NSIS first header.
    """
    content = bytearray(0x120)
    content[:2] = b"MZ"
    struct.pack_into("<I", content, 0x3C, 0x80)
    content[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", content, 0x86, 1)
    struct.pack_into("<H", content, 0x94, 0)
    struct.pack_into("<I", content, 0x98 + 16, 0x20)
    struct.pack_into("<I", content, 0x98 + 20, 0x100)
    if nsis:
        content.extend(b"\x00\x00\x00\x00\xef\xbe\xad\xdeNullsoftInstpayload")
    path.write_bytes(content)


class NsisInspectorTests(unittest.TestCase):
    """Verify NSIS routing, 7-Zip extraction, and generic analysis reuse."""

    def setUp(self) -> None:
        """Use disposable source and cache directories."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache_root = self.root / "cache" / "nsis" / "v1"
        cache_patch = patch(
            "whatyouship.inspectors.nsis_cache.cache_directory",
            return_value=self.cache_root,
        )
        cache_patch.start()
        self.addCleanup(cache_patch.stop)
        self.signature_patch = patch.object(
            NsisInspector,
            "_signature",
            return_value=ArtifactSignature(status="unsupported"),
        )
        self.signature_patch.start()
        self.addCleanup(self.signature_patch.stop)

    def _source(self, name: str = "release.exe") -> Path:
        """Create and return a synthetic NSIS installer.

        :param name: Installer file name.
        :returns: Path to the installer.
        """
        source = self.root / name
        _write_exe(source)
        return source

    def _entry(self, source: Path) -> Path:
        """Return the source's content-addressed cache entry.

        :param source: Installer whose digest names the entry.
        :returns: Expected final cache path.
        """
        return self.cache_root / hashlib.sha256(source.read_bytes()).hexdigest()

    def _successful_run(
        self, files: dict[str, bytes]
    ) -> object:
        """Create a 7-Zip runner that materializes a requested payload.

        :param files: Relative payload paths and contents.
        :returns: Callable suitable as ``subprocess.run`` side effect.
        """
        def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            """Write payload files below the requested output directory.

            :param command: 7-Zip command line.
            :param kwargs: Subprocess options supplied by the cache.
            :returns: Successful completed process.
            """
            self.assertTrue(kwargs["capture_output"])
            output = Path(next(argument[2:] for argument in command if argument.startswith("-o")))
            for name, content in files.items():
                target = output / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content)
            return subprocess.CompletedProcess(command, 0, "7-Zip output", "")

        return run

    def test_detection_accepts_nsis_and_rejects_plain_exe(self) -> None:
        """Require both a valid PE layout and the NSIS overlay signature."""
        installer = self._source()
        plain = self.root / "plain.exe"
        invalid = self.root / "invalid.exe"
        _write_exe(plain, nsis=False)
        invalid.write_bytes(b"not a PE")

        self.assertTrue(is_nsis_installer(installer))
        self.assertFalse(is_nsis_installer(plain))
        self.assertFalse(is_nsis_installer(invalid))

    def test_find_7zip_checks_supported_path_names_in_order(self) -> None:
        """Find 7zz, 7z, and 7z.exe only through ``shutil.which``."""
        with patch(
            "whatyouship.inspectors.nsis_cache.shutil.which",
            side_effect=[None, None, r"C:\\tools\\7z.exe"],
        ) as which:
            executable = find_7zip()

        self.assertEqual(executable, r"C:\\tools\\7z.exe")
        self.assertEqual([call.args[0] for call in which.call_args_list], ["7zz", "7z", "7z.exe"])

    def test_missing_7zip_reports_actionable_error(self) -> None:
        """Explain the PATH dependency without attempting extraction."""
        source = self._source()

        with (
            patch("whatyouship.inspectors.nsis_cache.shutil.which", return_value=None),
            patch("whatyouship.inspectors.nsis_cache.subprocess.run") as run,
            self.assertRaisesRegex(
                ValueError,
                "NSIS extraction requires 7-Zip. Add '7z' or '7zz' to PATH.",
            ),
        ):
            NsisInspector().inspect(source)

        run.assert_not_called()
        self.assertFalse(self._entry(source).exists())

    def test_successful_extraction_publishes_payload_and_stays_quiet(self) -> None:
        """Capture 7-Zip output and inspect the extracted payload tree."""
        source = self._source()
        output = io.StringIO()

        with (
            patch("whatyouship.inspectors.nsis_cache.shutil.which", return_value="7z"),
            patch(
                "whatyouship.inspectors.nsis_cache.subprocess.run",
                side_effect=self._successful_run({"bin/app.txt": b"payload"}),
            ) as run,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(output),
        ):
            artifact = NsisInspector().inspect(source)

        self.assertEqual(output.getvalue(), "")
        self.assertEqual(artifact.source_path, source)
        self.assertEqual(artifact.signature.status, "unsupported")
        self.assertEqual(
            [file.relative_path for file in artifact.files], [Path("bin/app.txt")]
        )
        extracted = self._entry(source) / "files" / "bin" / "app.txt"
        self.assertEqual(extracted.read_bytes(), b"payload")
        command = run.call_args.args[0]
        self.assertEqual(command[:5], ["7z", "x", "-y", "-bd", "-bb0"])

    def test_cache_hit_skips_7zip_lookup_and_extraction(self) -> None:
        """Reuse a valid content-addressed entry without requiring 7-Zip."""
        source = self._source()

        with (
            patch("whatyouship.inspectors.nsis_cache.shutil.which", return_value="7z"),
            patch(
                "whatyouship.inspectors.nsis_cache.subprocess.run",
                side_effect=self._successful_run({"app.txt": b"same"}),
            ) as run,
        ):
            first = NsisInspector().inspect(source)

        with (
            patch("whatyouship.inspectors.nsis_cache.shutil.which") as which,
            patch("whatyouship.inspectors.nsis_cache.subprocess.run") as second_run,
        ):
            second = NsisInspector().inspect(source)

        self.assertEqual(first, second)
        self.assertEqual(run.call_count, 1)
        which.assert_not_called()
        second_run.assert_not_called()

    def test_extraction_failure_removes_staging_and_final_entry(self) -> None:
        """Keep failed extraction output out of the valid cache namespace."""
        source = self._source()
        failure = subprocess.CompletedProcess(
            ["7z"], 2, "ordinary output", "Cannot open the file as archive"
        )

        with (
            patch("whatyouship.inspectors.nsis_cache.shutil.which", return_value="7z"),
            patch("whatyouship.inspectors.nsis_cache.subprocess.run", return_value=failure),
            self.assertRaisesRegex(ValueError, "7-Zip extraction failed with exit code 2"),
        ):
            NsisInspector().inspect(source)

        self.assertFalse(self._entry(source).exists())
        self.assertEqual(list(self.cache_root.iterdir()), [])

    def test_plain_exe_is_rejected_without_7zip(self) -> None:
        """Do not treat an arbitrary executable as an NSIS installer."""
        source = self.root / "application.exe"
        _write_exe(source, nsis=False)

        with (
            patch("whatyouship.inspectors.nsis_cache.shutil.which") as which,
            self.assertRaisesRegex(
                ValueError,
                "Unsupported EXE artifact .*not an NSIS or Inno Setup installer",
            ),
        ):
            inspect_artifact(source)

        which.assert_not_called()

    def test_existing_lint_rule_applies_to_extracted_payload(self) -> None:
        """Run generic lint rules against NSIS payload paths."""
        source = self._source()
        output = io.StringIO()

        with (
            patch("whatyouship.inspectors.nsis_cache.shutil.which", return_value="7z"),
            patch(
                "whatyouship.inspectors.nsis_cache.subprocess.run",
                side_effect=self._successful_run({"build/module.obj": b"object"}),
            ),
            contextlib.redirect_stdout(output),
        ):
            result = main(["lint", str(source)])

        self.assertEqual(result, 0)
        self.assertIn(
            f"build-artifact-extension | warning | {Path('build/module.obj')}",
            output.getvalue(),
        )

    def test_compare_two_nsis_payloads(self) -> None:
        """Use generic comparison for two extracted NSIS releases."""
        old = self._source("old.exe")
        new = self._source("new.exe")
        new.write_bytes(new.read_bytes() + b"different digest")
        payloads = [
            {"removed.txt": b"old", "changed.txt": b"old", "same.txt": b"same"},
            {"added.txt": b"new", "changed.txt": b"new", "same.txt": b"same"},
        ]
        output = io.StringIO()

        def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
            """Extract the payload selected by installer path.

            :param command: 7-Zip command line.
            :param kwargs: Subprocess options supplied by the cache.
            :returns: Successful completed process.
            """
            files = payloads[0] if Path(command[-1]) == old else payloads[1]
            return self._successful_run(files)(command, **kwargs)

        with (
            patch("whatyouship.inspectors.nsis_cache.shutil.which", return_value="7z"),
            patch("whatyouship.inspectors.nsis_cache.subprocess.run", side_effect=run),
            contextlib.redirect_stdout(output),
        ):
            result = main(["compare", str(old), str(new)])

        self.assertEqual(result, 0)
        self.assertIn("Added: 1\nRemoved: 1\nChanged: 1\nUnchanged: 1", output.getvalue())

    def test_windows_outer_signature_uses_authenticode_backend(self) -> None:
        """Verify the original installer separately on Windows."""
        source = self._source()
        expected = ArtifactSignature(status="valid")
        self.signature_patch.stop()
        with (
            patch("whatyouship.inspectors.nsis.sys.platform", "win32"),
            patch(
                "whatyouship.inspectors.windows_authenticode.WindowsAuthenticodeVerifier.verify",
                return_value=expected,
            ) as verify,
        ):
            actual = NsisInspector()._signature(source)

        self.assertEqual(actual, expected)
        verify.assert_called_once_with(source)


if __name__ == "__main__":
    unittest.main()
