# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for single-volume DMG extraction through 7-Zip."""

import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.inspectors.dmg_7zip_cache import (
    DmgSevenZipExtractionCache,
    find_7zip,
)


_SINGLE_HFS_LISTING = """\
Path = release.dmg
Type = Dmg

Path = 4.hfs
Type = HFS
"""


class DmgSevenZipExtractionCacheTests(unittest.TestCase):
    """Verify DMG listing, extraction, validation, and cache reuse."""

    def setUp(self) -> None:
        """Create disposable source and cache directories."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache_root = self.root / "cache" / "dmg-7zip" / "v1"
        self.source = self.root / "release.dmg"
        self.source.write_bytes(b"synthetic disk image")
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()
        cache = patch(
            "whatyouship.inspectors.dmg_7zip_cache.cache_directory",
            return_value=self.cache_root,
        )
        self.cache_directory = cache.start()
        self.addCleanup(cache.stop)

    def _successful_run(
        self, command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        """List one HFS volume and materialize one regular file.

        :param command: 7-Zip command line.
        :param _kwargs: Subprocess options supplied by the cache.
        :returns: Successful completed process.
        """
        if command[1] == "l":
            return subprocess.CompletedProcess(
                command, 0, _SINGLE_HFS_LISTING, ""
            )
        output = Path(
            next(argument[2:] for argument in command if argument.startswith("-o"))
        )
        payload = output / "Release" / "Application.app" / "payload.bin"
        payload.parent.mkdir(parents=True)
        payload.write_bytes(b"payload")
        return subprocess.CompletedProcess(command, 0, "Everything is Ok", "")

    def test_extracts_regular_files_with_metadata_and_links_disabled(self) -> None:
        """Publish the only volume and use flags matching native reports."""
        with patch(
            "whatyouship.inspectors.dmg_7zip_cache.find_7zip", return_value="7z"
        ), patch(
            "whatyouship.inspectors.dmg_7zip_cache.subprocess.run",
            side_effect=self._successful_run,
        ) as run:
            volume = DmgSevenZipExtractionCache().load_or_populate(
                self.digest, self.source
            )

        self.assertEqual(volume.name, "Release")
        self.cache_directory.assert_called_once_with("dmg-7zip")
        self.assertEqual(
            (volume / "Application.app" / "payload.bin").read_bytes(),
            b"payload",
        )
        self.assertEqual(run.call_count, 2)
        listing = run.call_args_list[0].args[0]
        extraction = run.call_args_list[1].args[0]
        self.assertEqual(listing[:4], ["7z", "l", "-slt", "-sccUTF-8"])
        self.assertEqual(extraction[:5], ["7z", "x", "-y", "-bd", "-bb0"])
        self.assertIn("-sns-", extraction)
        self.assertIn("-snl-", extraction)
        for call in run.call_args_list:
            self.assertTrue(call.kwargs["capture_output"])
            self.assertEqual(call.kwargs["errors"], "replace")
            self.assertFalse(call.kwargs["check"])

    def test_finds_supported_7zip_executable_names_in_order(self) -> None:
        """Support standalone and installed Windows 7-Zip command names."""
        with patch(
            "whatyouship.inspectors.dmg_7zip_cache.shutil.which",
            side_effect=[None, None, r"C:\\tools\\7z.exe"],
        ) as which:
            executable = find_7zip()

        self.assertEqual(executable, r"C:\\tools\\7z.exe")
        self.assertEqual(
            [call.args[0] for call in which.call_args_list],
            ["7zz", "7z", "7z.exe"],
        )

    def test_missing_7zip_has_actionable_error(self) -> None:
        """Tell the user which external command the backend requires."""
        with patch(
            "whatyouship.inspectors.dmg_7zip_cache.shutil.which",
            return_value=None,
        ), self.assertRaisesRegex(FileNotFoundError, "requires 7-Zip"):
            find_7zip()

    def test_cache_hit_does_not_require_7zip(self) -> None:
        """Reuse a validated extracted tree without external commands."""
        with patch(
            "whatyouship.inspectors.dmg_7zip_cache.find_7zip", return_value="7z"
        ), patch(
            "whatyouship.inspectors.dmg_7zip_cache.subprocess.run",
            side_effect=self._successful_run,
        ):
            first = DmgSevenZipExtractionCache().load_or_populate(
                self.digest, self.source
            )

        with patch(
            "whatyouship.inspectors.dmg_7zip_cache.find_7zip"
        ) as find, patch(
            "whatyouship.inspectors.dmg_7zip_cache.subprocess.run"
        ) as run:
            second = DmgSevenZipExtractionCache().load_or_populate(
                self.digest, self.source
            )

        self.assertEqual(first, second)
        find.assert_not_called()
        run.assert_not_called()

    def test_accepts_single_apfs_filesystem(self) -> None:
        """Accept an APFS volume recognized by 7-Zip."""
        def run(
            command: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            """Substitute an APFS listing before normal extraction.

            :param command: 7-Zip command line.
            :param kwargs: Subprocess options supplied by the cache.
            :returns: Successful completed process.
            """
            if command[1] == "l":
                return subprocess.CompletedProcess(
                    command,
                    0,
                    "Path = release.dmg\nType = Dmg\n\nType = APFS\n",
                    "",
                )
            return self._successful_run(command, **kwargs)

        with patch(
            "whatyouship.inspectors.dmg_7zip_cache.find_7zip", return_value="7z"
        ), patch(
            "whatyouship.inspectors.dmg_7zip_cache.subprocess.run",
            side_effect=run,
        ):
            volume = DmgSevenZipExtractionCache().load_or_populate(
                self.digest, self.source
            )

        self.assertTrue((volume / "Application.app" / "payload.bin").is_file())

    def test_rejects_listing_without_exactly_one_supported_filesystem(self) -> None:
        """Do not cache a raw or ambiguous DMG extraction."""
        listing = subprocess.CompletedProcess(
            ["7z", "l"], 0, "Type = Dmg\n", ""
        )

        with patch(
            "whatyouship.inspectors.dmg_7zip_cache.find_7zip", return_value="7z"
        ), patch(
            "whatyouship.inspectors.dmg_7zip_cache.subprocess.run",
            return_value=listing,
        ) as run, self.assertRaisesRegex(
            ValueError, "exactly one supported filesystem"
        ):
            DmgSevenZipExtractionCache().load_or_populate(
                self.digest, self.source
            )

        run.assert_called_once()
        self.assertEqual(list(self.cache_root.iterdir()), [])

    def test_rejects_multiple_extracted_volume_roots(self) -> None:
        """Require extraction to produce one unambiguous volume root."""
        def run(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            """Create two volume directories during extraction.

            :param command: 7-Zip command line.
            :param _kwargs: Subprocess options supplied by the cache.
            :returns: Successful completed process.
            """
            if command[1] == "l":
                return subprocess.CompletedProcess(
                    command, 0, _SINGLE_HFS_LISTING, ""
                )
            output = Path(
                next(
                    argument[2:]
                    for argument in command
                    if argument.startswith("-o")
                )
            )
            (output / "First").mkdir()
            (output / "Second").mkdir()
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch(
            "whatyouship.inspectors.dmg_7zip_cache.find_7zip", return_value="7z"
        ), patch(
            "whatyouship.inspectors.dmg_7zip_cache.subprocess.run",
            side_effect=run,
        ), self.assertRaisesRegex(ValueError, "exactly one DMG volume directory"):
            DmgSevenZipExtractionCache().load_or_populate(
                self.digest, self.source
            )

        self.assertEqual(list(self.cache_root.iterdir()), [])

    def test_reports_listing_failure_without_publishing_partial_data(self) -> None:
        """Preserve actionable diagnostics from a failed preflight listing."""
        failure = subprocess.CompletedProcess(
            ["7z", "l"], 2, "", "Cannot open the file as archive"
        )

        with patch(
            "whatyouship.inspectors.dmg_7zip_cache.find_7zip", return_value="7z"
        ), patch(
            "whatyouship.inspectors.dmg_7zip_cache.subprocess.run",
            return_value=failure,
        ), self.assertRaisesRegex(
            ValueError,
            "7-Zip DMG listing failed with exit code 2: Cannot open",
        ):
            DmgSevenZipExtractionCache().load_or_populate(
                self.digest, self.source
            )

        self.assertEqual(list(self.cache_root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
