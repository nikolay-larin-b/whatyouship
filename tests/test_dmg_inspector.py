# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for DMG artifact routing and generic mounted-volume analysis."""

import contextlib
import hashlib
import io
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import patch

from whatyouship.cli import main
from whatyouship.inspectors import inspect_artifact
from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.inspectors.dmg import DmgInspector
from whatyouship.inspectors.dmg_7zip_cache import DmgExtractedVolume
from whatyouship.inspectors.macos_disk_image import DiskImageMetadata
from whatyouship.model import ArtifactSymbolicLink


@contextlib.contextmanager
def _mounted_at(directory: Path) -> Iterator[Path]:
    """Yield a synthetic mounted volume for inspector tests.

    :param directory: Directory representing the mounted volume.
    :yields: Synthetic mounted volume path.
    """
    yield directory


class DmgInspectorTests(unittest.TestCase):
    """Verify native and cross-platform DMG inspection routing."""

    def setUp(self) -> None:
        """Create disposable source and mounted-volume paths."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "release.dmg"
        self.source.write_bytes(b"synthetic disk image")
        self.volume = self.root / "volume"
        self.volume.mkdir()
        platform = patch("whatyouship.inspectors.dmg.sys.platform", "darwin")
        platform.start()
        self.addCleanup(platform.stop)
        metadata = patch(
            "whatyouship.inspectors.dmg.inspect_disk_image_metadata",
            return_value=DiskImageMetadata(False, False),
        )
        metadata.start()
        self.addCleanup(metadata.stop)

    def test_inspect_uses_source_path_and_sorted_regular_files(self) -> None:
        """Inspect mounted files while preserving the original DMG identity."""
        (self.volume / "z.txt").write_bytes(b"last")
        (self.volume / "a.txt").write_bytes(b"first")

        with patch(
            "whatyouship.inspectors.dmg.MacOSDiskImageMounter.mount",
            return_value=_mounted_at(self.volume),
        ) as mount, patch(
            "whatyouship.inspectors.dmg.DirectoryInspector.inspect",
            wraps=DirectoryInspector().inspect,
        ) as inspect_directory:
            artifact = DmgInspector().inspect(self.source)

        mount.assert_called_once_with(self.source)
        inspect_directory.assert_called_once_with(
            self.volume,
            validate_executable_permissions=True,
        )
        self.assertEqual(artifact.source_path, self.source)
        self.assertEqual(
            [file.relative_path for file in artifact.files],
            [Path("a.txt"), Path("z.txt")],
        )
        self.assertEqual([file.size_bytes for file in artifact.files], [5, 4])
        self.assertEqual(
            artifact.files[0].sha256, hashlib.sha256(b"first").hexdigest()
        )
        self.assertEqual(artifact.signature.status, "unsupported")
        self.assertFalse(artifact.license_agreement_present)

    def test_non_macos_uses_cached_7zip_volume_without_license_metadata(
        self,
    ) -> None:
        """Use the cross-platform extraction backend outside macOS."""
        (self.volume / "payload.txt").write_bytes(b"payload")
        digest = hashlib.sha256(self.source.read_bytes()).hexdigest()

        with patch(
            "whatyouship.inspectors.dmg.sys.platform", "linux"
        ), patch(
            "whatyouship.inspectors.dmg.DmgSevenZipExtractionCache.load_or_populate",
            return_value=DmgExtractedVolume(
                self.volume,
                (ArtifactSymbolicLink(Path("current"), "payload.txt"),),
            ),
        ) as cache, patch(
            "whatyouship.inspectors.dmg.inspect_disk_image_metadata"
        ) as metadata:
            artifact = DmgInspector().inspect(self.source)

        cache.assert_called_once_with(digest, self.source)
        metadata.assert_not_called()
        self.assertEqual(artifact.source_path, self.source)
        self.assertEqual(
            [file.relative_path for file in artifact.files],
            [Path("payload.txt")],
        )
        self.assertEqual(
            artifact.symbolic_links,
            [ArtifactSymbolicLink(Path("current"), "payload.txt")],
        )
        self.assertIsNone(artifact.license_agreement_present)

    def test_license_image_uses_cached_normalized_image(self) -> None:
        """Mount a normalized cached image without losing source metadata."""
        normalized = self.root / "normalized.dmg"
        normalized.write_bytes(b"normalized")
        digest = hashlib.sha256(self.source.read_bytes()).hexdigest()

        with patch(
            "whatyouship.inspectors.dmg.inspect_disk_image_metadata",
            return_value=DiskImageMetadata(False, True),
        ), patch(
            "whatyouship.inspectors.dmg.DmgConversionCache.load_or_populate",
            return_value=normalized,
        ) as cache, patch(
            "whatyouship.inspectors.dmg.MacOSDiskImageMounter.mount",
            return_value=_mounted_at(self.volume),
        ) as mount:
            artifact = DmgInspector().inspect(self.source)

        cache.assert_called_once_with(digest, self.source)
        mount.assert_called_once_with(normalized)
        self.assertEqual(artifact.source_path, self.source)
        self.assertTrue(artifact.license_agreement_present)

    def test_encrypted_image_is_rejected_before_mounting(self) -> None:
        """Reject encrypted images because no password input is supported."""
        with patch(
            "whatyouship.inspectors.dmg.inspect_disk_image_metadata",
            return_value=DiskImageMetadata(True, False),
        ), patch(
            "whatyouship.inspectors.dmg.MacOSDiskImageMounter.mount"
        ) as mount, self.assertRaisesRegex(ValueError, "Encrypted DMG"):
            DmgInspector().inspect(self.source)

        mount.assert_not_called()

    def test_case_insensitive_dmg_extension_routes_to_dmg_inspector(self) -> None:
        """Recognize uppercase DMG extensions through artifact routing."""
        source = self.root / "release.DMG"
        source.write_bytes(b"synthetic disk image")

        with patch(
            "whatyouship.inspectors.DmgInspector.inspect",
            wraps=DmgInspector().inspect,
        ) as inspect, patch(
            "whatyouship.inspectors.dmg.MacOSDiskImageMounter.mount",
            return_value=_mounted_at(self.volume),
        ):
            artifact = inspect_artifact(source)

        inspect.assert_called_once_with(source)
        self.assertEqual(artifact.source_path, source)

    def test_mount_failure_is_reported_as_dmg_inspection_error(self) -> None:
        """Add artifact context to errors from the platform backend."""
        with patch(
            "whatyouship.inspectors.dmg.MacOSDiskImageMounter.mount",
            side_effect=ValueError("Disk image mounting requires macOS"),
        ), self.assertRaisesRegex(
            ValueError,
            "Unable to inspect DMG .*Disk image mounting requires macOS",
        ):
            DmgInspector().inspect(self.source)

    def test_missing_and_directory_sources_keep_specific_errors(self) -> None:
        """Validate the source before invoking the platform backend."""
        missing = self.root / "missing.dmg"

        with patch(
            "whatyouship.inspectors.dmg.MacOSDiskImageMounter.mount"
        ) as mount:
            with self.assertRaisesRegex(FileNotFoundError, "Artifact does not exist"):
                DmgInspector().inspect(missing)
            with self.assertRaisesRegex(
                IsADirectoryError, "DMG artifact is not a file"
            ):
                DmgInspector().inspect(self.volume)

        mount.assert_not_called()

    def test_cli_inspect_and_lint_use_generic_volume_analysis(self) -> None:
        """Run existing inspect output and lint rules against a DMG volume."""
        target = self.volume / "nested" / "build.obj"
        target.parent.mkdir()
        target.write_bytes(b"object")
        inspect_output = io.StringIO()
        lint_output = io.StringIO()

        with patch(
            "whatyouship.inspectors.dmg.MacOSDiskImageMounter.mount",
            side_effect=[_mounted_at(self.volume), _mounted_at(self.volume)],
        ):
            with contextlib.redirect_stdout(inspect_output):
                inspect_result = main(["inspect", str(self.source)])
            with contextlib.redirect_stdout(lint_output):
                lint_result = main(["lint", str(self.source)])

        self.assertEqual(inspect_result, 0)
        self.assertEqual(lint_result, 1)
        self.assertIn(f"Source: {self.source}\nFiles: 1", inspect_output.getvalue())
        self.assertIn(
            "Embedded license agreement: absent", inspect_output.getvalue()
        )
        self.assertIn("nested/build.obj | 6 |", inspect_output.getvalue())
        self.assertIn(
            "build-artifact-extension | warning | nested/build.obj",
            lint_output.getvalue(),
        )
        self.assertIn(
            "missing-license-agreement | error | .",
            lint_output.getvalue(),
        )

    def test_cli_compare_dmgs_classifies_file_changes(self) -> None:
        """Reuse generic comparison for two mounted DMG volumes."""
        old_source = self.root / "old.dmg"
        new_source = self.root / "new.dmg"
        old_source.write_bytes(b"old disk image")
        new_source.write_bytes(b"new disk image")
        old_volume = self.root / "old-volume"
        new_volume = self.root / "new-volume"
        old_volume.mkdir()
        new_volume.mkdir()
        (old_volume / "removed.txt").write_bytes(b"old")
        (old_volume / "changed.txt").write_bytes(b"old")
        (old_volume / "same.txt").write_bytes(b"same")
        (new_volume / "added.txt").write_bytes(b"new")
        (new_volume / "changed.txt").write_bytes(b"new")
        (new_volume / "same.txt").write_bytes(b"same")
        output = io.StringIO()

        with patch(
            "whatyouship.inspectors.dmg.MacOSDiskImageMounter.mount",
            side_effect=[_mounted_at(old_volume), _mounted_at(new_volume)],
        ), contextlib.redirect_stdout(output):
            result = main(["compare", str(old_source), str(new_source)])

        self.assertEqual(result, 0)
        self.assertIn(
            "Added: 1\nRemoved: 1\nChanged: 1\nUnchanged: 1",
            output.getvalue(),
        )
        self.assertIn("Added files:\n  added.txt", output.getvalue())
        self.assertIn("Removed files:\n  removed.txt", output.getvalue())
        self.assertIn("Changed files:\n  changed.txt", output.getvalue())

    def test_cli_help_lists_dmg_for_every_artifact_argument(self) -> None:
        """Advertise DMG support in inspect, lint, and compare help."""
        for command in ("inspect", "lint", "compare"):
            with self.subTest(command=command):
                output = io.StringIO()
                with (
                    contextlib.redirect_stdout(output),
                    self.assertRaises(SystemExit) as result,
                ):
                    main([command, "--help"])

                self.assertEqual(result.exception.code, 0)
                self.assertIn("DMG", output.getvalue())


if __name__ == "__main__":
    unittest.main()
