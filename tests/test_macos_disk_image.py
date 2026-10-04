# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for the native macOS disk image mount lifecycle."""

import plistlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from whatyouship.inspectors.macos_disk_image import (
    MacOSDiskImageMounter,
    convert_disk_image,
    inspect_disk_image_metadata,
    verify_disk_image,
)


def _attach_result(mount_points: list[Path]) -> subprocess.CompletedProcess[bytes]:
    """Build a successful synthetic ``hdiutil attach`` result.

    :param mount_points: Volume paths to include in the result plist.
    :returns: Completed process containing the encoded attachment result.
    """
    entities: list[dict[str, str]] = [{"dev-entry": "/dev/disk99"}]
    entities.extend(
        {
            "dev-entry": f"/dev/disk99s{index}",
            "mount-point": str(mount_point),
        }
        for index, mount_point in enumerate(mount_points, start=1)
    )
    return subprocess.CompletedProcess(
        ["hdiutil", "attach"],
        0,
        plistlib.dumps({"system-entities": entities}),
        b"",
    )


class MacOSDiskImageMounterTests(unittest.TestCase):
    """Verify safe attachment, validation, and cleanup behavior."""

    def setUp(self) -> None:
        """Create a disposable disk image path and private mount root."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "release.dmg"
        self.source.write_bytes(b"synthetic image")
        self.mount_root = self.root / "private-mount"
        self.mount_root.mkdir()
        self.mount_point = self.mount_root / "volume"

    def _patch_mount_root(self) -> Any:
        """Patch temporary mount creation to use the test directory.

        :returns: Patch object replacing ``tempfile.mkdtemp``.
        """
        return patch(
            "whatyouship.inspectors.macos_disk_image.tempfile.mkdtemp",
            return_value=str(self.mount_root),
        )

    def test_reads_encryption_and_license_metadata(self) -> None:
        """Parse security-relevant properties from ``hdiutil imageinfo``."""
        result = subprocess.CompletedProcess(
            ["hdiutil", "imageinfo"],
            0,
            plistlib.dumps({
                "Properties": {
                    "Encrypted": False,
                    "Software License Agreement": True,
                }
            }),
            b"",
        )

        with patch(
            "whatyouship.inspectors.macos_disk_image.sys.platform", "darwin"
        ), patch(
            "whatyouship.inspectors.macos_disk_image.subprocess.run",
            return_value=result,
        ) as run:
            metadata = inspect_disk_image_metadata(self.source)

        self.assertFalse(metadata.encrypted)
        self.assertTrue(metadata.license_agreement_present)
        self.assertEqual(
            run.call_args.args[0][:2], ["/usr/bin/hdiutil", "imageinfo"]
        )
        self.assertEqual(run.call_args.kwargs["input"], b"\0")

    def test_converts_to_compressed_image_noninteractively(self) -> None:
        """Request an exact UDZO output path without interactive password input."""
        destination = self.root / "normalized.dmg"

        def complete(
            command: list[str], **_kwargs: object
        ) -> subprocess.CompletedProcess[bytes]:
            output_path = Path(command[command.index("-o") + 1])
            output_path.write_bytes(b"normalized")
            return subprocess.CompletedProcess(command, 0, b"", b"")

        with patch(
            "whatyouship.inspectors.macos_disk_image.subprocess.run",
            side_effect=complete,
        ) as run:
            convert_disk_image(self.source, destination)

        self.assertEqual(run.call_count, 2)
        command = run.call_args_list[0].args[0]
        self.assertEqual(command[:2], ["/usr/bin/hdiutil", "convert"])
        self.assertEqual(command[command.index("-format") + 1], "UDTO")
        raw_path = destination.parent / "intermediate.cdr"
        self.assertEqual(command[command.index("-o") + 1], str(raw_path))
        self.assertIn("-stdinpass", command)
        self.assertEqual(run.call_args_list[0].kwargs["input"], b"\0")
        compressed = run.call_args_list[1].args[0]
        self.assertEqual(compressed[:3], ["/usr/bin/hdiutil", "convert", str(raw_path)])
        self.assertEqual(compressed[compressed.index("-format") + 1], "UDZO")
        self.assertEqual(compressed[compressed.index("-o") + 1], str(destination))
        self.assertFalse(raw_path.exists())

    def test_verifies_disk_image_checksums_noninteractively(self) -> None:
        """Validate a normalized image before publishing it to the cache."""
        result = subprocess.CompletedProcess(
            ["hdiutil", "verify"],
            0,
            b"verified",
            b"",
        )

        with patch(
            "whatyouship.inspectors.macos_disk_image.sys.platform",
            "darwin",
        ), patch(
            "whatyouship.inspectors.macos_disk_image.subprocess.run",
            return_value=result,
        ) as run:
            verify_disk_image(self.source)

        self.assertEqual(
            run.call_args.args[0],
            [
                "/usr/bin/hdiutil",
                "verify",
                "-nocache",
                "-stdinpass",
                str(self.source.resolve()),
            ],
        )
        self.assertEqual(run.call_args.kwargs["input"], b"\0")
        self.assertTrue(run.call_args.kwargs["capture_output"])
        self.assertFalse(run.call_args.kwargs["check"])

    def test_failed_disk_image_verification_reports_diagnostics(self) -> None:
        """Reject an image whose internal checksums do not verify."""
        result = subprocess.CompletedProcess(
            ["hdiutil", "verify"],
            1,
            b"",
            b"hdiutil: verify failed - image checksum mismatch\n",
        )

        with patch(
            "whatyouship.inspectors.macos_disk_image.sys.platform",
            "darwin",
        ), patch(
            "whatyouship.inspectors.macos_disk_image.subprocess.run",
            return_value=result,
        ), self.assertRaisesRegex(
            ValueError,
            "hdiutil verify failed with exit code 1: .*checksum mismatch",
        ):
            verify_disk_image(self.source)

    def test_mount_uses_noninteractive_read_only_attachment_and_detaches(self) -> None:
        """Yield the private volume and detach it normally after use."""
        attach = _attach_result([self.mount_point])
        detach = subprocess.CompletedProcess(["hdiutil", "detach"], 0, b"", b"")

        with (
            patch("whatyouship.inspectors.macos_disk_image.sys.platform", "darwin"),
            self._patch_mount_root(),
            patch(
                "whatyouship.inspectors.macos_disk_image.os.path.ismount",
                return_value=False,
            ),
            patch(
                "whatyouship.inspectors.macos_disk_image.subprocess.run",
                side_effect=[attach, detach],
            ) as run,
            MacOSDiskImageMounter().mount(self.source) as mounted,
        ):
            self.assertEqual(mounted, self.mount_point)
            self.assertTrue(mounted.is_dir())

        attach_call = run.call_args_list[0]
        command = attach_call.args[0]
        self.assertEqual(command[:2], ["/usr/bin/hdiutil", "attach"])
        self.assertIn("-readonly", command)
        self.assertIn("-nobrowse", command)
        self.assertIn("-noautoopen", command)
        self.assertEqual(
            command[command.index("-mountpoint") + 1], str(self.mount_point)
        )
        self.assertIn("-plist", command)
        self.assertIn("-stdinpass", command)
        self.assertEqual(Path(command[-1]), self.source.resolve())
        self.assertEqual(attach_call.kwargs["input"], b"\0")
        self.assertTrue(attach_call.kwargs["capture_output"])
        self.assertFalse(attach_call.kwargs["check"])
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["/usr/bin/hdiutil", "detach", str(self.mount_point)],
        )
        self.assertFalse(self.mount_root.exists())

    def test_non_macos_platform_is_rejected_without_running_hdiutil(self) -> None:
        """Fail before creating a mount point or invoking a system command."""
        with (
            patch("whatyouship.inspectors.macos_disk_image.sys.platform", "linux"),
            patch(
                "whatyouship.inspectors.macos_disk_image.tempfile.mkdtemp"
            ) as mkdtemp,
            patch("whatyouship.inspectors.macos_disk_image.subprocess.run") as run,
            self.assertRaisesRegex(ValueError, "requires macOS"),
        ):
            with MacOSDiskImageMounter().mount(self.source):
                pass

        mkdtemp.assert_not_called()
        run.assert_not_called()

    def test_attach_failure_reports_bounded_diagnostics_without_detach(self) -> None:
        """Expose the system error and remove unused private directories."""
        failure = subprocess.CompletedProcess(
            ["hdiutil", "attach"],
            1,
            b"",
            b"hdiutil: attach failed - no mountable filesystems\n",
        )

        with (
            patch("whatyouship.inspectors.macos_disk_image.sys.platform", "darwin"),
            self._patch_mount_root(),
            patch(
                "whatyouship.inspectors.macos_disk_image.os.path.ismount",
                return_value=False,
            ),
            patch(
                "whatyouship.inspectors.macos_disk_image.subprocess.run",
                return_value=failure,
            ) as run,
            self.assertRaisesRegex(
                ValueError,
                "hdiutil attach failed with exit code 1: .*no mountable filesystems",
            ),
        ):
            with MacOSDiskImageMounter().mount(self.source):
                pass

        run.assert_called_once()
        self.assertFalse(self.mount_root.exists())

    def test_missing_hdiutil_is_reported_and_private_directories_are_removed(
        self,
    ) -> None:
        """Turn failure to execute the fixed system utility into a clear error."""
        with (
            patch("whatyouship.inspectors.macos_disk_image.sys.platform", "darwin"),
            self._patch_mount_root(),
            patch(
                "whatyouship.inspectors.macos_disk_image.os.path.ismount",
                return_value=False,
            ),
            patch(
                "whatyouship.inspectors.macos_disk_image.subprocess.run",
                side_effect=FileNotFoundError("missing"),
            ),
            self.assertRaisesRegex(
                FileNotFoundError, "Unable to run macOS disk image utility"
            ),
        ):
            with MacOSDiskImageMounter().mount(self.source):
                pass

        self.assertFalse(self.mount_root.exists())

    def test_embedded_license_agreement_is_reported_without_accepting_it(self) -> None:
        """Explain cancellation caused by an interactive disk image agreement."""
        attach = subprocess.CompletedProcess(
            ["hdiutil", "attach"], 1, b"", b"hdiutil: attach canceled\n"
        )
        imageinfo = subprocess.CompletedProcess(
            ["hdiutil", "imageinfo"],
            0,
            plistlib.dumps({
                "Properties": {
                    "Encrypted": False,
                    "Software License Agreement": True,
                }
            }),
            b"",
        )

        with (
            patch("whatyouship.inspectors.macos_disk_image.sys.platform", "darwin"),
            self._patch_mount_root(),
            patch(
                "whatyouship.inspectors.macos_disk_image.os.path.ismount",
                return_value=False,
            ),
            patch(
                "whatyouship.inspectors.macos_disk_image.subprocess.run",
                side_effect=[attach, imageinfo],
            ) as run,
            self.assertRaisesRegex(
                ValueError,
                "embedded software license agreement .* non-interactively",
            ),
        ):
            with MacOSDiskImageMounter().mount(self.source):
                pass

        self.assertEqual(run.call_count, 2)
        imageinfo_call = run.call_args_list[1]
        self.assertEqual(
            imageinfo_call.args[0][:2], ["/usr/bin/hdiutil", "imageinfo"]
        )
        self.assertEqual(imageinfo_call.kwargs["input"], b"\0")
        self.assertFalse(self.mount_root.exists())

    def test_invalid_plist_detaches_a_volume_found_at_private_mount_point(self) -> None:
        """Clean up a successful attachment even when its output is malformed."""
        attach = subprocess.CompletedProcess(
            ["hdiutil", "attach"], 0, b"not a plist", b""
        )
        detach = subprocess.CompletedProcess(["hdiutil", "detach"], 0, b"", b"")

        with (
            patch("whatyouship.inspectors.macos_disk_image.sys.platform", "darwin"),
            self._patch_mount_root(),
            patch(
                "whatyouship.inspectors.macos_disk_image.os.path.ismount",
                return_value=True,
            ),
            patch(
                "whatyouship.inspectors.macos_disk_image.subprocess.run",
                side_effect=[attach, detach],
            ) as run,
            self.assertRaisesRegex(ValueError, "invalid property list"),
        ):
            with MacOSDiskImageMounter().mount(self.source):
                pass

        self.assertEqual(run.call_count, 2)
        self.assertFalse(self.mount_root.exists())

    def test_external_existing_mount_is_rejected_and_not_detached(self) -> None:
        """Never detach a path that was not allocated by this operation."""
        external = self.root / "existing-volume"
        external.mkdir()
        attach = _attach_result([external])

        with (
            patch("whatyouship.inspectors.macos_disk_image.sys.platform", "darwin"),
            self._patch_mount_root(),
            patch(
                "whatyouship.inspectors.macos_disk_image.os.path.ismount",
                return_value=False,
            ),
            patch(
                "whatyouship.inspectors.macos_disk_image.subprocess.run",
                return_value=attach,
            ) as run,
            self.assertRaisesRegex(ValueError, "may already be mounted"),
        ):
            with MacOSDiskImageMounter().mount(self.source):
                pass

        run.assert_called_once()
        self.assertTrue(external.exists())
        self.assertFalse(self.mount_root.exists())

    def test_multiple_mounted_volumes_are_rejected_and_detached(self) -> None:
        """Reject ambiguous trees while cleaning up the private attachment."""
        attach = _attach_result([self.mount_point, self.mount_root / "second"])
        detach = subprocess.CompletedProcess(["hdiutil", "detach"], 0, b"", b"")

        with (
            patch("whatyouship.inspectors.macos_disk_image.sys.platform", "darwin"),
            self._patch_mount_root(),
            patch(
                "whatyouship.inspectors.macos_disk_image.os.path.ismount",
                return_value=True,
            ),
            patch(
                "whatyouship.inspectors.macos_disk_image.subprocess.run",
                side_effect=[attach, detach],
            ) as run,
            self.assertRaisesRegex(ValueError, "exactly one mountable volume; found 2"),
        ):
            with MacOSDiskImageMounter().mount(self.source):
                pass

        self.assertEqual(run.call_count, 2)

    def test_detach_failure_is_reported_without_forcing_or_removing_mount(self) -> None:
        """Leave the mount point intact when a normal detach cannot complete."""
        attach = _attach_result([self.mount_point])
        detach = subprocess.CompletedProcess(
            ["hdiutil", "detach"], 16, b"", b"hdiutil: couldn't unmount disk\n"
        )

        with (
            patch("whatyouship.inspectors.macos_disk_image.sys.platform", "darwin"),
            self._patch_mount_root(),
            patch(
                "whatyouship.inspectors.macos_disk_image.os.path.ismount",
                return_value=False,
            ),
            patch(
                "whatyouship.inspectors.macos_disk_image.subprocess.run",
                side_effect=[attach, detach],
            ) as run,
            self.assertRaisesRegex(
                ValueError, "hdiutil detach failed with exit code 16"
            ),
        ):
            with MacOSDiskImageMounter().mount(self.source):
                pass

        self.assertNotIn("-force", run.call_args_list[1].args[0])
        self.assertTrue(self.mount_root.exists())

    def test_body_error_is_preserved_when_detach_also_fails(self) -> None:
        """Annotate the primary failure instead of hiding it with cleanup failure."""
        attach = _attach_result([self.mount_point])
        detach = subprocess.CompletedProcess(
            ["hdiutil", "detach"], 16, b"", b"resource busy\n"
        )

        with (
            patch("whatyouship.inspectors.macos_disk_image.sys.platform", "darwin"),
            self._patch_mount_root(),
            patch(
                "whatyouship.inspectors.macos_disk_image.os.path.ismount",
                return_value=False,
            ),
            patch(
                "whatyouship.inspectors.macos_disk_image.subprocess.run",
                side_effect=[attach, detach],
            ),
            self.assertRaisesRegex(RuntimeError, "inspection failed") as raised,
        ):
            with MacOSDiskImageMounter().mount(self.source):
                raise RuntimeError("inspection failed")

        self.assertTrue(
            any("cleanup failed" in note for note in raised.exception.__notes__)
        )


if __name__ == "__main__":
    unittest.main()
