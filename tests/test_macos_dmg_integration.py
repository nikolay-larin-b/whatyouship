# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Integration tests for the native macOS DMG backend.

Run on macOS with::

    python -m unittest tests.test_macos_dmg_integration
"""

import hashlib
import json
import os
import plistlib
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.inspectors.dmg import DmgInspector
from whatyouship.inspectors.dmg_cache import DmgConversionCache
from whatyouship.inspectors.macos_disk_image import (
    MacOSDiskImageMounter,
    convert_disk_image,
    inspect_disk_image_metadata,
)


_HDIUTIL = Path("/usr/bin/hdiutil")
_RUN_INTEGRATION = sys.platform == "darwin" and _HDIUTIL.is_file()


def _run_hdiutil(arguments: list[str]) -> None:
    """Run one non-interactive native disk image command.

    :param arguments: Arguments following the ``hdiutil`` executable.
    :raises AssertionError: If the command fails.
    """
    result = subprocess.run(
        [str(_HDIUTIL), *arguments],
        input=b"\0",
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        output = (result.stderr or result.stdout).decode(
            "utf-8",
            errors="replace",
        )
        raise AssertionError(
            f"hdiutil {' '.join(arguments)} failed: {output.strip()}"
        )


def _string_list(values: tuple[str, ...]) -> bytes:
    """Encode a classic ``STR#`` resource.

    :param values: Strings stored in the resource.
    :returns: Big-endian count followed by Pascal strings.
    """
    encoded = [value.encode("mac_roman") for value in values]
    if any(len(value) > 255 for value in encoded):
        raise ValueError("STR# test value exceeds 255 bytes")
    return struct.pack(">H", len(encoded)) + b"".join(
        bytes((len(value),)) + value for value in encoded
    )


def _resource(identifier: int, name: str, data: bytes) -> dict[str, object]:
    """Build one resource dictionary accepted by ``hdiutil udifrez``.

    :param identifier: Classic resource ID.
    :param name: Resource name.
    :param data: Raw resource data.
    :returns: Property-list resource dictionary.
    """
    return {
        "Attributes": "0x0000",
        "Data": data,
        "ID": str(identifier),
        "Name": name,
    }


def _embed_test_license(image: Path, resources_path: Path) -> None:
    """Embed a minimal English software license agreement in a DMG.

    :param image: Read-only disk image to update.
    :param resources_path: Temporary property-list path.
    """
    buttons = _string_list((
        "English",
        "Agree",
        "Disagree",
        "Print",
        "Save...",
        "Click Agree to access the test files.",
    ))
    resources = {
        "LPic": [_resource(
            5000,
            "",
            bytes.fromhex("00000002000000000000000000040000"),
        )],
        "STR#": [_resource(5000, "English buttons", buttons)],
        "TEXT": [_resource(
            5000,
            "English",
            b"Test software license agreement.\n",
        )],
    }
    resources_path.write_bytes(plistlib.dumps(resources))
    _run_hdiutil(["udifrez", str(image), "-xml", str(resources_path)])


@unittest.skipUnless(
    _RUN_INTEGRATION,
    "native DMG integration tests require macOS and hdiutil",
)
class MacOSDmgIntegrationTests(unittest.TestCase):
    """Exercise real disk image creation, attachment, and conversion."""

    def setUp(self) -> None:
        """Create an isolated payload and native compressed DMG."""
        temporary = tempfile.TemporaryDirectory(
            prefix="whatyouship-dmg-integration-"
        )
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.payload = self.root / "payload"
        self.payload.mkdir()
        (self.payload / "payload.txt").write_text(
            "native DMG integration payload\n",
            encoding="utf-8",
        )
        contents = self.payload / "Sample.app" / "Contents"
        executable = contents / "MacOS" / "sample"
        executable.parent.mkdir(parents=True)
        (contents / "Info.plist").write_bytes(plistlib.dumps({
            "CFBundleIdentifier": "com.example.sample",
            "CFBundleExecutable": "sample",
            "CFBundlePackageType": "APPL",
        }))
        executable.write_bytes(struct.pack(
            "<IIIIIIII",
            0xFEEDFACF,
            0x0100000C,
            0,
            0x2,
            0,
            0,
            0,
            0,
        ))
        executable.chmod(0o644)
        self.source = self.root / "release.dmg"
        _run_hdiutil([
            "create",
            "-srcfolder",
            str(self.payload),
            "-volname",
            "WhatYouShip Integration",
            "-format",
            "UDZO",
            "-ov",
            str(self.source),
        ])

    def test_mounts_reads_and_detaches_synthetic_image(self) -> None:
        """Read payload files and leave no private mount behind."""
        metadata = inspect_disk_image_metadata(self.source)
        self.assertFalse(metadata.encrypted)
        self.assertFalse(metadata.license_agreement_present)

        mounted_path: Path | None = None
        with MacOSDiskImageMounter().mount(self.source) as mounted:
            mounted_path = mounted
            self.assertEqual(
                (mounted / "payload.txt").read_text(encoding="utf-8"),
                "native DMG integration payload\n",
            )
            self.assertTrue(os.path.ismount(mounted))

        self.assertIsNotNone(mounted_path)
        assert mounted_path is not None
        self.assertFalse(os.path.ismount(mounted_path))
        self.assertFalse(mounted_path.exists())

    def test_normalizes_license_image_and_reuses_cache(self) -> None:
        """Remove presentation resources once and reuse the verified image."""
        _embed_test_license(
            self.source,
            self.root / "license-resources.plist",
        )
        metadata = inspect_disk_image_metadata(self.source)
        self.assertTrue(metadata.license_agreement_present)
        with self.source.open("rb") as stream:
            source_digest = hashlib.file_digest(stream, "sha256").hexdigest()
        cache_root = self.root / "cache" / "dmg" / "v1"

        with patch(
            "whatyouship.inspectors.dmg_cache.cache_directory",
            return_value=cache_root,
        ), patch(
            "whatyouship.inspectors.dmg_cache.convert_disk_image",
            wraps=convert_disk_image,
        ) as conversion:
            first = DmgConversionCache().load_or_populate(
                source_digest,
                self.source,
            )
            second = DmgConversionCache().load_or_populate(
                source_digest,
                self.source,
            )

        self.assertEqual(first, second)
        self.assertEqual(conversion.call_count, 1)
        self.assertFalse(
            inspect_disk_image_metadata(first).license_agreement_present
        )
        manifest = json.loads(
            (first.parent / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["version"], 3)
        self.assertEqual(manifest["size_bytes"], first.stat().st_size)
        with first.open("rb") as stream:
            normalized_digest = hashlib.file_digest(
                stream,
                "sha256",
            ).hexdigest()
        self.assertEqual(manifest["sha256"], normalized_digest)

        with MacOSDiskImageMounter().mount(first) as mounted:
            self.assertEqual(
                (mounted / "payload.txt").read_text(encoding="utf-8"),
                "native DMG integration payload\n",
            )

    def test_reports_non_executable_application_main_file(self) -> None:
        """Validate executable mode bits from the mounted DMG filesystem."""
        artifact = DmgInspector().inspect(self.source)

        self.assertEqual(len(artifact.bundles), 1)
        self.assertIn(
            "non-executable-main-file",
            {issue.identity for issue in artifact.bundles[0].issues},
        )


if __name__ == "__main__":
    unittest.main()
