# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for MSI file extraction into release artifacts."""

import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from whatyouship.inspectors.msi import MsiInspector
from whatyouship.model import BinaryMetadata


class MsiInspectorTests(unittest.TestCase):
    """Verify MSI payloads and target paths using synthetic pymsi data."""

    def test_reads_payloads_and_target_installation_paths(self) -> None:
        """Prefer target long names and hash extracted payload bytes."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "release.msi"
            source.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1synthetic MSI data")

            root = SimpleNamespace(id="TARGETDIR", parent=None)
            app = SimpleNamespace(id="APPDIR", parent=root)
            bin_directory = SimpleNamespace(id="BINDIR", parent=app)
            flat_directory = SimpleNamespace(id="FLATDIR", parent=app)
            first = Mock()
            first.name = "LONGNA~1.ILK|Long Name.ilk"
            first.component.directory = bin_directory
            first.resolve.return_value.decompress.return_value = memoryview(b"abc")
            second = Mock()
            second.name = "README.TXT"
            second.component.directory = flat_directory
            second.resolve.return_value.decompress.return_value = memoryview(b"")

            package = Mock()
            package.get.return_value.iter.return_value = [
                {"Directory": "TARGETDIR", "DefaultDir": "SourceDir"},
                {"Directory": "APPDIR", "DefaultDir": "APP~1|Application:source-app"},
                {"Directory": "BINDIR", "DefaultDir": "BIN:source-bin"},
                {"Directory": "FLATDIR", "DefaultDir": ".:source-flat"},
            ]
            package_context = MagicMock()
            package_context.__enter__ = Mock(return_value=package)
            package_context.__exit__ = Mock(return_value=False)
            binary_metadata = BinaryMetadata("PE", "x86_64", "executable")

            with (
                patch("whatyouship.inspectors.msi.pymsi.Package", return_value=package_context),
                patch(
                    "whatyouship.inspectors.msi.pymsi.Msi",
                    return_value=SimpleNamespace(files={"second": second, "first": first}),
                ) as msi_factory,
                patch(
                    "whatyouship.inspectors.msi.PeInspector.inspect",
                    side_effect=[None, binary_metadata],
                ),
            ):
                artifact = MsiInspector().inspect(source)

            msi_factory.assert_called_once_with(package, load_data=True)
            self.assertEqual(artifact.source_path, source)
            self.assertEqual(
                [file.relative_path for file in artifact.files],
                [Path("Application/BIN/Long Name.ilk"), Path("Application/README.TXT")],
            )
            self.assertEqual([file.size_bytes for file in artifact.files], [3, 0])
            self.assertEqual(artifact.files[0].binary, binary_metadata)
            self.assertIsNone(artifact.files[1].binary)
            self.assertEqual(
                [file.sha256 for file in artifact.files],
                [hashlib.sha256(b"abc").hexdigest(), hashlib.sha256(b"").hexdigest()],
            )

    def test_invalid_msi_is_reported(self) -> None:
        """Return a readable error for an invalid MSI package."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "invalid.msi"
            source.write_bytes(b"not an MSI")

            with self.assertRaisesRegex(ValueError, "Unable to inspect MSI"):
                MsiInspector().inspect(source)


if __name__ == "__main__":
    unittest.main()
