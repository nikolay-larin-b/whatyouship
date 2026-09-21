# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for MSI file extraction into release artifacts."""

import hashlib
import json
import tempfile
import unittest
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from whatyouship.inspectors.msi import MsiInspector
from whatyouship.model import BinaryMetadata


_MSI_HEADER = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class MsiInspectorTests(unittest.TestCase):
    """Verify MSI payloads and target paths using synthetic pymsi data."""

    def test_reads_payloads_and_target_installation_paths(self) -> None:
        """Prefer target long names and hash extracted payload bytes."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "release.msi"
            source.write_bytes(_MSI_HEADER + b"synthetic MSI data")

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
                patch(
                    "whatyouship.inspectors.msi_cache.platformdirs.user_cache_dir",
                    return_value=str(Path(temporary_directory) / "cache"),
                ),
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

    def test_cache_miss_publishes_extracted_payloads(self) -> None:
        """Create a completed content-keyed entry after initial extraction."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "release.msi"
            source.write_bytes(_MSI_HEADER + b"payload archive")
            cache_home = root / "cache"
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            entry = cache_home / "msi" / "v1" / digest

            with (
                patch(
                    "whatyouship.inspectors.msi_cache.platformdirs.user_cache_dir",
                    return_value=str(cache_home),
                ),
                patch.object(
                    MsiInspector,
                    "_extract_payloads",
                    return_value=iter([(Path("App/app.bin"), b"abc")]),
                ) as extract,
            ):
                artifact = MsiInspector().inspect(source)

            extract.assert_called_once_with(source)
            self.assertEqual(artifact.files[0].relative_path, Path("App/app.bin"))
            self.assertEqual(artifact.files[0].sha256, hashlib.sha256(b"abc").hexdigest())
            self.assertEqual((entry / "files" / "00000000.bin").read_bytes(), b"abc")
            self.assertEqual(json.loads((entry / "manifest.json").read_text())["version"], 1)

    def test_cache_hit_skips_msi_extraction_but_reinspects_binary(self) -> None:
        """Reuse payloads while running binary inspection on every analysis."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "release.msi"
            source.write_bytes(_MSI_HEADER + b"same archive")

            with (
                patch(
                    "whatyouship.inspectors.msi_cache.platformdirs.user_cache_dir",
                    return_value=str(root / "cache"),
                ),
                patch.object(
                    MsiInspector,
                    "_extract_payloads",
                    return_value=iter([(Path("app.bin"), b"abc")]),
                ) as extract,
                patch("whatyouship.inspectors.msi.PeInspector.inspect", return_value=None) as binary_inspect,
            ):
                first = MsiInspector().inspect(source)
                second = MsiInspector().inspect(source)

            extract.assert_called_once_with(source)
            self.assertEqual(first, second)
            self.assertEqual(binary_inspect.call_count, 2)

    def test_identical_msi_content_at_different_paths_shares_entry(self) -> None:
        """Key extracted content by MSI bytes instead of source name or path."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first_path = root / "first.msi"
            second_path = root / "elsewhere" / "renamed.msi"
            second_path.parent.mkdir()
            content = _MSI_HEADER + b"identical archive"
            first_path.write_bytes(content)
            second_path.write_bytes(content)
            cache_home = root / "cache"

            with (
                patch(
                    "whatyouship.inspectors.msi_cache.platformdirs.user_cache_dir",
                    return_value=str(cache_home),
                ),
                patch.object(
                    MsiInspector,
                    "_extract_payloads",
                    return_value=iter([(Path("app.bin"), b"abc")]),
                ) as extract,
            ):
                first = MsiInspector().inspect(first_path)
                second = MsiInspector().inspect(second_path)

            extract.assert_called_once_with(first_path)
            self.assertEqual(first.files, second.files)
            self.assertEqual(first.source_path, first_path)
            self.assertEqual(second.source_path, second_path)
            self.assertEqual(
                [path.name for path in (cache_home / "msi" / "v1").iterdir()],
                [hashlib.sha256(content).hexdigest()],
            )

    def test_changed_msi_content_uses_a_new_entry(self) -> None:
        """Reextract when the same MSI path has different complete bytes."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "release.msi"
            first_content = _MSI_HEADER + b"first archive"
            second_content = _MSI_HEADER + b"second archive"
            source.write_bytes(first_content)
            cache_home = root / "cache"

            with (
                patch(
                    "whatyouship.inspectors.msi_cache.platformdirs.user_cache_dir",
                    return_value=str(cache_home),
                ),
                patch.object(
                    MsiInspector,
                    "_extract_payloads",
                    side_effect=[
                        iter([(Path("app.bin"), b"first")]),
                        iter([(Path("app.bin"), b"second")]),
                    ],
                ) as extract,
            ):
                first = MsiInspector().inspect(source)
                source.write_bytes(second_content)
                second = MsiInspector().inspect(source)

            self.assertEqual(extract.call_count, 2)
            self.assertNotEqual(first.files[0].sha256, second.files[0].sha256)
            self.assertEqual(
                {path.name for path in (cache_home / "msi" / "v1").iterdir()},
                {
                    hashlib.sha256(first_content).hexdigest(),
                    hashlib.sha256(second_content).hexdigest(),
                },
            )

    def test_incomplete_cache_entry_is_rebuilt(self) -> None:
        """Ignore an entry whose manifest names a missing payload."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "release.msi"
            source.write_bytes(_MSI_HEADER + b"archive")
            cache_home = root / "cache"
            entry = cache_home / "msi" / "v1" / hashlib.sha256(source.read_bytes()).hexdigest()
            entry.mkdir(parents=True)
            (entry / "manifest.json").write_text(json.dumps({
                "version": 1,
                "files": [{
                    "relative_path": "app.bin",
                    "size_bytes": 3,
                    "sha256": hashlib.sha256(b"abc").hexdigest(),
                }],
            }))

            with (
                patch(
                    "whatyouship.inspectors.msi_cache.platformdirs.user_cache_dir",
                    return_value=str(cache_home),
                ),
                patch.object(
                    MsiInspector,
                    "_extract_payloads",
                    return_value=iter([(Path("app.bin"), b"fresh")]),
                ) as extract,
            ):
                artifact = MsiInspector().inspect(source)

            extract.assert_called_once_with(source)
            self.assertEqual(artifact.files[0].sha256, hashlib.sha256(b"fresh").hexdigest())
            self.assertEqual((entry / "files" / "00000000.bin").read_bytes(), b"fresh")

    def test_failed_extraction_does_not_publish_entry(self) -> None:
        """Leave no visible entry or temporary directory after partial extraction."""
        def fail_after_one_file(source_path: Path) -> Iterator[tuple[Path, bytes]]:
            """Yield one payload before simulating a decompression failure.

            :param source_path: MSI path supplied by the inspector.
            :yields: One partial payload before raising an error.
            :raises RuntimeError: After the first payload.
            """
            yield Path("partial.bin"), b"partial"
            raise RuntimeError("broken extraction")

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "release.msi"
            source.write_bytes(_MSI_HEADER + b"broken archive")
            cache_home = root / "cache"
            entry = cache_home / "msi" / "v1" / hashlib.sha256(source.read_bytes()).hexdigest()

            with (
                patch(
                    "whatyouship.inspectors.msi_cache.platformdirs.user_cache_dir",
                    return_value=str(cache_home),
                ),
                patch.object(
                    MsiInspector,
                    "_extract_payloads",
                    side_effect=fail_after_one_file,
                ),
            ):
                with self.assertRaisesRegex(ValueError, "Unable to inspect MSI"):
                    MsiInspector().inspect(source)

            self.assertFalse(entry.exists())
            self.assertEqual(list((cache_home / "msi" / "v1").iterdir()), [])

    def test_invalid_msi_is_reported(self) -> None:
        """Return a readable error for an invalid MSI package."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "invalid.msi"
            source.write_bytes(b"not an MSI")

            with self.assertRaisesRegex(ValueError, "Unable to inspect MSI"):
                MsiInspector().inspect(source)


if __name__ == "__main__":
    unittest.main()
