# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for ZIP artifact extraction, caching, and generic analysis."""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import lief

from whatyouship.cli import main
from whatyouship.inspectors.zip import ZipInspector
from whatyouship.inspectors.zip_cache import ZipExtractionCache


def _write_zip(path: Path, files: dict[str, bytes]) -> None:
    """Write a synthetic ZIP artifact.

    :param path: ZIP file to create.
    :param files: Archive member names and contents.
    """
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)


def _pe_payload() -> bytes:
    """Build a small PE executable for end-to-end ZIP inspection.

    :returns: Serialized PE executable bytes.
    """
    with lief.logging.level_scope(lief.logging.LEVEL.OFF):
        factory = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)
        section = lief.PE.Section(".text")
        section.content = [0xC3]
        factory.add_section(section)
        binary = factory.get()
        binary.header.add_characteristic(
            lief.PE.Header.CHARACTERISTICS.EXECUTABLE_IMAGE
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "app.exe"
            binary.write(path)
            return path.read_bytes()


class ZipInspectorTests(unittest.TestCase):
    """Verify safe ZIP extraction and reuse of directory analysis."""

    def setUp(self) -> None:
        """Keep ZIP cache entries inside a disposable test directory."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache_home = self.root / "cache"
        cache_patch = patch(
            "whatyouship.inspectors.zip_cache.cache_directory",
            return_value=self.cache_home / "zip" / "v1",
        )
        cache_patch.start()
        self.addCleanup(cache_patch.stop)

    def _entry(self, source: Path) -> Path:
        """Get the cache entry corresponding to a ZIP's complete bytes.

        :param source: Source ZIP archive.
        :returns: Versioned content-addressed cache entry path.
        """
        return self.cache_home / "zip" / "v1" / hashlib.sha256(source.read_bytes()).hexdigest()

    def test_regular_zip_uses_source_path_and_sorted_files(self) -> None:
        """Inspect file sizes and digests through the directory inspector."""
        source = self.root / "release.zip"
        _write_zip(source, {"z.txt": b"last", "a.txt": b"first"})

        artifact = ZipInspector().inspect(source)

        self.assertEqual(artifact.source_path, source)
        self.assertEqual([file.relative_path for file in artifact.files], [Path("a.txt"), Path("z.txt")])
        self.assertEqual([file.size_bytes for file in artifact.files], [5, 4])
        self.assertEqual(artifact.files[0].sha256, hashlib.sha256(b"first").hexdigest())
        self.assertEqual(artifact.signature.status, "unsupported")
        self.assertEqual((self._entry(source) / "files" / "a.txt").read_bytes(), b"first")

    def test_nested_directories_do_not_become_files(self) -> None:
        """Keep nested member paths and omit explicit directory entries."""
        source = self.root / "nested.zip"
        _write_zip(source, {"bin/": b"", "bin/tools/": b"", "bin/tools/app.txt": b"data"})

        artifact = ZipInspector().inspect(source)

        self.assertEqual([file.relative_path for file in artifact.files], [Path("bin/tools/app.txt")])

    def test_empty_zip_has_no_files(self) -> None:
        """Publish an empty but complete ZIP cache entry."""
        source = self.root / "empty.zip"
        _write_zip(source, {})

        artifact = ZipInspector().inspect(source)

        self.assertEqual(artifact.files, [])
        self.assertEqual(json.loads((self._entry(source) / "manifest.json").read_text())["files"], [])

    def test_corrupted_zip_leaves_no_cache_entry(self) -> None:
        """Report bad ZIP data and remove only the staging directory."""
        source = self.root / "broken.zip"
        source.write_bytes(b"not a ZIP")

        with self.assertRaisesRegex(ValueError, "Unable to inspect ZIP"):
            ZipInspector().inspect(source)

        self.assertFalse(self._entry(source).exists())
        self.assertEqual(list((self.cache_home / "zip" / "v1").iterdir()), [])

    def test_corrupted_member_data_leaves_no_cache_entry(self) -> None:
        """Detect a bad member checksum after opening a valid ZIP container."""
        source = self.root / "damaged.zip"
        _write_zip(source, {"payload.txt": b"unique payload bytes"})
        data = source.read_bytes().replace(b"unique payload bytes", b"broken payload bytes", 1)
        source.write_bytes(data)

        with self.assertRaisesRegex(ValueError, "Unable to inspect ZIP"):
            ZipInspector().inspect(source)

        self.assertFalse(self._entry(source).exists())
        self.assertEqual(list((self.cache_home / "zip" / "v1").iterdir()), [])

    def test_cli_reports_corrupted_zip(self) -> None:
        """Show an extraction error with a nonzero CLI exit code."""
        source = self.root / "broken.zip"
        source.write_bytes(b"not a ZIP")
        error_output = io.StringIO()

        with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
            main(["inspect", str(source)])

        self.assertEqual(result.exception.code, 2)
        self.assertIn("Unable to inspect ZIP", error_output.getvalue())

    def test_unsafe_entry_paths_are_rejected(self) -> None:
        """Reject traversal, absolute, drive, and backslash paths."""
        for index, name in enumerate(("../outside.txt", "/absolute.txt", "C:/drive.txt", "dir\\escape.txt")):
            with self.subTest(name=name):
                source = self.root / f"unsafe-{index}.zip"
                _write_zip(source, {name: b"payload"})

                with self.assertRaisesRegex(ValueError, "Unsafe ZIP entry path"):
                    ZipInspector().inspect(source)

                self.assertFalse(self._entry(source).exists())
                self.assertFalse((self.root / "outside.txt").exists())

    def test_symlink_entry_is_rejected(self) -> None:
        """Never materialize archive symlinks in the extracted tree."""
        source = self.root / "link.zip"
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = 0o120777 << 16
        with zipfile.ZipFile(source, "w") as archive:
            archive.writestr(link, "../../outside")

        with self.assertRaisesRegex(ValueError, "Unsupported ZIP entry type"):
            ZipInspector().inspect(source)

        self.assertFalse(self._entry(source).exists())

    def test_cache_miss_publishes_complete_entry(self) -> None:
        """Write the completion manifest only after extracting all members."""
        source = self.root / "release.zip"
        _write_zip(source, {"nested/app.bin": b"payload"})

        ZipInspector().inspect(source)

        entry = self._entry(source)
        self.assertEqual((entry / "files" / "nested" / "app.bin").read_bytes(), b"payload")
        self.assertEqual(json.loads((entry / "manifest.json").read_text())["version"], 1)
        self.assertEqual([path.name for path in entry.parent.iterdir()], [entry.name])

    def test_cache_hit_skips_extraction(self) -> None:
        """Reuse a complete entry while inspecting its files again."""
        source = self.root / "release.zip"
        _write_zip(source, {"app.bin": b"payload"})

        with patch.object(ZipExtractionCache, "_extract", wraps=ZipExtractionCache()._extract) as extract:
            first = ZipInspector().inspect(source)
            second = ZipInspector().inspect(source)

        self.assertEqual(extract.call_count, 1)
        self.assertEqual(first, second)

    def test_identical_zips_at_different_paths_share_one_entry(self) -> None:
        """Use source content rather than name or location as the cache key."""
        first_path = self.root / "first.zip"
        second_path = self.root / "elsewhere" / "renamed.zip"
        second_path.parent.mkdir()
        _write_zip(first_path, {"app.txt": b"same"})
        second_path.write_bytes(first_path.read_bytes())

        with patch.object(ZipExtractionCache, "_extract", wraps=ZipExtractionCache()._extract) as extract:
            first = ZipInspector().inspect(first_path)
            second = ZipInspector().inspect(second_path)

        self.assertEqual(extract.call_count, 1)
        self.assertEqual(first.files, second.files)
        self.assertEqual(second.source_path, second_path)
        self.assertEqual([path.name for path in self._entry(first_path).parent.iterdir()], [self._entry(first_path).name])

    def test_incomplete_entry_is_rebuilt(self) -> None:
        """Ignore an entry whose manifest names a missing extracted file."""
        source = self.root / "release.zip"
        _write_zip(source, {"app.txt": b"fresh"})
        entry = self._entry(source)
        (entry / "files").mkdir(parents=True)
        (entry / "manifest.json").write_text(json.dumps({
            "version": 1,
            "files": [{"relative_path": "app.txt", "size_bytes": 5}],
        }))

        with patch.object(ZipExtractionCache, "_extract", wraps=ZipExtractionCache()._extract) as extract:
            artifact = ZipInspector().inspect(source)

        self.assertEqual(extract.call_count, 1)
        self.assertEqual(artifact.files[0].sha256, hashlib.sha256(b"fresh").hexdigest())
        self.assertEqual((entry / "files" / "app.txt").read_bytes(), b"fresh")

    def test_failed_extraction_preserves_ready_entry(self) -> None:
        """Remove failed staging data without deleting another ready entry."""
        ready = self.root / "ready.zip"
        broken = self.root / "broken.zip"
        _write_zip(ready, {"app.txt": b"ready"})
        ready_entry = self._entry(ready)
        ZipInspector().inspect(ready)
        _write_zip(broken, {"partial.txt": b"partial", "../outside.txt": b"unsafe"})

        with self.assertRaisesRegex(ValueError, "Unsafe ZIP entry path"):
            ZipInspector().inspect(broken)

        self.assertEqual((ready_entry / "files" / "app.txt").read_bytes(), b"ready")
        self.assertEqual([path.name for path in ready_entry.parent.iterdir()], [ready_entry.name])

    def test_cli_inspect_and_lint_use_generic_analysis(self) -> None:
        """Route ZIP to existing inspect output and build artifact rule."""
        source = self.root / "release.ZIP"
        _write_zip(source, {"nested/build.obj": b"object"})
        inspect_output = io.StringIO()
        lint_output = io.StringIO()

        with contextlib.redirect_stdout(inspect_output):
            self.assertEqual(main(["inspect", str(source)]), 0)
        with contextlib.redirect_stdout(lint_output):
            self.assertEqual(main(["lint", str(source)]), 0)

        self.assertIn(f"Source: {source}\nFiles: 1", inspect_output.getvalue())
        self.assertIn("nested/build.obj | 6 |", inspect_output.getvalue())
        self.assertIn("build-artifact-extension | warning | nested/build.obj", lint_output.getvalue())

    def test_cli_compare_zips_classifies_changes(self) -> None:
        """Use generic comparison for added, removed, and changed ZIP files."""
        old = self.root / "old.zip"
        new = self.root / "new.zip"
        _write_zip(old, {"removed.txt": b"old", "changed.txt": b"old", "same.txt": b"same"})
        _write_zip(new, {"added.txt": b"new", "changed.txt": b"new", "same.txt": b"same"})
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            self.assertEqual(main(["compare", str(old), str(new)]), 0)

        self.assertIn("Added: 1\nRemoved: 1\nChanged: 1\nUnchanged: 1", output.getvalue())
        self.assertIn("Added files:\n  added.txt", output.getvalue())
        self.assertIn("Removed files:\n  removed.txt", output.getvalue())
        self.assertIn("Changed files:\n  changed.txt", output.getvalue())

    def test_binary_analysis_runs_for_zip_members(self) -> None:
        """Inspect an actual PE payload using the existing binary backend."""
        source = self.root / "binary.zip"
        _write_zip(source, {"bin/app.exe": _pe_payload()})

        artifact = ZipInspector().inspect(source)

        self.assertEqual(artifact.files[0].relative_path, Path("bin/app.exe"))
        self.assertIsNotNone(artifact.files[0].binary)
        self.assertEqual(artifact.files[0].binary.format, "PE")
        self.assertEqual(artifact.files[0].binary.kind, "executable")


if __name__ == "__main__":
    unittest.main()
