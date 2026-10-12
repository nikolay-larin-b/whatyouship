# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for the high-level artifact operation API."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import whatyouship
from whatyouship.cli import main
from whatyouship.config import BuildArtifactSettings, LintConfiguration
from whatyouship.model import ReleaseArtifact
from whatyouship.operations import compare, inspect, lint
from whatyouship.paths import cache_directory, cache_root_directory, cache_scope
from whatyouship.renderers import render_report
from whatyouship.report import CompareReport, InspectReport, LintReport


class OperationTests(unittest.TestCase):
    """Verify public operation orchestration independently from the CLI."""

    def test_inspect_accepts_string_and_returns_report(self) -> None:
        """Inspect a string path and return structured artifact data."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory)
            (source / "payload.txt").write_bytes(b"payload")

            report = inspect(str(source))

        self.assertIsInstance(report, InspectReport)
        self.assertEqual(report.artifact.source_path, source)
        self.assertEqual(
            [file.relative_path for file in report.artifact.files],
            [Path("payload.txt")],
        )

    def test_lint_accepts_path_like_and_returns_report(self) -> None:
        """Apply default lint rules through the public operation."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory)
            (source / "debug.obj").write_bytes(b"object")

            report = lint(source)

        self.assertIsInstance(report, LintReport)
        self.assertEqual(
            [finding.rule_id for finding in report.findings],
            ["build-artifact-extension"],
        )

    def test_compare_accepts_mixed_path_inputs_and_returns_report(self) -> None:
        """Compare string and path-like inputs through one operation scope."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            old = root / "old"
            new = root / "new"
            old.mkdir()
            new.mkdir()
            (old / "removed.txt").write_bytes(b"old")
            (new / "added.txt").write_bytes(b"new")

            report = compare(str(old), new)

        self.assertIsInstance(report, CompareReport)
        self.assertEqual(report.comparison.added, [Path("added.txt")])
        self.assertEqual(report.comparison.removed, [Path("removed.txt")])

    def test_lint_loads_configuration_and_classifies_baseline_findings(self) -> None:
        """Use one TOML rule set for current and baseline findings."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            baseline = root / "baseline"
            current = root / "current"
            baseline.mkdir()
            current.mkdir()
            (baseline / "existing.tmp").write_bytes(b"old")
            (current / "existing.tmp").write_bytes(b"new")
            (current / "new.tmp").write_bytes(b"new")
            config = root / "whatyouship.toml"
            config.write_text(
                "[rules.build-artifact-extension]\n"
                "severity = \"error\"\n"
                "extensions = [\".tmp\"]\n",
                encoding="utf-8",
            )

            report = lint(current, baseline=str(baseline), config=config)

        self.assertIsNotNone(report.baseline_comparison)
        assert report.baseline_comparison is not None
        self.assertEqual(
            [finding.relative_path for finding in report.baseline_comparison.existing],
            [Path("existing.tmp")],
        )
        self.assertEqual(
            [finding.relative_path for finding in report.baseline_comparison.new],
            [Path("new.tmp")],
        )
        self.assertEqual(report.baseline_comparison.resolved, [])
        self.assertTrue(
            all(finding.severity == "error" for finding in report.findings)
        )

    def test_lint_accepts_prepared_configuration(self) -> None:
        """Accept typed settings without requiring a TOML file."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory)
            (source / "debug.obj").write_bytes(b"object")
            configuration = LintConfiguration(
                build_artifacts=BuildArtifactSettings(enabled=False)
            )

            report = lint(source, config=configuration)

        self.assertEqual(report.findings, [])

    def test_cli_and_python_api_render_equivalent_results(self) -> None:
        """Route every CLI artifact command through the public operations."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            old = root / "old"
            new = root / "new"
            old.mkdir()
            new.mkdir()
            (old / "debug.obj").write_bytes(b"old")
            (new / "debug.obj").write_bytes(b"new")
            commands = (
                (["inspect", str(new)], inspect(new)),
                (["lint", str(new)], lint(new)),
                (["compare", str(old), str(new)], compare(old, new)),
            )

            for arguments, report in commands:
                with self.subTest(command=arguments[0]):
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        exit_code = main(arguments)
                    self.assertEqual(exit_code, 0)
                    self.assertEqual(output.getvalue(), render_report(report, "text"))

    def test_temporary_cache_is_removed_after_operation(self) -> None:
        """Avoid persistent cache writes when the caller does not opt in."""
        selected_roots: list[Path] = []

        def inspect_with_cache(source: Path) -> ReleaseArtifact:
            """Record and populate the selected extraction cache.

            :param source: Artifact path received from the operation.
            :returns: Empty artifact for the supplied path.
            """
            selected_root = cache_root_directory()
            selected_roots.append(selected_root)
            cache_directory("zip").mkdir(parents=True)
            return ReleaseArtifact(source)

        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory) / "home"
            with (
                patch("whatyouship.paths.Path.home", return_value=home),
                patch(
                    "whatyouship.operations.inspect_artifact",
                    side_effect=inspect_with_cache,
                ),
            ):
                report = inspect("release.zip")

            self.assertEqual(report.artifact.source_path, Path("release.zip"))
            self.assertEqual(len(selected_roots), 1)
            self.assertFalse(selected_roots[0].exists())
            self.assertFalse((home / ".whatyouship" / "cache").exists())

    def test_persistent_cache_requires_explicit_operation_option(self) -> None:
        """Preserve and reuse the user cache only for ``cache=True``."""
        selected_roots: list[Path] = []

        def inspect_with_cache(source: Path) -> ReleaseArtifact:
            """Record and populate the selected persistent cache.

            :param source: Artifact path received from the operation.
            :returns: Empty artifact for the supplied path.
            """
            selected_root = cache_root_directory()
            selected_roots.append(selected_root)
            cache_directory("zip").mkdir(parents=True, exist_ok=True)
            return ReleaseArtifact(source)

        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory) / "home"
            with (
                patch("whatyouship.paths.Path.home", return_value=home),
                patch(
                    "whatyouship.operations.inspect_artifact",
                    side_effect=inspect_with_cache,
                ),
            ):
                compare("old.zip", "new.zip", cache=True)

            persistent_root = home / ".whatyouship" / "cache"
            self.assertEqual(selected_roots, [persistent_root, persistent_root])
            self.assertTrue((persistent_root / "zip" / "v1").is_dir())

    def test_operation_reuses_explicit_outer_cache_scope(self) -> None:
        """Keep a caller-owned cache scope active across API operations."""
        selected_roots: list[Path] = []

        def inspect_with_cache(source: Path) -> ReleaseArtifact:
            """Record the cache root selected by the outer scope.

            :param source: Artifact path received from the operation.
            :returns: Empty artifact for the supplied path.
            """
            selected_roots.append(cache_root_directory())
            return ReleaseArtifact(source)

        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory) / "home"
            with (
                patch("whatyouship.paths.Path.home", return_value=home),
                cache_scope(persistent=True),
                patch(
                    "whatyouship.operations.inspect_artifact",
                    side_effect=inspect_with_cache,
                ),
            ):
                expected_root = cache_root_directory()
                inspect("release.zip")
                inspect("release.zip")

            self.assertEqual(selected_roots, [expected_root, expected_root])
            self.assertEqual(expected_root, home / ".whatyouship" / "cache")

    def test_input_errors_remain_programmatic_exceptions(self) -> None:
        """Preserve useful exception types instead of applying CLI handling."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            unsupported = root / "release.bin"
            unsupported.write_bytes(b"payload")

            with self.assertRaisesRegex(FileNotFoundError, "does not exist"):
                inspect(root / "missing.zip")
            with self.assertRaisesRegex(ValueError, "Unsupported artifact type"):
                lint(unsupported)
            with self.assertRaisesRegex(ValueError, "Unsupported artifact type"):
                compare(root, unsupported)

    def test_operations_are_not_exported_from_package_root(self) -> None:
        """Keep operation names canonical in ``whatyouship.operations``."""
        self.assertFalse(hasattr(whatyouship, "inspect"))
        self.assertFalse(callable(getattr(whatyouship, "lint", None)))
        self.assertFalse(callable(getattr(whatyouship, "compare", None)))


if __name__ == "__main__":
    unittest.main()
