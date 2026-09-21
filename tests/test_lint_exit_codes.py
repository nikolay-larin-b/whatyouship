# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for lint release-gate exit codes."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.cli import main
from whatyouship.model import ArtifactFile, BinaryMetadata, ReleaseArtifact, SignatureMetadata


class LintExitCodeTests(unittest.TestCase):
    """Verify severity thresholds and baseline eligibility."""

    def test_warning_findings_follow_selected_threshold(self) -> None:
        """Default error threshold passes warnings; warning threshold fails."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact = Path(temporary_directory) / "release"
            artifact.mkdir()
            (artifact / "build.obj").write_bytes(b"object")
            for options, expected in (
                ([], 0),
                (["--fail-on", "error"], 0),
                (["--fail-on", "warning"], 1),
                (["--fail-on", "never"], 0),
            ):
                with self.subTest(options=options), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(["lint", str(artifact), *options]), expected)

    def test_error_findings_follow_selected_threshold(self) -> None:
        """Fail error and warning gates while allowing the never gate."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = root / "release"
            artifact.mkdir()
            (artifact / "build.obj").write_bytes(b"object")
            config = root / "rules.toml"
            config.write_text("[rules.build-artifact-extension]\nseverity = 'error'\n")
            for options, expected in (
                ([], 1),
                (["--fail-on", "error"], 1),
                (["--fail-on", "warning"], 1),
                (["--fail-on", "never"], 0),
            ):
                with self.subTest(options=options), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        main(["lint", str(artifact), "--config", str(config), *options]),
                        expected,
                    )

    def test_no_findings_pass_every_threshold(self) -> None:
        """Return success when the artifact has no lint findings."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            artifact = Path(temporary_directory) / "release"
            artifact.mkdir()
            for threshold in ("error", "warning", "never"):
                with self.subTest(threshold=threshold), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(
                        main(["lint", str(artifact), "--fail-on", threshold]), 0
                    )

    def test_baseline_existing_and_resolved_errors_do_not_fail(self) -> None:
        """Apply the gate only to findings newly present in the current release."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            previous = root / "previous"
            current = root / "current"
            previous.mkdir()
            current.mkdir()
            (previous / "existing.obj").write_bytes(b"old")
            (previous / "resolved.ilk").write_bytes(b"old")
            (current / "existing.obj").write_bytes(b"new")
            config = root / "rules.toml"
            config.write_text("[rules.build-artifact-extension]\nseverity = 'error'\n")
            for threshold in ("error", "warning"):
                output = io.StringIO()
                with self.subTest(threshold=threshold), contextlib.redirect_stdout(output):
                    result = main([
                        "lint", str(current), "--baseline", str(previous),
                        "--config", str(config), "--fail-on", threshold,
                    ])
                self.assertEqual(result, 0)
                self.assertIn("New: 0\nExisting: 1\nResolved: 1", output.getvalue())

    def test_baseline_new_warning_does_not_inherit_existing_error(self) -> None:
        """Ignore an existing error when only a new warning is eligible."""
        previous = ReleaseArtifact(
            Path("previous"), [ArtifactFile(Path("existing.obj"), 1, "a" * 64)]
        )
        current = ReleaseArtifact(Path("current"), [
            ArtifactFile(Path("existing.obj"), 1, "a" * 64),
            ArtifactFile(
                Path("app.bin"), 1, "b" * 64,
                binary=BinaryMetadata(
                    "PE", "x86_64", "executable",
                    signature=SignatureMetadata(False),
                ),
            ),
        ])
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "rules.toml"
            config.write_text("[rules.build-artifact-extension]\nseverity = 'error'\n")
            for threshold, expected in (("error", 0), ("warning", 1)):
                with (
                    self.subTest(threshold=threshold),
                    patch("whatyouship.cli.inspect_artifact", side_effect=[current, previous]),
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    self.assertEqual(main([
                        "lint", "current", "--baseline", "previous",
                        "--config", str(config), "--fail-on", threshold,
                    ]), expected)

    def test_baseline_new_error_fails_default_gate(self) -> None:
        """Fail the default gate when a new finding has error severity."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            previous = root / "previous"
            current = root / "current"
            previous.mkdir()
            current.mkdir()
            (current / "new.obj").write_bytes(b"new")
            config = root / "rules.toml"
            config.write_text("[rules.build-artifact-extension]\nseverity = 'error'\n")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main([
                    "lint", str(current), "--baseline", str(previous),
                    "--config", str(config),
                ])

            self.assertEqual(result, 1)
            self.assertIn("New: 1", output.getvalue())

    def test_threshold_does_not_change_text_json_or_csv_output(self) -> None:
        """Write identical reports regardless of the chosen release gate."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = root / "release"
            artifact.mkdir()
            (artifact / "build.obj").write_bytes(b"object")
            for suffix in (".txt", ".json", ".csv"):
                with self.subTest(suffix=suffix):
                    first = root / f"first{suffix}"
                    second = root / f"second{suffix}"
                    self.assertEqual(main([
                        "lint", str(artifact), "--fail-on", "warning", "-o", str(first),
                    ]), 1)
                    self.assertEqual(main([
                        "lint", str(artifact), "--fail-on", "never", "-o", str(second),
                    ]), 0)
                    self.assertEqual(first.read_bytes(), second.read_bytes())
                    if suffix == ".json":
                        self.assertEqual(json.loads(first.read_text())["report_type"], "lint")

    def test_lint_errors_still_exit_two(self) -> None:
        """Keep invalid configuration and bad threshold as CLI errors."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = root / "release"
            artifact.mkdir()
            cases = (
                (["lint", str(artifact), "--config", str(root / "missing.toml")],
                 "Configuration file does not exist"),
                (["lint", str(artifact), "--fail-on", "critical"],
                 "invalid choice"),
            )
            for arguments, message in cases:
                error_output = io.StringIO()
                with (
                    self.subTest(arguments=arguments),
                    contextlib.redirect_stderr(error_output),
                    self.assertRaises(SystemExit) as result,
                ):
                    main(arguments)
                self.assertEqual(result.exception.code, 2)
                self.assertIn(message, error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
