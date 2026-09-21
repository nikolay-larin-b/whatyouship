# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for the WhatYouShip command-line interface."""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship import __version__
from whatyouship.cli import main
from whatyouship.model import ArtifactFile, ArtifactSignature, BinaryMetadata, InstallationScope, ReleaseArtifact, SignatureMetadata


class CliTests(unittest.TestCase):
    """Verify the supported command-line options."""

    def test_help(self) -> None:
        """Verify that ``--help`` prints usage information and exits."""
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as result:
            main(["--help"])

        self.assertEqual(result.exception.code, 0)
        self.assertIn("usage: whatyouship", output.getvalue())
        self.assertIn("--version", output.getvalue())
        self.assertIn("lint", output.getvalue())
        self.assertIn("compare", output.getvalue())

    def test_version(self) -> None:
        """Verify that ``--version`` prints the package version and exits."""
        output = io.StringIO()
        with contextlib.redirect_stdout(output), self.assertRaises(SystemExit) as result:
            main(["--version"])

        self.assertEqual(result.exception.code, 0)
        self.assertEqual(output.getvalue(), f"whatyouship {__version__}\n")

    def test_inspect_prints_summary_and_sorted_files(self) -> None:
        """Print source, counts, sizes, and digests in path order."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "z.txt").write_bytes(b"abc")
            (root / "a.txt").write_bytes(b"")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["inspect", str(root)])

            self.assertEqual(result, 0)
            lines = output.getvalue().splitlines()
            self.assertEqual(lines[:3], [f"Source: {root}", "Files: 2", "Total size: 3 bytes"])
            self.assertEqual(lines[3:6], ["Artifact signature:", "  Status: unsupported", ""])
            self.assertEqual(lines[6], "Relative path | Size (bytes) | SHA-256")
            self.assertEqual(
                lines[7:],
                [
                    "a.txt | 0 | e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "z.txt | 3 | ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                ],
            )

    def test_inspect_rejects_missing_artifact(self) -> None:
        """Report a missing artifact through argparse with exit code two."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            missing = Path(temporary_directory) / "missing"
            error_output = io.StringIO()

            with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                main(["inspect", str(missing)])

            self.assertEqual(result.exception.code, 2)
            self.assertIn("Artifact does not exist", error_output.getvalue())

    def test_inspect_rejects_unsupported_file(self) -> None:
        """Report an unsupported file type through argparse."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            file = Path(temporary_directory) / "file.txt"
            file.write_bytes(b"data")
            error_output = io.StringIO()

            with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                main(["inspect", str(file)])

            self.assertEqual(result.exception.code, 2)
            self.assertIn("Unsupported artifact type", error_output.getvalue())

    def test_lint_prints_build_artifact_findings(self) -> None:
        """Print rule ID, severity, path, and description for each finding."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "z.obj").write_bytes(b"object")
            (root / "a.ILK").write_bytes(b"linker")
            (root / "symbols.pdb").write_bytes(b"symbols")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["lint", str(root)])

            self.assertEqual(result, 0)
            self.assertEqual(
                output.getvalue().splitlines(),
                [
                    "build-artifact-extension | warning | a.ILK | Suspicious build artifact extension: .ilk.",
                    "build-artifact-extension | warning | z.obj | Suspicious build artifact extension: .obj.",
                ],
            )

    def test_lint_reports_no_findings(self) -> None:
        """Report a clean artifact without listing files."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            (root / "library.lib").write_bytes(b"library")
            (root / "symbols.pdb").write_bytes(b"symbols")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["lint", str(root)])

            self.assertEqual(result, 0)
            self.assertEqual(output.getvalue(), "No findings.\n")

    def test_lint_rejects_missing_artifact(self) -> None:
        """Report a missing lint input with a nonzero exit code."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            missing = Path(temporary_directory) / "missing"
            error_output = io.StringIO()

            with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                main(["lint", str(missing)])

            self.assertEqual(result.exception.code, 2)
            self.assertIn("Artifact does not exist", error_output.getvalue())

    def test_lint_rejects_unsupported_file(self) -> None:
        """Report an unsupported artifact type for linting."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "release.tar"
            source.write_bytes(b"data")
            error_output = io.StringIO()

            with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                main(["lint", str(source)])

            self.assertEqual(result.exception.code, 2)
            self.assertIn("Unsupported artifact type", error_output.getvalue())

    def test_inspect_rejects_invalid_msi(self) -> None:
        """Report an invalid MSI without a traceback."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "invalid.msi"
            source.write_bytes(b"not an MSI")
            error_output = io.StringIO()

            with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                main(["inspect", str(source)])

            self.assertEqual(result.exception.code, 2)
            self.assertIn("Unable to inspect MSI", error_output.getvalue())

    def test_inspect_uses_msi_inspector(self) -> None:
        """Route MSI files to the MSI inspector for inspect output."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "release.MSI"
            source.write_bytes(b"synthetic MSI data")
            artifact = ReleaseArtifact(
                source_path=source,
                files=[ArtifactFile(Path("App/readme.txt"), 3, "a" * 64)],
            )
            output = io.StringIO()

            with (
                patch("whatyouship.inspectors.MsiInspector") as inspector,
                contextlib.redirect_stdout(output),
            ):
                inspector.return_value.inspect.return_value = artifact
                result = main(["inspect", str(source)])

            self.assertEqual(result, 0)
            inspector.return_value.inspect.assert_called_once_with(source)
            self.assertIn("App/readme.txt | 3 |", output.getvalue())

    def test_lint_uses_msi_inspector(self) -> None:
        """Apply the existing lint rule to files from an MSI artifact."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "release.msi"
            source.write_bytes(b"synthetic MSI data")
            artifact = ReleaseArtifact(
                source_path=source,
                files=[ArtifactFile(Path("App/build.obj"), 3, "a" * 64)],
            )
            output = io.StringIO()

            with (
                patch("whatyouship.inspectors.MsiInspector") as inspector,
                contextlib.redirect_stdout(output),
            ):
                inspector.return_value.inspect.return_value = artifact
                result = main(["lint", str(source)])

            self.assertEqual(result, 0)
            inspector.return_value.inspect.assert_called_once_with(source)
            self.assertIn("build-artifact-extension | warning | App/build.obj", output.getvalue())

    def test_inspect_prints_binary_metadata(self) -> None:
        """Show identified binary metadata below its file entry."""
        source = Path("release")
        artifact = ReleaseArtifact(
            source_path=source,
            files=[
                ArtifactFile(
                    relative_path=Path("app.exe"),
                    size_bytes=3,
                    sha256="a" * 64,
                    binary=BinaryMetadata(
                        format="PE",
                        architecture="x86_64",
                        kind="executable",
                        file_version="1.2.3.4",
                        product_version="5.6.7.8",
                    ),
                )
            ],
        )
        output = io.StringIO()

        with patch("whatyouship.cli.inspect_artifact", return_value=artifact), contextlib.redirect_stdout(output):
            result = main(["inspect", str(source)])

        self.assertEqual(result, 0)
        self.assertIn(
            "  Binary: executable | Architecture: x86_64 | "
            "File version: 1.2.3.4 | Product version: 5.6.7.8\n",
            output.getvalue(),
        )
        self.assertNotIn("PE", output.getvalue())

    def test_inspect_prints_signature_metadata(self) -> None:
        """Show signature validity, signer subject, and timestamp."""
        artifact = ReleaseArtifact(
            Path("release"),
            [ArtifactFile(Path("app.exe"), 1, "a" * 64, binary=BinaryMetadata(
                "PE", "x86_64", "executable",
                signature=SignatureMetadata(True, True, "CN=Example Publisher", True),
            ))],
        )
        output = io.StringIO()

        with patch("whatyouship.cli.inspect_artifact", return_value=artifact), contextlib.redirect_stdout(output):
            result = main(["inspect", "release"])

        self.assertEqual(result, 0)
        self.assertIn("Signature: valid | Signer: CN=Example Publisher | Timestamp: present", output.getvalue())

    def test_inspect_prints_artifact_signature_separately(self) -> None:
        """Show the package signature before signatures of contained files."""
        from datetime import datetime, timezone

        artifact = ReleaseArtifact(
            Path("release.msi"),
            [ArtifactFile(Path("app.exe"), 1, "a" * 64, binary=BinaryMetadata(
                "PE", "x86_64", "executable", signature=SignatureMetadata(False),
            ))],
            ArtifactSignature(
                "valid", "CN=Example Publisher", datetime(2026, 1, 2, tzinfo=timezone.utc)
            ),
        )
        output = io.StringIO()

        with patch("whatyouship.cli.inspect_artifact", return_value=artifact), contextlib.redirect_stdout(output):
            result = main(["inspect", "release.msi"])

        self.assertEqual(result, 0)
        self.assertIn(
            "Artifact signature:\n  Status: valid\n  Signer: CN=Example Publisher\n"
            "  Timestamp: 2026-01-02T00:00:00+00:00",
            output.getvalue(),
        )
        self.assertIn("  Signature: absent", output.getvalue())

    def test_inspect_prints_installation_scope(self) -> None:
        """Show statically inferred MSI scope in the artifact summary."""
        artifact = ReleaseArtifact(
            Path("release.msi"), installation_scope=InstallationScope("dual-purpose")
        )
        output = io.StringIO()

        with (
            patch("whatyouship.cli.inspect_artifact", return_value=artifact),
            contextlib.redirect_stdout(output),
        ):
            result = main(["inspect", "release.msi"])

        self.assertEqual(result, 0)
        self.assertIn("Installation scope: dual-purpose\n", output.getvalue())

    def test_lint_reports_artifact_signature_findings(self) -> None:
        """Print package signature findings independently of binary findings."""
        output = io.StringIO()
        for status, expected in (
            ("unsigned", "unsigned-artifact | warning | . | Unsigned release artifact."),
            ("invalid", "invalid-artifact-signature | error | . | Invalid release artifact signature."),
        ):
            with self.subTest(status=status):
                artifact = ReleaseArtifact(
                    Path("release.msi"), signature=ArtifactSignature(status)
                )
                output.seek(0)
                output.truncate(0)
                with (
                    patch("whatyouship.cli.inspect_artifact", return_value=artifact),
                    contextlib.redirect_stdout(output),
                ):
                    result = main(["lint", "release.msi"])

                self.assertEqual(result, 0)
                self.assertEqual(output.getvalue().strip(), expected)

    def test_lint_reports_installation_scope_conflict(self) -> None:
        """Render a concrete scope contradiction through the CLI."""
        artifact = ReleaseArtifact(
            Path("release.msi"),
            installation_scope=InstallationScope(
                "ambiguous", ("Component 'App' uses fixed per-machine HKLM registry entry.",)
            ),
        )
        output = io.StringIO()

        with (
            patch("whatyouship.cli.inspect_artifact", return_value=artifact),
            contextlib.redirect_stdout(output),
        ):
            result = main(["lint", "release.msi"])

        self.assertEqual(result, 0)
        self.assertEqual(
            output.getvalue().strip(),
            "inconsistent-installation-scope | warning | . | "
            "Component 'App' uses fixed per-machine HKLM registry entry.",
        )

    def test_lint_reports_unsigned_binary(self) -> None:
        """Run the unsigned binary rule through the CLI."""
        artifact = ReleaseArtifact(
            Path("release"),
            [ArtifactFile(Path("app.dat"), 1, "a" * 64, binary=BinaryMetadata(
                "PE", "x86_64", "executable", signature=SignatureMetadata(False),
            ))],
        )
        output = io.StringIO()

        with patch("whatyouship.cli.inspect_artifact", return_value=artifact), contextlib.redirect_stdout(output):
            result = main(["lint", "release"])

        self.assertEqual(result, 0)
        self.assertEqual(output.getvalue(), "unsigned-binary | warning | app.dat | Unsigned executable.\n")

    def test_lint_baseline_reports_new_existing_and_resolved(self) -> None:
        """Show new and resolved findings without listing existing ones."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            baseline = root / "previous"
            current = root / "current"
            baseline.mkdir()
            current.mkdir()
            for name in ("existing.obj", "resolved.ilk"):
                (baseline / name).write_bytes(b"data")
            for name in ("existing.obj", "new.tlog"):
                (current / name).write_bytes(b"data")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["lint", str(current), "--baseline", str(baseline)])

            self.assertEqual(result, 0)
            self.assertEqual(output.getvalue().splitlines(), [
                "New: 1",
                "Existing: 1",
                "Resolved: 1",
                "",
                "New findings:",
                "build-artifact-extension | warning | new.tlog | Suspicious build artifact extension: .tlog.",
                "",
                "Resolved findings:",
                "build-artifact-extension | warning | resolved.ilk | Suspicious build artifact extension: .ilk.",
            ])

    def test_lint_baseline_reports_no_new_findings(self) -> None:
        """Summarize existing findings without listing them."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            baseline = root / "previous"
            current = root / "current"
            baseline.mkdir()
            current.mkdir()
            (baseline / "existing.obj").write_bytes(b"old")
            (current / "existing.obj").write_bytes(b"new")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["lint", str(current), "--baseline", str(baseline)])

            self.assertEqual(result, 0)
            self.assertEqual(
                output.getvalue(),
                "New: 0\nExisting: 1\nResolved: 0\nNo new findings.\n",
            )

    def test_lint_baseline_reports_resolved_without_new_findings(self) -> None:
        """Keep the no-new message while listing resolved findings."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            baseline = root / "previous"
            current = root / "current"
            baseline.mkdir()
            current.mkdir()
            (baseline / "resolved.obj").write_bytes(b"old")
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["lint", str(current), "--baseline", str(baseline)])

            self.assertEqual(result, 0)
            self.assertEqual(output.getvalue().splitlines(), [
                "New: 0",
                "Existing: 0",
                "Resolved: 1",
                "No new findings.",
                "",
                "Resolved findings:",
                "build-artifact-extension | warning | resolved.obj | Suspicious build artifact extension: .obj.",
            ])

    def test_lint_baseline_rejects_missing_artifact(self) -> None:
        """Report an invalid baseline with a nonzero exit code."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            current = Path(temporary_directory) / "current"
            current.mkdir()
            missing = Path(temporary_directory) / "missing"
            error_output = io.StringIO()

            with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                main(["lint", str(current), "--baseline", str(missing)])

            self.assertEqual(result.exception.code, 2)
            self.assertIn("Artifact does not exist", error_output.getvalue())

    def test_lint_baseline_uses_msi_inspector(self) -> None:
        """Inspect MSI baselines through the existing artifact routing."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            baseline = root / "previous.msi"
            baseline.write_bytes(b"synthetic MSI data")
            current = root / "current"
            current.mkdir()
            (current / "new.obj").write_bytes(b"data")
            previous_artifact = ReleaseArtifact(
                baseline, [ArtifactFile(Path("resolved.ilk"), 4, "a" * 64)]
            )
            output = io.StringIO()

            with (
                patch("whatyouship.inspectors.MsiInspector") as inspector,
                contextlib.redirect_stdout(output),
            ):
                inspector.return_value.inspect.return_value = previous_artifact
                result = main(["lint", str(current), "--baseline", str(baseline)])

            self.assertEqual(result, 0)
            inspector.return_value.inspect.assert_called_once_with(baseline)
            self.assertIn("New: 1\nExisting: 0\nResolved: 1", output.getvalue())

    def test_lint_config_changes_extensions_and_severity(self) -> None:
        """Apply configured extensions and severity to lint output."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = root / "release"
            artifact.mkdir()
            (artifact / "library.lib").write_bytes(b"library")
            (artifact / "build.obj").write_bytes(b"object")
            config = root / "rules.toml"
            config.write_text(
                "[rules.build-artifact-extension]\n"
                "severity = 'error'\n"
                "extensions = ['.lib']\n"
            )
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["lint", str(artifact), "--config", str(config)])

            self.assertEqual(result, 0)
            self.assertEqual(
                output.getvalue(),
                "build-artifact-extension | error | library.lib | "
                "Suspicious build artifact extension: .lib.\n",
            )

    def test_lint_config_disables_rules(self) -> None:
        """Suppress findings from rules disabled in the configuration."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = root / "release"
            artifact.mkdir()
            (artifact / "build.obj").write_bytes(b"object")
            config = root / "rules.toml"
            config.write_text(
                "[rules.build-artifact-extension]\nenabled = false\n"
                "[rules.unsigned-binary]\nenabled = false\n"
            )
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["lint", str(artifact), "--config", str(config)])

            self.assertEqual(result, 0)
            self.assertEqual(output.getvalue(), "No findings.\n")

    def test_lint_config_sets_unsigned_binary_severity(self) -> None:
        """Apply the configured severity to unsigned binary findings."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            config = Path(temporary_directory) / "rules.toml"
            config.write_text("[rules.unsigned-binary]\nseverity = 'error'\n")
            artifact = ReleaseArtifact(
                Path("release"),
                [ArtifactFile(Path("app.exe"), 1, "a", binary=BinaryMetadata(
                    "PE", "x86_64", "executable", signature=SignatureMetadata(False),
                ))],
            )
            output = io.StringIO()

            with (
                patch("whatyouship.cli.inspect_artifact", return_value=artifact),
                contextlib.redirect_stdout(output),
            ):
                result = main(["lint", "release", "--config", str(config)])

            self.assertEqual(result, 0)
            self.assertEqual(
                output.getvalue(),
                "unsigned-binary | error | app.exe | Unsigned executable.\n",
            )

    def test_lint_config_applies_to_baseline_and_current(self) -> None:
        """Use one configured rule set for both baseline lint passes."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            baseline = root / "previous"
            current = root / "current"
            baseline.mkdir()
            current.mkdir()
            (baseline / "library.lib").write_bytes(b"old")
            (current / "library.lib").write_bytes(b"new")
            (current / "module.exp").write_bytes(b"new")
            config = root / "rules.toml"
            config.write_text(
                "[rules.build-artifact-extension]\n"
                "severity = 'error'\n"
                "extensions = ['.lib', '.exp']\n"
            )
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main([
                    "lint", str(current), "--baseline", str(baseline), "--config", str(config)
                ])

            self.assertEqual(result, 0)
            self.assertEqual(output.getvalue().splitlines(), [
                "New: 1",
                "Existing: 1",
                "Resolved: 0",
                "",
                "New findings:",
                "build-artifact-extension | error | module.exp | Suspicious build artifact extension: .exp.",
            ])

    def test_lint_config_errors_exit_nonzero(self) -> None:
        """Report missing, malformed, and unsupported configuration files."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = root / "release"
            artifact.mkdir()
            config = root / "rules.toml"
            cases = (
                (None, "Configuration file does not exist"),
                ("[rules.build-artifact-extension\n", "Invalid TOML"),
                ("[rules.unknown]\nenabled = true\n", "Unknown rule ID"),
                ("[rules.unsigned-binary]\nseverity = 'critical'\n", "Invalid severity"),
            )
            for content, message in cases:
                with self.subTest(message=message):
                    if content is not None:
                        config.write_text(content)
                    error_output = io.StringIO()
                    with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                        main(["lint", str(artifact), "--config", str(config)])
                    self.assertEqual(result.exception.code, 2)
                    self.assertIn(message, error_output.getvalue())

    def test_compare_directories_prints_summary_and_changed_paths(self) -> None:
        """Compare directories and omit unchanged paths from detail lists."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            old = root / "old"
            new = root / "new"
            old.mkdir()
            new.mkdir()
            for directory, names in (
                (old, {"removed.txt": b"old", "changed.txt": b"old", "same.txt": b"same"}),
                (new, {"added.txt": b"new", "changed.txt": b"new", "same.txt": b"same"}),
            ):
                for name, content in names.items():
                    (directory / name).write_bytes(content)
            output = io.StringIO()

            with contextlib.redirect_stdout(output):
                result = main(["compare", str(old), str(new)])

            self.assertEqual(result, 0)
            self.assertEqual(output.getvalue().splitlines(), [
                f"Old: {old}",
                f"New: {new}",
                "Added: 1",
                "Removed: 1",
                "Changed: 1",
                "Unchanged: 1",
                "Semantic differences: 0",
                "",
                "Added files:",
                "  added.txt",
                "",
                "Removed files:",
                "  removed.txt",
                "",
                "Changed files:",
                "  changed.txt",
            ])

    def test_compare_prints_installation_scope_change(self) -> None:
        """Show artifact-level scope transitions without a file path prefix."""
        old = ReleaseArtifact(
            Path("old.msi"), installation_scope=InstallationScope("per-user")
        )
        new = ReleaseArtifact(
            Path("new.msi"), installation_scope=InstallationScope("per-machine")
        )
        output = io.StringIO()

        with (
            patch("whatyouship.cli.inspect_artifact", side_effect=[old, new]),
            contextlib.redirect_stdout(output),
        ):
            result = main(["compare", "old.msi", "new.msi"])

        self.assertEqual(result, 0)
        self.assertIn("  Installation scope: per-user -> per-machine\n", output.getvalue())

    def test_compare_uses_msi_inspector_for_msi_input(self) -> None:
        """Use the existing MSI inspector when either input is an MSI."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            old = root / "old.msi"
            old.write_bytes(b"synthetic MSI data")
            new = root / "new"
            new.mkdir()
            (new / "app.txt").write_bytes(b"new")
            old_artifact = ReleaseArtifact(old, [ArtifactFile(Path("app.txt"), 3, "a" * 64)])
            output = io.StringIO()

            with (
                patch("whatyouship.inspectors.MsiInspector") as inspector,
                contextlib.redirect_stdout(output),
            ):
                inspector.return_value.inspect.return_value = old_artifact
                result = main(["compare", str(old), str(new)])

            self.assertEqual(result, 0)
            inspector.return_value.inspect.assert_called_once_with(old)
            self.assertIn("Changed: 1", output.getvalue())

    def test_compare_rejects_invalid_new_artifact(self) -> None:
        """Report a bad second input through argparse with a nonzero exit code."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            old = Path(temporary_directory) / "old"
            old.mkdir()
            new = Path(temporary_directory) / "missing"
            error_output = io.StringIO()

            with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                main(["compare", str(old), str(new)])

            self.assertEqual(result.exception.code, 2)
            self.assertIn("Artifact does not exist", error_output.getvalue())

    def test_compare_highlights_signed_to_unsigned_regression(self) -> None:
        """Show the signature regression outside the digest change list."""
        path = Path("app.exe")
        old = ReleaseArtifact(Path("old"), [ArtifactFile(
            path, 1, "a", binary=BinaryMetadata(
                "PE", "x86_64", "executable", signature=SignatureMetadata(True, True),
            ),
        )])
        new = ReleaseArtifact(Path("new"), [ArtifactFile(
            path, 1, "b", binary=BinaryMetadata(
                "PE", "x86_64", "executable", signature=SignatureMetadata(False),
            ),
        )])
        output = io.StringIO()

        with patch("whatyouship.cli.inspect_artifact", side_effect=[old, new]), contextlib.redirect_stdout(output):
            result = main(["compare", "old", "new"])

        self.assertEqual(result, 0)
        self.assertIn("Changed files:\n  app.exe", output.getvalue())
        self.assertIn("Semantic differences: 1", output.getvalue())
        self.assertIn(
            "app.exe | Signature: signed (valid) -> unsigned "
            "[POTENTIALLY DANGEROUS: signed -> unsigned]",
            output.getvalue(),
        )

    def test_compare_labels_version_regressions_as_warnings(self) -> None:
        """Show downgrade and missing metadata warnings in compare output."""
        path = Path("app.exe")
        old = ReleaseArtifact(Path("old"), [ArtifactFile(
            path, 1, "a", BinaryMetadata("PE", "x86_64", "executable", "1.2.10", "2.0"),
        )])
        new = ReleaseArtifact(Path("new"), [ArtifactFile(
            path, 1, "b", BinaryMetadata("PE", "x86_64", "executable", "1.2.9", None),
        )])
        output = io.StringIO()

        with patch("whatyouship.cli.inspect_artifact", side_effect=[old, new]), contextlib.redirect_stdout(output):
            result = main(["compare", "old", "new"])

        self.assertEqual(result, 0)
        self.assertIn(
            "app.exe | File version: 1.2.10 -> 1.2.9 [WARNING: version downgrade]",
            output.getvalue(),
        )
        self.assertIn(
            "app.exe | Product version: 2.0 -> unavailable [WARNING: version metadata removed]",
            output.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
