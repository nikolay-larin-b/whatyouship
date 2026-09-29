# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for structured text, JSON, and CSV report output."""

import contextlib
import csv
import io
import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from whatyouship import __version__
from whatyouship.cli import main
from whatyouship.compare import ComparisonResult, SemanticDifference
from whatyouship.model import (
    AppBundleMetadata,
    ArtifactFile,
    ArtifactSignature,
    ArtifactSymbolicLink,
    BinaryDependency,
    BinaryEntitlement,
    BinaryMetadata,
    BundleIssue,
    Finding,
    InstallationScope,
    InstallationScopeConflict,
    ReleaseArtifact,
    SignatureMetadata,
)
from whatyouship.report import CompareReport, InspectReport, LintReport
from whatyouship.renderers.csv import INSPECT_COLUMNS, LINT_COLUMNS, render_csv


class ReportOutputTests(unittest.TestCase):
    """Verify CLI output files and stable structured report contents."""

    def test_text_file_matches_stdout_for_every_command(self) -> None:
        """Keep file text identical to the existing console output."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            old = root / "old"
            new = root / "new"
            old.mkdir()
            new.mkdir()
            (old / "removed.ilk").write_bytes(b"old")
            (new / "added.obj").write_bytes(b"new")
            cases = (
                ("inspect", [str(new)]),
                ("lint", [str(new)]),
                ("compare", [str(old), str(new)]),
            )
            for command, arguments in cases:
                with self.subTest(command=command):
                    output = io.StringIO()
                    target = root / f"{command}.txt"
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(main([command, *arguments]), 0)
                    file_stdout = io.StringIO()
                    with contextlib.redirect_stdout(file_stdout):
                        self.assertEqual(main([command, *arguments, "-o", str(target)]), 0)
                    self.assertEqual(file_stdout.getvalue(), "")
                    self.assertEqual(target.read_text(encoding="utf-8"), output.getvalue())

    def test_inspect_json_preserves_available_metadata(self) -> None:
        """Serialize artifact, file, binary, and signature metadata without loss."""
        timestamp = datetime(2026, 9, 22, 10, 30, tzinfo=timezone.utc)
        artifact = ReleaseArtifact(
            Path("release.msi"),
            [ArtifactFile(
                Path("bin/app.exe"), 42, "a" * 64,
                binary=BinaryMetadata(
                    "PE", "x86_64", "executable", "1.2.3", "4.5.6",
                    SignatureMetadata(
                        True,
                        True,
                        "CN=Publisher",
                        True,
                        "certificate",
                    ),
                ),
            )],
            signature=ArtifactSignature(
                "valid",
                "CN=Package Publisher",
                timestamp,
                team_id="TEAM123456",
                notarization_ticket=True,
            ),
            installation_scope=InstallationScope(
                "ambiguous",
                (InstallationScopeConflict("registry:conflict", "Conflicting registry root"),),
            ),
            bundles=[AppBundleMetadata(
                Path("Sample.app"),
                identifier="com.example.sample",
                name="Sample",
                short_version="1.2.3",
                bundle_version="45",
                executable="sample",
                executable_path=Path("Sample.app/Contents/MacOS/sample"),
                minimum_system_version="13.0",
                package_type="APPL",
                issues=(BundleIssue("sample-issue", "Sample bundle issue."),),
            )],
            symbolic_links=[
                ArtifactSymbolicLink(Path("Current"), "Versions/A"),
                ArtifactSymbolicLink(Path("Applications"), "/Applications", True),
            ],
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "inspect.json"
            with patch("whatyouship.cli.inspect_artifact", return_value=artifact):
                self.assertEqual(main(["inspect", "release.msi", "--output", str(target)]), 0)
            data = json.loads(target.read_text(encoding="utf-8"))

        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["tool_version"], __version__)
        self.assertEqual(data["report_type"], "inspect")
        self.assertEqual(data["artifact"]["source_path"], "release.msi")
        self.assertEqual(data["artifact"]["file_count"], 1)
        self.assertEqual(data["artifact"]["total_size_bytes"], 42)
        self.assertEqual(data["artifact"]["signature"], {
            "status": "valid", "signer": "CN=Package Publisher",
            "timestamp": timestamp.isoformat(),
            "team_id": "TEAM123456",
            "notarization_ticket": True,
        })
        self.assertEqual(data["artifact"]["installation_scope"], {
            "kind": "ambiguous", "conflicts": ["Conflicting registry root"],
        })
        self.assertIsNone(data["artifact"]["license_agreement_present"])
        self.assertEqual(data["artifact"]["bundles"], [{
            "relative_path": "Sample.app",
            "identifier": "com.example.sample",
            "name": "Sample",
            "short_version": "1.2.3",
            "bundle_version": "45",
            "executable": "sample",
            "executable_path": "Sample.app/Contents/MacOS/sample",
            "minimum_system_version": "13.0",
            "package_type": "APPL",
            "issues": [{
                "identity": "sample-issue",
                "message": "Sample bundle issue.",
            }],
        }])
        self.assertEqual(data["artifact"]["symbolic_links"], [
            {
                "relative_path": "Current",
                "target": "Versions/A",
                "external": False,
            },
            {
                "relative_path": "Applications",
                "target": "/Applications",
                "external": True,
            },
        ])
        self.assertEqual(data["artifact"]["files"][0], {
            "relative_path": "bin/app.exe", "size_bytes": 42, "sha256": "a" * 64,
            "binary": {
                "format": "PE", "architecture": "x86_64", "kind": "executable",
                "file_version": "1.2.3", "product_version": "4.5.6",
                "minimum_os_version": None,
                "dependencies": [],
                "runtime_search_paths": [],
                "signature": {
                    "present": True, "valid": True,
                    "signer": "CN=Publisher", "timestamp": True,
                    "type": "certificate",
                    "hardened_runtime": None,
                    "entitlements": [],
                },
            },
        })

    def test_inspect_text_displays_application_bundle_metadata(self) -> None:
        """Include bundle identity, versions, executable, and issues in text."""
        artifact = ReleaseArtifact(
            Path("release.dmg"),
            [ArtifactFile(
                Path("Sample.app/Contents/MacOS/sample"),
                32,
                "a" * 64,
                BinaryMetadata(
                    "Mach-O",
                    "arm64",
                    "executable",
                    signature=SignatureMetadata(
                        True,
                        signature_type="certificate",
                        hardened_runtime=True,
                        entitlements=(BinaryEntitlement(
                            "com.apple.security.app-sandbox",
                            "true",
                        ),),
                    ),
                    minimum_os_version="13.0",
                    dependencies=(
                        BinaryDependency("@rpath/libSample.dylib"),
                        BinaryDependency(
                            "/usr/lib/libobjc.A.dylib",
                            required=False,
                        ),
                    ),
                    runtime_search_paths=("@executable_path/../Frameworks",),
                ),
            )],
            bundles=[AppBundleMetadata(
                Path("Sample.app"),
                identifier="com.example.sample",
                short_version="1.2.3",
                bundle_version="45",
                executable="sample",
                executable_path=Path("Sample.app/Contents/MacOS/sample"),
                issues=(BundleIssue("missing-value", "A required value is missing."),),
            )],
            symbolic_links=[
                ArtifactSymbolicLink(Path("Current"), "Versions/A"),
                ArtifactSymbolicLink(Path("Applications"), "/Applications", True),
            ],
        )
        output = io.StringIO()

        with (
            patch("whatyouship.cli.inspect_artifact", return_value=artifact),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(main(["inspect", "release.dmg"]), 0)

        rendered = output.getvalue()
        self.assertIn("Application bundles:\n  Sample.app", rendered)
        self.assertIn("Identifier: com.example.sample", rendered)
        self.assertIn("Version: 1.2.3", rendered)
        self.assertIn("Build version: 45", rendered)
        self.assertIn("Executable: sample", rendered)
        self.assertIn("Issue: A required value is missing.", rendered)
        self.assertIn("Minimum OS version: 13.0", rendered)
        self.assertIn("Dependency: @rpath/libSample.dylib | required", rendered)
        self.assertIn("Dependency: /usr/lib/libobjc.A.dylib | weak", rendered)
        self.assertIn(
            "Runtime search path: @executable_path/../Frameworks",
            rendered,
        )
        self.assertIn("Hardened Runtime: enabled", rendered)
        self.assertIn(
            "Entitlement: com.apple.security.app-sandbox = true",
            rendered,
        )
        self.assertIn("Symbolic links:\n  Current -> Versions/A", rendered)
        self.assertIn("  Applications -> /Applications | external", rendered)

    def test_lint_json_baseline_keeps_all_categories(self) -> None:
        """Retain existing findings even though text hides their details."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            old = root / "old"
            new = root / "new"
            old.mkdir()
            new.mkdir()
            for directory, names in (
                (old, ("existing.obj", "resolved.ilk")),
                (new, ("existing.obj", "new.iobj")),
            ):
                for name in names:
                    (directory / name).write_bytes(b"data")
            target = root / "lint.json"

            self.assertEqual(main(["lint", str(new), "--baseline", str(old), "-o", str(target)]), 0)
            data = json.loads(target.read_text(encoding="utf-8"))

        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["report_type"], "lint")
        self.assertEqual(data["artifact"], {"source_path": str(new)})
        self.assertEqual(data["baseline"]["source_path"], str(old))
        self.assertEqual(
            {category: [item["relative_path"] for item in data["baseline"][category]]
             for category in ("new", "existing", "resolved")},
            {"new": ["new.iobj"], "existing": ["existing.obj"], "resolved": ["resolved.ilk"]},
        )
        self.assertEqual(len(data["findings"]), 2)

    def test_compare_json_keeps_all_path_groups_and_semantics(self) -> None:
        """Serialize unchanged paths and semantic warnings alongside changes."""
        old = ReleaseArtifact(Path("old.zip"))
        new = ReleaseArtifact(Path("new.zip"))
        comparison = ComparisonResult(
            added=[Path("added.txt")], removed=[Path("removed.txt")],
            changed=[Path("changed.exe")], unchanged=[Path("same.txt")],
            semantic_differences=[SemanticDifference(
                Path("changed.exe"), "File version", "2.0", "1.0",
                severity="warning", warning_message="version downgrade",
            )],
        )
        with tempfile.TemporaryDirectory() as temporary_directory:
            target = Path(temporary_directory) / "compare.json"
            with (
                patch("whatyouship.cli.inspect_artifact", side_effect=[old, new]),
                patch("whatyouship.cli.compare_artifacts", return_value=comparison),
            ):
                self.assertEqual(main(["compare", "old.zip", "new.zip", "-o", str(target)]), 0)
            data = json.loads(target.read_text(encoding="utf-8"))

        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["report_type"], "compare")
        self.assertEqual(data["old_artifact"], {"source_path": "old.zip"})
        self.assertEqual(data["new_artifact"], {"source_path": "new.zip"})
        self.assertEqual(
            {category: data[category] for category in ("added", "removed", "changed", "unchanged")},
            {"added": ["added.txt"], "removed": ["removed.txt"],
             "changed": ["changed.exe"], "unchanged": ["same.txt"]},
        )
        self.assertEqual(data["semantic_differences"][0]["severity"], "warning")
        self.assertEqual(data["semantic_differences"][0]["warning_message"], "version downgrade")

    def test_inspect_csv_has_one_row_per_file_and_quotes_values(self) -> None:
        """Use the standard CSV writer for file paths containing delimiters."""
        artifact = ReleaseArtifact(Path("release"), [
            ArtifactFile(Path('name,"quoted".txt'), 4, "a" * 64),
            ArtifactFile(Path("other.txt"), 5, "b" * 64),
        ])
        raw = render_csv(InspectReport(artifact))
        rows = list(csv.DictReader(io.StringIO(raw)))

        self.assertEqual(len(rows), 2)
        self.assertEqual(tuple(rows[0]), INSPECT_COLUMNS)
        self.assertNotIn("source_path", rows[0])
        self.assertEqual(rows[0]["relative_path"], 'name,"quoted".txt')
        self.assertEqual(rows[0]["size_bytes"], "4")
        self.assertIn('"name,""quoted"".txt"', raw)
        self.assertNotIn(str(artifact.source_path), raw)

    def test_inspect_csv_includes_macho_minimum_os_version(self) -> None:
        """Serialize the Mach-O deployment target in file-oriented CSV output."""
        artifact = ReleaseArtifact(Path("release.dmg"), [ArtifactFile(
            Path("Sample.app/Contents/MacOS/sample"),
            32,
            "a" * 64,
            BinaryMetadata(
                "Mach-O",
                "arm64",
                "executable",
                signature=SignatureMetadata(
                    True,
                    hardened_runtime=True,
                    entitlements=(BinaryEntitlement(
                        "com.apple.security.app-sandbox",
                        "true",
                    ),),
                ),
                minimum_os_version="13.0",
                dependencies=(BinaryDependency("@rpath/libSample.dylib"),),
                runtime_search_paths=("@loader_path/../Frameworks",),
            ),
        )])

        rows = list(csv.DictReader(io.StringIO(
            render_csv(InspectReport(artifact))
        )))

        self.assertEqual(rows[0]["minimum_os_version"], "13.0")
        self.assertEqual(
            json.loads(rows[0]["dependencies"]),
            [{"path": "@rpath/libSample.dylib", "required": True}],
        )
        self.assertEqual(
            json.loads(rows[0]["runtime_search_paths"]),
            ["@loader_path/../Frameworks"],
        )
        self.assertEqual(rows[0]["hardened_runtime"], "true")
        self.assertEqual(
            json.loads(rows[0]["entitlements"]),
            [{"key": "com.apple.security.app-sandbox", "value": True}],
        )

    def test_lint_csv_has_one_row_per_finding_and_quotes_message(self) -> None:
        """Preserve punctuation and newlines in CSV finding messages."""
        finding = Finding(
            "sample",
            "warning",
            Path("a,b.obj"),
            "sample-conflict",
            'A "quoted",\nmessage',
        )
        report = LintReport(ReleaseArtifact(Path("release")), [finding])

        raw = render_csv(report)
        rows = list(csv.DictReader(io.StringIO(raw)))

        self.assertEqual(tuple(rows[0]), LINT_COLUMNS)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], {
            "category": "current", "rule_id": "sample", "severity": "warning",
            "relative_path": "a,b.obj", "message": 'A "quoted",\nmessage',
        })

    def test_lint_csv_baseline_writes_new_existing_and_resolved(self) -> None:
        """Keep all baseline categories in finding rows."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            old = root / "old"
            new = root / "new"
            old.mkdir()
            new.mkdir()
            for directory, names in (
                (old, ("existing.obj", "resolved.ilk")),
                (new, ("existing.obj", "new.iobj")),
            ):
                for name in names:
                    (directory / name).write_bytes(b"data")
            target = root / "lint.csv"

            self.assertEqual(main(["lint", str(new), "--baseline", str(old), "-o", str(target)]), 0)
            with target.open(newline="", encoding="utf-8") as stream:
                rows = list(csv.DictReader(stream))

        self.assertEqual(
            [(row["category"], row["relative_path"]) for row in rows],
            [("new", "new.iobj"), ("existing", "existing.obj"), ("resolved", "resolved.ilk")],
        )

    def test_invalid_extension_and_compare_csv_fail(self) -> None:
        """Reject unsupported output extensions and compare CSV early."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = root / "release"
            artifact.mkdir()
            for arguments, message in (
                (["inspect", str(artifact), "-o", str(root / "report.xml")], "Unsupported output file extension"),
                (["compare", str(artifact), str(artifact), "-o", str(root / "report.csv")], "CSV output is not supported for compare"),
            ):
                with self.subTest(arguments=arguments):
                    error_output = io.StringIO()
                    with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                        main(arguments)
                    self.assertEqual(result.exception.code, 2)
                    self.assertIn(message, error_output.getvalue())

    def test_output_write_error_is_reported(self) -> None:
        """Report file write failures through the CLI error path."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            artifact = root / "release"
            artifact.mkdir()
            output_directory = root / "report.json"
            output_directory.mkdir()
            error_output = io.StringIO()

            with contextlib.redirect_stderr(error_output), self.assertRaises(SystemExit) as result:
                main(["inspect", str(artifact), "-o", str(output_directory)])

            self.assertEqual(result.exception.code, 2)
            self.assertIn("report.json", error_output.getvalue())


if __name__ == "__main__":
    unittest.main()
