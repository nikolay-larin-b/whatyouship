# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for targeted lint exceptions, baseline policy, and report visibility."""

import contextlib
import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.cli import main
from whatyouship.config import (
    BuildArtifactSettings,
    IgnoreSettings,
    LintConfiguration,
    load_config,
)
from whatyouship.exceptions import ConfigurationError
from whatyouship.model import ArtifactSignature, Finding, ReleaseArtifact
from whatyouship.operations import lint
from whatyouship.renderers import render_report
from whatyouship.suppressions import suppress_findings


class SuppressionTests(unittest.TestCase):
    """Verify portable, explicit suppression boundaries."""

    def test_exact_and_glob_paths(self) -> None:
        """Match entire case-sensitive paths and distinguish segment wildcards."""
        cases = (
            ("vendor/helper", "vendor/helper", True),
            ("vendor/helper", "other/vendor/helper", False),
            ("vendor/helper", "vendor/helper/child", False),
            ("vendor/helper", "vendor/Helper", False),
            ("vendor/*", "vendor/helper", True),
            ("vendor/*", "vendor/nested/helper", False),
            ("symbols/**/*.pdb", "symbols/app.pdb", True),
            ("symbols/**/*.pdb", "symbols/a/b/app.pdb", True),
            ("symbols/**/*.pdb", "other/app.pdb", False),
            ("**/*.pdb", "app.pdb", True),
            ("**/*.pdb", "a/app.PDB", False),
            ("a/**/b/**/file", "a/b/file", True),
            ("a/**/b/**/file", "a/x/b/y/z/file", True),
            ("vendor/**", "vendor", True),
            ("vendor/**", "vendor/a/b", True),
            ("**", "a/b", True),
            ("**", ".", False),
            ("*", ".", False),
            (".", ".", True),
            (".", "file", False),
        )
        for pattern, path, expected in cases:
            with self.subTest(pattern=pattern, path=path):
                finding = Finding("unsigned-binary", "warning", Path(path), "id", "message")
                self.assertEqual(IgnoreSettings("unsigned-binary", pattern).matches(finding), expected)

    def test_rule_and_first_matching_exception(self) -> None:
        """Preserve finding order and attach the first matching exception."""
        first = Finding("unsigned-binary", "warning", Path("vendor/helper"), "one", "first")
        other = Finding("invalid-binary-signature", "error", first.relative_path, "two", "other")
        last = Finding("unsigned-binary", "warning", Path("app"), "three", "last")
        ignore = IgnoreSettings("unsigned-binary", "vendor/*", "Approved vendor tool.")
        active, suppressed = suppress_findings(
            [first, other, last], [ignore, IgnoreSettings("unsigned-binary", "**", "Fallback.")]
        )
        self.assertEqual(active, [other])
        self.assertEqual([item.finding for item in suppressed], [first, last])
        self.assertIs(suppressed[0].finding, first)
        self.assertIs(suppressed[0].ignore, ignore)

    def test_invalid_typed_settings(self) -> None:
        """Reject malformed paths and unsupported settings before matching."""
        for path in (
            "", "/absolute", "../file", "a/../b", "./file", "a/./b", "a//b",
            "a/", "C:/file", "C:relative", "a\\b", "a/**b", "a/***", "a/[x]",
            "a/?", "a/{x}", "a/\nfile",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                IgnoreSettings("unsigned-binary", path)
        with self.assertRaises(ValueError):
            IgnoreSettings("unknown-rule", "file")

    def test_loads_ignore_tables_with_optional_reason(self) -> None:
        """Combine strict rule settings with ordered ignore tables."""
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.toml"
            path.write_text(
                '[rules.unsigned-binary]\nseverity = "error"\n'
                '[[ignore]]\nrule = "unsigned-binary"\npath = "vendor/helper"\n'
                'reason = "Approved tool."\n'
                '[[ignore]]\nrule = "unsigned-artifact"\npath = "."\n',
                encoding="utf-8",
            )
            config = load_config(path)
        self.assertEqual(config.unsigned_binary.severity, "error")
        self.assertEqual(config.ignore, (
            IgnoreSettings("unsigned-binary", "vendor/helper", "Approved tool."),
            IgnoreSettings("unsigned-artifact", "."),
        ))

    def test_rejects_invalid_ignore_configuration(self) -> None:
        """Reject invalid tables, unknown keys, missing fields, and wrong types."""
        documents = (
            'ignore = "file"',
            '[ignore]\nrule = "unsigned-binary"\npath = "file"',
            'ignore = ["file"]',
            '[[ignore]]\nrule = "unsigned-binary"',
            '[[ignore]]\npath = "file"',
            '[[ignore]]\nrule = "unknown"\npath = "file"',
            '[[ignore]]\nrule = 1\npath = "file"',
            '[[ignore]]\nrule = "unsigned-binary"\npath = 1',
            '[[ignore]]\nrule = "unsigned-binary"\npath = "../file"',
            '[[ignore]]\nrule = "unsigned-binary"\npath = "file"\nreason = false',
            '[[ignore]]\nrule = "unsigned-binary"\npath = "file"\nplatform = "macos"',
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "config.toml"
            for document in documents:
                with self.subTest(document=document):
                    path.write_text(document, encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_config(path)
                    with self.assertRaises(ConfigurationError):
                        lint(root, config=path)

    def test_artifact_level_suppression(self) -> None:
        """Suppress artifact findings only through an explicit dot path."""
        artifact = ReleaseArtifact(Path("release"), signature=ArtifactSignature(status="unsigned"))
        config = LintConfiguration(ignore=(IgnoreSettings("unsigned-artifact", "."),))
        with patch("whatyouship.operations._inspect_source", return_value=artifact):
            report = lint("release", config=config)
        self.assertEqual(report.findings, [])
        self.assertEqual(report.suppressed_findings[0].finding.relative_path, Path("."))

    def test_baseline_and_renderers_retain_suppressed_findings_separately(self) -> None:
        """Filter both artifacts before classification while retaining audit data."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new = root / "old", root / "new"
            old.mkdir()
            new.mkdir()
            for directory, names in (
                (old, ("same.obj", "resolved.obj", "vendor/common.obj", "vendor/old.obj")),
                (new, ("same.obj", "new.obj", "vendor/common.obj", "vendor/new.obj")),
            ):
                for name in names:
                    path = directory / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"object")
            config = LintConfiguration(
                build_artifacts=BuildArtifactSettings(severity="error"),
                ignore=(IgnoreSettings("build-artifact-extension", "vendor/**", "Vendor files."),),
            )
            report = lint(new, baseline=old, config=config)
        comparison = report.baseline_comparison
        assert comparison is not None
        self.assertEqual([item.relative_path for item in comparison.new], [Path("new.obj")])
        self.assertEqual([item.relative_path for item in comparison.existing], [Path("same.obj")])
        self.assertEqual([item.relative_path for item in comparison.resolved], [Path("resolved.obj")])
        self.assertEqual(len(report.findings), 2)
        self.assertEqual(len(report.suppressed_findings), 2)
        self.assertEqual(len(report.baseline_suppressed_findings), 2)
        text = render_report(report, "text")
        self.assertIn("Suppressed findings: 2", text)
        self.assertIn("Baseline suppressed findings: 2", text)
        self.assertNotIn("vendor/common.obj", text)
        data = json.loads(render_report(report, "json"))
        suppressed = data["suppressed_findings"]
        self.assertEqual(len(suppressed), 2)
        self.assertEqual(suppressed[0]["relative_path"], "vendor/common.obj")
        self.assertEqual(suppressed[0]["ignore"], {"path": "vendor/**", "reason": "Vendor files."})
        self.assertEqual(len(data["baseline"]["suppressed_findings"]), 2)
        rows = list(csv.DictReader(io.StringIO(render_report(report, "csv"))))
        self.assertEqual([row["category"] for row in rows], [
            "new", "existing", "resolved", "suppressed", "suppressed",
            "baseline-suppressed", "baseline-suppressed",
        ])

    def test_cli_exceptions_do_not_hide_unmatched_findings(self) -> None:
        """Gate only active findings with and without a baseline."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload, baseline = root / "payload", root / "baseline"
            payload.mkdir()
            baseline.mkdir()
            (payload / "allowed.obj").write_bytes(b"allowed")
            path = root / "config.toml"
            path.write_text(
                '[[ignore]]\nrule = "build-artifact-extension"\npath = "allowed.obj"\n',
                encoding="utf-8",
            )
            output = root / "lint.json"
            for baseline_arguments in ([], ["--baseline", str(baseline)]):
                arguments = ["lint", str(payload), "--config", str(path),
                             "--fail-on", "warning", "-o", str(output), *baseline_arguments]
                with self.subTest(baseline=bool(baseline_arguments)), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(main(arguments), 0)
                    data = json.loads(output.read_text(encoding="utf-8"))
                    self.assertEqual(data["findings"], [])
                    self.assertIsNone(data["suppressed_findings"][0]["ignore"]["reason"])
                    self.assertEqual(len(data["suppressed_findings"]), 1)
                    (payload / "blocked.obj").write_bytes(b"blocked")
                    self.assertEqual(main(arguments), 1)
                    (payload / "blocked.obj").unlink()

    def test_invalid_ignore_is_cli_configuration_error(self) -> None:
        """Report invalid exceptions through the standard CLI error contract."""
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config.toml"
            config.write_text('[[ignore]]\nrule = "typo"\npath = "**"\n', encoding="utf-8")
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    main(["lint", str(root), "--config", str(config)])
        self.assertEqual(raised.exception.code, 2)
