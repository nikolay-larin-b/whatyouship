# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for the lint engine and build artifact rule."""

import unittest
from pathlib import Path

from whatyouship.lint import LintEngine, compare_findings
from whatyouship.model import (
    ArtifactFile,
    ArtifactSignature,
    BinaryMetadata,
    Finding,
    InstallationScope,
    InstallationScopeConflict,
    ReleaseArtifact,
    SignatureMetadata,
)
from whatyouship.rules.build_artifacts import BuildArtifactRule
from whatyouship.rules.inconsistent_installation_scope import InconsistentInstallationScopeRule
from whatyouship.rules.invalid_artifact_signature import InvalidArtifactSignatureRule
from whatyouship.rules.unsigned_artifact import UnsignedArtifactRule
from whatyouship.rules.unsigned_binary import UnsignedBinaryRule


class _FixedRule:
    """Return one predetermined finding for engine tests."""

    def __init__(self, finding: Finding) -> None:
        """Store the finding returned by this rule.

        :param finding: Finding to return when the rule runs.
        """
        self.finding = finding

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Return the stored finding.

        :param artifact: Artifact supplied by the engine.
        :returns: A list containing the stored finding.
        """
        return [self.finding]


class LintTests(unittest.TestCase):
    """Verify rule application and build artifact detection."""

    def test_engine_collects_findings_from_all_rules(self) -> None:
        """Collect findings from each rule in the supplied order."""
        first = Finding("first", "warning", Path("a"), "first", "First finding.")
        second = Finding("second", "warning", Path("b"), "second", "Second finding.")
        artifact = ReleaseArtifact(source_path=Path("release"))

        findings = LintEngine([_FixedRule(first), _FixedRule(second)]).run(artifact)

        self.assertEqual(findings, [first, second])

    def test_identical_finding_is_existing(self) -> None:
        """Classify the same semantic finding as existing."""
        previous = Finding(
            "rule-a", "warning", Path("shared.obj"), "shared", "Same finding."
        )
        current = Finding(
            "rule-a", "warning", Path("shared.obj"), "shared", "Same finding."
        )

        comparison = compare_findings([previous], [current])

        self.assertEqual(comparison.existing, [current])
        self.assertEqual(comparison.new, [])
        self.assertEqual(comparison.resolved, [])

    def test_different_identity_on_same_rule_and_path_is_new_and_resolved(self) -> None:
        """Distinguish semantic conflicts reported at the same artifact path."""
        previous = Finding(
            "rule-a", "warning", Path("."), "component:Old", "Old conflict."
        )
        current = Finding(
            "rule-a", "warning", Path("."), "component:New", "New conflict."
        )

        comparison = compare_findings([previous], [current])

        self.assertEqual(comparison.existing, [])
        self.assertEqual(comparison.new, [current])
        self.assertEqual(comparison.resolved, [previous])

    def test_message_change_with_same_identity_is_existing(self) -> None:
        """Ignore cosmetic message changes during baseline matching."""
        previous = Finding(
            "rule-a", "warning", Path("app.exe"), "unsigned", "Earlier wording."
        )
        current = Finding(
            "rule-a", "warning", Path("app.exe"), "unsigned", "Improved wording."
        )

        comparison = compare_findings([previous], [current])

        self.assertEqual(comparison.existing, [current])
        self.assertEqual(comparison.new, [])
        self.assertEqual(comparison.resolved, [])

    def test_severity_change_with_same_identity_is_existing(self) -> None:
        """Ignore severity changes during baseline matching."""
        previous = Finding(
            "rule-a", "warning", Path("app.exe"), "unsigned", "Unsigned binary."
        )
        current = Finding(
            "rule-a", "error", Path("app.exe"), "unsigned", "Unsigned binary."
        )

        comparison = compare_findings([previous], [current])

        self.assertEqual(comparison.existing, [current])
        self.assertEqual(comparison.new, [])
        self.assertEqual(comparison.resolved, [])

    def test_compares_empty_findings(self) -> None:
        """Return empty groups when neither artifact has findings."""
        comparison = compare_findings([], [])

        self.assertEqual(comparison.existing, [])
        self.assertEqual(comparison.new, [])
        self.assertEqual(comparison.resolved, [])

    def test_baseline_distinguishes_multiple_installation_scope_conflicts(self) -> None:
        """Match scope conflicts by component and conflict type at path ``.``."""
        old_scope = InstallationScope(
            "ambiguous",
            (
                InstallationScopeConflict(
                    "component:App:fixed-per-machine:registry-entry:MachineKey",
                    "Component 'App' writes to HKLM.",
                ),
                InstallationScopeConflict(
                    "component:Data:fixed-per-user:directory:AppDataFolder",
                    "Component 'Data' uses AppDataFolder.",
                ),
            ),
        )
        new_scope = InstallationScope(
            "ambiguous",
            (
                InstallationScopeConflict(
                    "component:App:fixed-per-machine:registry-entry:MachineKey",
                    "Component 'App' uses a fixed machine registry entry.",
                ),
                InstallationScopeConflict(
                    "component:Tools:mixed-destinations",
                    "Component 'Tools' mixes per-user and per-machine destinations.",
                ),
            ),
        )
        rule = InconsistentInstallationScopeRule()
        previous = rule.check(
            ReleaseArtifact(Path("old.msi"), installation_scope=old_scope)
        )
        current = rule.check(
            ReleaseArtifact(Path("new.msi"), installation_scope=new_scope)
        )

        comparison = compare_findings(previous, current)

        self.assertEqual(comparison.existing, [current[0]])
        self.assertEqual(comparison.new, [current[1]])
        self.assertEqual(comparison.resolved, [previous[1]])

    def test_build_artifact_rule_flags_only_listed_extensions(self) -> None:
        """Flag suspicious extensions while leaving .lib and .pdb alone."""
        names = [
            "one.ilk",
            "two.obj",
            "three.iobj",
            "four.ipdb",
            "five.tlog",
            "six.lastbuildstate",
            "seven.ILK",
            "library.lib",
            "symbols.pdb",
        ]
        artifact = ReleaseArtifact(
            source_path=Path("release"),
            files=[ArtifactFile(Path(name), 1, "0" * 64) for name in names],
        )

        findings = LintEngine([BuildArtifactRule()]).run(artifact)

        self.assertEqual(
            [finding.relative_path for finding in findings],
            [Path(name) for name in names[:7]],
        )
        self.assertTrue(all(finding.rule_id == "build-artifact-extension" for finding in findings))
        self.assertTrue(all(finding.severity == "warning" for finding in findings))
        self.assertEqual(findings[0].identity, "extension:.ilk")
        self.assertTrue(all("Suspicious build artifact extension" in finding.message for finding in findings))

    def test_unsigned_binary_rule_uses_binary_type(self) -> None:
        """Flag unsigned executables and libraries regardless of filename."""
        files = [
            ArtifactFile(Path(name), 1, "0" * 64, binary=binary)
            for name, binary in [
                ("app.dat", BinaryMetadata("PE", "x86_64", "executable", signature=SignatureMetadata(False))),
                ("library.bin", BinaryMetadata("PE", "x86_64", "library", signature=SignatureMetadata(False))),
                ("fake.exe", None),
                ("signed.dll", BinaryMetadata("PE", "x86_64", "library", signature=SignatureMetadata(True, True))),
                ("unknown.exe", BinaryMetadata("PE", "x86_64", "executable", signature=SignatureMetadata(True, None))),
                ("unreadable.exe", BinaryMetadata("PE", "x86_64", "executable", signature=SignatureMetadata(None))),
                ("other.bin", BinaryMetadata("synthetic", "x86_64", "executable", signature=SignatureMetadata(False))),
            ]
        ]
        artifact = ReleaseArtifact(Path("release"), files)

        findings = UnsignedBinaryRule().check(artifact)

        self.assertEqual([finding.relative_path for finding in findings], [Path("app.dat"), Path("library.bin"), Path("other.bin")])
        self.assertTrue(all(finding.rule_id == "unsigned-binary" for finding in findings))
        self.assertTrue(all(finding.severity == "warning" for finding in findings))
        self.assertTrue(all(finding.identity == "unsigned" for finding in findings))
        self.assertEqual(
            [finding.message for finding in findings],
            ["Unsigned executable.", "Unsigned library.", "Unsigned executable."],
        )

    def test_artifact_signature_rules_are_independent_of_binary_signatures(self) -> None:
        """Apply package and contained binary signature checks separately."""
        binary = BinaryMetadata(
            "PE", "x86_64", "executable", signature=SignatureMetadata(False)
        )
        files = [ArtifactFile(Path("app.exe"), 1, "0" * 64, binary=binary)]
        rules = [UnsignedArtifactRule(), InvalidArtifactSignatureRule(), UnsignedBinaryRule()]

        unsigned = LintEngine(rules).run(
            ReleaseArtifact(Path("release.msi"), files, ArtifactSignature("unsigned"))
        )
        invalid = LintEngine(rules).run(
            ReleaseArtifact(Path("release.msi"), files, ArtifactSignature("invalid"))
        )
        unsupported = LintEngine(rules).run(ReleaseArtifact(Path("release"), files))

        self.assertEqual(
            [finding.rule_id for finding in unsigned],
            ["unsigned-artifact", "unsigned-binary"],
        )
        self.assertEqual(unsigned[0].relative_path, Path("."))
        self.assertEqual(
            [finding.rule_id for finding in invalid],
            ["invalid-artifact-signature", "unsigned-binary"],
        )
        self.assertEqual(invalid[0].severity, "error")
        self.assertEqual(
            [finding.rule_id for finding in unsupported], ["unsigned-binary"]
        )

    def test_installation_scope_rule_reports_each_contradiction(self) -> None:
        """Report specific scope conflicts with warning severity by default."""
        artifact = ReleaseArtifact(
            Path("release.msi"),
            installation_scope=InstallationScope(
                "ambiguous",
                (
                    InstallationScopeConflict(
                        "component:App:fixed-per-machine:registry-entry:MachineKey",
                        "Component 'App' writes to HKLM.",
                    ),
                    InstallationScopeConflict(
                        "component:Data:fixed-per-user:directory:AppDataFolder",
                        "Component 'Data' uses AppDataFolder.",
                    ),
                ),
            ),
        )

        findings = InconsistentInstallationScopeRule().check(artifact)

        self.assertEqual(len(findings), 2)
        self.assertTrue(all(finding.rule_id == "inconsistent-installation-scope" for finding in findings))
        self.assertTrue(all(finding.severity == "warning" for finding in findings))
        self.assertEqual(
            [finding.message for finding in findings],
            [conflict.message for conflict in artifact.installation_scope.conflicts],
        )
        self.assertEqual(
            InconsistentInstallationScopeRule().check(ReleaseArtifact(Path("directory"))),
            [],
        )


if __name__ == "__main__":
    unittest.main()
