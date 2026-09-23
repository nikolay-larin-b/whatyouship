# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for static MSI installation scope analysis."""

import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from whatyouship.inspectors.msi_scope import MsiScopeInspector, analyze_msi_scope
from whatyouship.model import InstallationScope, ReleaseArtifact
from whatyouship.rules.inconsistent_installation_scope import InconsistentInstallationScopeRule


class MsiScopeTests(unittest.TestCase):
    """Verify authored scope and fixed destination checks."""

    def test_per_user_package_with_user_destinations(self) -> None:
        """Accept an unset ALLUSERS with user directories and HKCU entries."""
        scope = analyze_msi_scope({
            "Directory": [
                {"Directory": "AppDataFolder", "Directory_Parent": "TARGETDIR"},
                {"Directory": "APPDIR", "Directory_Parent": "AppDataFolder"},
            ],
            "Component": [{
                "Component": "UserSettings", "Directory_": "APPDIR",
                "Attributes": 4, "KeyPath": "SettingsKey",
            }],
            "Registry": [{
                "Registry": "SettingsKey", "Root": 1,
                "Component_": "UserSettings",
            }],
        })

        self.assertEqual(scope, InstallationScope("per-user"))

    def test_per_machine_package_with_machine_destinations(self) -> None:
        """Accept ALLUSERS=1 with machine directories and HKLM entries."""
        scope = analyze_msi_scope({
            "Property": [{"Property": "ALLUSERS", "Value": "1"}],
            "Directory": [{
                "Directory": "CommonAppDataFolder", "Directory_Parent": "TARGETDIR",
            }],
            "Component": [{
                "Component": "SharedSettings", "Directory_": "CommonAppDataFolder",
            }],
            "Registry": [{
                "Registry": "MachineKey", "Root": 2,
                "Component_": "SharedSettings",
            }],
        })

        self.assertEqual(scope, InstallationScope("per-machine"))

    def test_dual_purpose_package_uses_redirected_destinations(self) -> None:
        """Accept ALLUSERS=2, context-aware folders, and registry roots."""
        scope = analyze_msi_scope({
            "Property": [
                {"Property": "ALLUSERS", "Value": "2"},
                {"Property": "MSIINSTALLPERUSER", "Value": "1"},
            ],
            "Directory": [{
                "Directory": "ProgramFilesFolder", "Directory_Parent": "TARGETDIR",
            }],
            "Component": [{
                "Component": "Application", "Directory_": "ProgramFilesFolder",
                "Attributes": 4, "KeyPath": "AppKey",
            }],
            "Registry": [
                {"Registry": "AppKey", "Root": -1, "Component_": "Application"},
                {"Registry": "ClassKey", "Root": 0, "Component_": "Application"},
            ],
            "CustomAction": [{
                "Action": "ChoosePerUser", "Type": 51,
                "Source": "MSIINSTALLPERUSER", "Target": "1",
            }],
        })

        self.assertEqual(scope, InstallationScope("dual-purpose"))
        self.assertEqual(
            analyze_msi_scope({"Property": [{"Property": "ALLUSERS", "Value": "2"}]}),
            InstallationScope("dual-purpose"),
        )

    def test_per_user_package_with_machine_destinations_is_ambiguous(self) -> None:
        """Report fixed machine folders and a machine registry key path."""
        scope = analyze_msi_scope({
            "Directory": [{
                "Directory": "CommonAppDataFolder", "Directory_Parent": "TARGETDIR",
            }],
            "Component": [{
                "Component": "Mixed", "Directory_": "CommonAppDataFolder",
                "Attributes": 4, "KeyPath": "MachineKey",
            }],
            "Registry": [{
                "Registry": "MachineKey", "Root": 2, "Component_": "Mixed",
            }],
        })

        self.assertEqual(scope.kind, "ambiguous")
        self.assertTrue(
            any("CommonAppDataFolder" in item.message for item in scope.conflicts)
        )
        self.assertTrue(
            any(
                "HKLM registry key path 'MachineKey'" in item.message
                for item in scope.conflicts
            )
        )
        self.assertEqual(
            {conflict.identity for conflict in scope.conflicts},
            {
                "component:Mixed:fixed-per-machine:directory:CommonAppDataFolder",
                "component:Mixed:fixed-per-machine:registry-key-path:MachineKey",
            },
        )

    def test_per_machine_package_with_user_destinations_is_ambiguous(self) -> None:
        """Report HKCU and AppData destinations in a machine package."""
        scope = analyze_msi_scope({
            "Property": [{"Property": "ALLUSERS", "Value": "1"}],
            "Directory": [{"Directory": "AppDataFolder"}],
            "Component": [{"Component": "UserData", "Directory_": "AppDataFolder"}],
            "Registry": [{"Registry": "UserKey", "Root": 1, "Component_": "UserData"}],
        })

        self.assertEqual(scope.kind, "ambiguous")
        self.assertTrue(any("AppDataFolder" in item.message for item in scope.conflicts))
        self.assertTrue(any("HKCU" in item.message for item in scope.conflicts))

    def test_per_user_package_with_fixed_machine_component_regression(self) -> None:
        """Keep a JASON 6.1-like HKLM component visible in a per-user package."""
        scope = analyze_msi_scope({
            "Component": [{
                "Component": "CM_CP_JASON.exe", "Directory_": "ProgramFilesFolder",
                "Attributes": 0,
            }],
            "Registry": [{
                "Registry": "CPMachineRegistration", "Root": 2,
                "Component_": "CM_CP_JASON.exe",
            }],
        })

        self.assertEqual(scope.kind, "ambiguous")
        self.assertTrue(any(
            "Component 'CM_CP_JASON.exe' uses fixed per-machine HKLM registry entry"
            in conflict.message
            and "per-user installation scope" in conflict.message
            for conflict in scope.conflicts
        ))
        findings = InconsistentInstallationScopeRule().check(
            ReleaseArtifact(Path("jason-6.1.msi"), installation_scope=scope)
        )
        self.assertTrue(any(
            finding.rule_id == "inconsistent-installation-scope"
            and finding.severity == "warning"
            and "CM_CP_JASON.exe" in finding.message
            for finding in findings
        ))

    def test_per_machine_shortcut_keypaths_do_not_create_scope_conflicts(self) -> None:
        """Accept JASON 6.2-like HKCU key paths for non-advertised shortcuts."""
        scope = analyze_msi_scope({
            "Property": [{"Property": "ALLUSERS", "Value": "1"}],
            "Directory": [{
                "Directory": "CommonDesktopFolder", "Directory_Parent": "TARGETDIR",
            }],
            "Component": [
                {
                    "Component": "CM_SHORTCUT", "Directory_": "ProgramMenuFolder",
                    "Attributes": 4, "KeyPath": "StartMenuShortcutKey",
                },
                {
                    "Component": "CM_SHORTCUT_DESKTOP",
                    "Directory_": "CommonDesktopFolder",
                    "Attributes": 4, "KeyPath": "DesktopShortcutKey",
                },
            ],
            "Registry": [
                {
                    "Registry": "StartMenuShortcutKey", "Root": 1,
                    "Component_": "CM_SHORTCUT",
                },
                {
                    "Registry": "DesktopShortcutKey", "Root": 1,
                    "Component_": "CM_SHORTCUT_DESKTOP",
                },
            ],
            "Shortcut": [
                {
                    "Shortcut": "StartMenuLink", "Component_": "CM_SHORTCUT",
                    "Target": "[#JASON.exe]",
                },
                {
                    "Shortcut": "DesktopLink",
                    "Component_": "CM_SHORTCUT_DESKTOP",
                    "Target": "[INSTALLDIR]JASON.exe",
                },
            ],
        })

        self.assertEqual(scope, InstallationScope("per-machine"))
        self.assertEqual(
            InconsistentInstallationScopeRule().check(
                ReleaseArtifact(Path("jason-6.2.msi"), installation_scope=scope)
            ),
            [],
        )

    def test_per_machine_shortcut_exception_is_limited_to_its_hkcu_keypath(self) -> None:
        """Flag other HKCU entries and advertised-only shortcut components."""
        for shortcut_target in (None, "MainFeature"):
            with self.subTest(shortcut_target=shortcut_target):
                shortcuts = (
                    [] if shortcut_target is None else [{
                        "Shortcut": "Link", "Component_": "Shortcuts",
                        "Target": shortcut_target,
                    }]
                )
                scope = analyze_msi_scope({
                    "Property": [{"Property": "ALLUSERS", "Value": "1"}],
                    "Component": [{
                        "Component": "Shortcuts", "Attributes": 4,
                        "KeyPath": "ShortcutKey",
                    }],
                    "Registry": [{
                        "Registry": "ShortcutKey", "Root": 1,
                        "Component_": "Shortcuts",
                    }],
                    "Shortcut": shortcuts,
                })

                self.assertEqual(scope.kind, "ambiguous")
                self.assertTrue(
                    any(
                        "HKCU registry key path" in item.message
                        for item in scope.conflicts
                    )
                )

        scope = analyze_msi_scope({
            "Property": [{"Property": "ALLUSERS", "Value": "1"}],
            "Component": [{
                "Component": "Shortcuts", "Attributes": 4,
                "KeyPath": "ShortcutKey",
            }],
            "Registry": [
                {"Registry": "ShortcutKey", "Root": 1, "Component_": "Shortcuts"},
                {"Registry": "OtherUserKey", "Root": 1, "Component_": "Shortcuts"},
            ],
            "Shortcut": [{
                "Shortcut": "Link", "Component_": "Shortcuts", "Target": "[#AppFile]",
            }],
        })

        self.assertEqual(scope.kind, "ambiguous")
        self.assertTrue(
            any(
                "HKCU registry entry 'OtherUserKey'" in item.message
                for item in scope.conflicts
            )
        )
        self.assertFalse(
            any("ShortcutKey" in item.message for item in scope.conflicts)
        )

    def test_dual_purpose_package_with_fixed_root_is_ambiguous(self) -> None:
        """Flag a fixed HKLM entry that cannot follow a per-user choice."""
        scope = analyze_msi_scope({
            "Property": [{"Property": "ALLUSERS", "Value": "2"}],
            "Component": [{"Component": "Application", "Directory_": "TARGETDIR"}],
            "Registry": [{"Registry": "FixedKey", "Root": 2, "Component_": "Application"}],
        })

        self.assertEqual(scope.kind, "ambiguous")
        self.assertIn("dual-purpose", scope.conflicts[0].message)
        self.assertIn("HKLM", scope.conflicts[0].message)

    def test_component_mixes_user_and_machine_destinations(self) -> None:
        """Identify an internally mixed component even before install choice."""
        scope = analyze_msi_scope({
            "Property": [{"Property": "ALLUSERS", "Value": "2"}],
            "Directory": [{"Directory": "AppDataFolder"}],
            "Component": [{"Component": "Mixed", "Directory_": "AppDataFolder"}],
            "Registry": [{"Registry": "MachineKey", "Root": 2, "Component_": "Mixed"}],
        })

        self.assertEqual(scope.kind, "ambiguous")
        self.assertTrue(
            any(
                "mixes per-user and per-machine" in item.message
                for item in scope.conflicts
            )
        )

    def test_custom_action_changes_declared_scope(self) -> None:
        """Detect explicit Type 51 scope changes, including flagged actions."""
        scope = analyze_msi_scope({
            "Property": [{"Property": "ALLUSERS", "Value": "1"}],
            "CustomAction": [{
                "Action": "ChangeScope", "Type": 51 | 0x100,
                "Source": "ALLUSERS", "Target": "2",
            }],
        })

        self.assertEqual(scope.kind, "ambiguous")
        self.assertIn("CustomAction 'ChangeScope'", scope.conflicts[0].message)

    def test_formatted_custom_action_scope_is_ambiguous(self) -> None:
        """Report a scope property set from runtime formatted text."""
        scope = analyze_msi_scope({
            "Property": [{"Property": "ALLUSERS", "Value": "2"}],
            "CustomAction": [{
                "Action": "SetChoice", "Type": 51,
                "Source": "MSIINSTALLPERUSER", "Target": "[CHOSEN_SCOPE]",
            }],
        })

        self.assertEqual(scope.kind, "ambiguous")
        self.assertIn("formatted value", scope.conflicts[0].message)

    def test_ignored_msiinstallperuser_property_is_reported(self) -> None:
        """Explain why MSIINSTALLPERUSER cannot override ALLUSERS=1."""
        scope = analyze_msi_scope({"Property": [
            {"Property": "ALLUSERS", "Value": "1"},
            {"Property": "MSIINSTALLPERUSER", "Value": "1"},
        ]})

        self.assertEqual(scope.kind, "ambiguous")
        self.assertIn("ignored unless ALLUSERS=2", scope.conflicts[0].message)

    def test_ignored_matching_per_user_preference_has_no_conflict(self) -> None:
        """Keep an ignored preference from masquerading as mixed scope."""
        scope = analyze_msi_scope({"Property": [
            {"Property": "MSIINSTALLPERUSER", "Value": "1"},
        ]})

        self.assertEqual(scope, InstallationScope("per-user"))

    def test_conditional_component_does_not_imply_fixed_scope(self) -> None:
        """Avoid asserting a fixed install destination for conditional rows."""
        scope = analyze_msi_scope({
            "Property": [{"Property": "ALLUSERS", "Value": "2"}],
            "Component": [{
                "Component": "UserOnly", "Directory_": "AppDataFolder",
                "Condition": "NOT ALLUSERS",
            }],
        })

        self.assertEqual(scope, InstallationScope("dual-purpose"))

    def test_inspector_reads_scope_tables_from_package(self) -> None:
        """Use the cross-platform MSI database reader for each required table."""
        rows = {
            "Property": [{"Property": "ALLUSERS", "Value": "1"}],
            "Directory": [], "Registry": [], "Component": [], "Shortcut": [],
            "CustomAction": [],
        }
        package = MagicMock()
        package.get.side_effect = lambda name: SimpleNamespace(iter=lambda: rows[name])
        package_context = MagicMock()
        package_context.__enter__.return_value = package

        with patch("whatyouship.inspectors.msi_scope.pymsi.Package", return_value=package_context) as open_package:
            scope = MsiScopeInspector().inspect(Path("release.msi"))

        self.assertEqual(scope, InstallationScope("per-machine"))
        self.assertEqual(package.get.call_count, 6)
        open_package.assert_called_once_with(Path("release.msi"))


if __name__ == "__main__":
    unittest.main()
