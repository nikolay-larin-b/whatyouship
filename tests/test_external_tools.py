# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for external-tool discovery and installation guidance."""

import unittest
from unittest.mock import Mock, patch

from whatyouship.external_tools import (
    INNOEXTRACT,
    SEVEN_ZIP,
    find_external_tool,
)


class ExternalToolTests(unittest.TestCase):
    """Verify lookup order and platform-specific missing-tool errors."""

    def test_returns_first_available_supported_executable(self) -> None:
        """Try executable names in their declared order."""
        which = Mock(side_effect=[None, "/usr/bin/7z"])

        executable = find_external_tool(SEVEN_ZIP, "inspect a release", which)

        self.assertEqual(executable, "/usr/bin/7z")
        self.assertEqual(
            [call.args[0] for call in which.call_args_list],
            ["7zz", "7z"],
        )

    def test_windows_error_uses_official_download_page(self) -> None:
        """Direct Windows users to the tool's official distribution page."""
        with (
            patch("whatyouship.external_tools.sys.platform", "win32"),
            self.assertRaises(FileNotFoundError) as raised,
        ):
            find_external_tool(INNOEXTRACT, "extract an installer", Mock(return_value=None))

        message = str(raised.exception)
        self.assertIn("required to extract an installer", message)
        self.assertIn("https://constexpr.org/innoextract/", message)
        self.assertIn("'innoextract' is available in PATH", message)

    def test_macos_error_uses_homebrew_formula(self) -> None:
        """Provide the supported Homebrew command on macOS."""
        with (
            patch("whatyouship.external_tools.sys.platform", "darwin"),
            self.assertRaises(FileNotFoundError) as raised,
        ):
            find_external_tool(SEVEN_ZIP, "extract an installer", Mock(return_value=None))

        self.assertIn("brew install sevenzip", str(raised.exception))

    def test_linux_error_uses_distribution_package_manager(self) -> None:
        """Select commands for supported Linux distribution families."""
        cases = (
            ({"ID": "ubuntu", "ID_LIKE": "debian"}, "sudo apt install 7zip"),
            ({"ID": "fedora"}, "sudo dnf install 7zip"),
            ({"ID": "manjaro", "ID_LIKE": "arch"}, "sudo pacman -S 7zip"),
        )
        for release, expected in cases:
            with self.subTest(release=release), patch(
                "whatyouship.external_tools.sys.platform", "linux"
            ), patch(
                "whatyouship.external_tools.platform.freedesktop_os_release",
                return_value=release,
            ), self.assertRaises(FileNotFoundError) as raised:
                find_external_tool(
                    SEVEN_ZIP,
                    "extract an installer",
                    Mock(return_value=None),
                )

            self.assertIn(expected, str(raised.exception))

    def test_unknown_linux_error_names_package(self) -> None:
        """Keep Linux guidance useful when distribution detection fails."""
        with (
            patch("whatyouship.external_tools.sys.platform", "linux"),
            patch(
                "whatyouship.external_tools.platform.freedesktop_os_release",
                side_effect=OSError,
            ),
            self.assertRaises(FileNotFoundError) as raised,
        ):
            find_external_tool(INNOEXTRACT, "extract an installer", Mock(return_value=None))

        self.assertIn("system package manager", str(raised.exception))
        self.assertIn("package: innoextract", str(raised.exception))

