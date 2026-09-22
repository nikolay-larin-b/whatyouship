# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for user-specific WhatYouShip data paths."""

import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.paths import cache_directory, config_directory, user_data_directory


class UserDataPathTests(unittest.TestCase):
    """Verify the platform-independent home-relative data layout."""

    def test_user_data_layout_is_rooted_below_home(self) -> None:
        """Place caches and configuration below ``~/.whatyouship``."""
        home = Path("/users/example")

        with patch("whatyouship.paths.Path.home", return_value=home):
            self.assertEqual(user_data_directory(), home / ".whatyouship")
            self.assertEqual(
                cache_directory("msi"),
                home / ".whatyouship" / "cache" / "msi" / "v1",
            )
            self.assertEqual(
                cache_directory("zip"),
                home / ".whatyouship" / "cache" / "zip" / "v1",
            )
            self.assertEqual(
                config_directory(), home / ".whatyouship" / "config"
            )


if __name__ == "__main__":
    unittest.main()
