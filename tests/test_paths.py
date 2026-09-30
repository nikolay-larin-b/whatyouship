# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for user-specific WhatYouShip data paths and cache scopes."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from whatyouship.paths import (
    cache_directory,
    cache_root_directory,
    cache_scope,
    config_directory,
    user_data_directory,
)


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

    def test_temporary_cache_scope_is_removed_on_exit(self) -> None:
        """Use and remove a command-scoped cache instead of persistent data."""
        with cache_scope(persistent=False):
            root = cache_root_directory()
            entry = cache_directory("zip") / "entry"
            entry.mkdir(parents=True)
            self.assertTrue(entry.is_dir())
            self.assertEqual(root.name.split("-")[0], "whatyouship")

        self.assertFalse(root.exists())

    def test_persistent_cache_scope_keeps_user_cache_root(self) -> None:
        """Keep the home-relative cache when persistent caching is requested."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            home = Path(temporary_directory)
            with (
                patch("whatyouship.paths.Path.home", return_value=home),
                cache_scope(persistent=True),
            ):
                self.assertEqual(
                    cache_root_directory(), home / ".whatyouship" / "cache"
                )


if __name__ == "__main__":
    unittest.main()
