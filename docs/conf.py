# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Sphinx configuration for the WhatYouShip documentation."""

from whatyouship import __version__


project = "WhatYouShip"
copyright = "2026, Nikolay Larin"
author = "Nikolay Larin"

release = __version__

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.viewcode",
]

autosummary_generate = True
autodoc_typehints = "description"
nitpicky = True
nitpick_ignore_regex = [
    ("py:class", r"(?:datetime\.datetime|os\.PathLike|pathlib\.Path)"),
]
html_title = f"WhatYouShip {release} documentation"
