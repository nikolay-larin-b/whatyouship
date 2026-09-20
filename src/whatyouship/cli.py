# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Command-line entry point for WhatYouShip."""

import argparse

from whatyouship import __version__


def main(argv: list[str] | None = None) -> int:
    """Run the WhatYouShip command-line interface.

    :param argv: Arguments to parse, or ``None`` to use command-line arguments.
    :returns: Zero when argument parsing completes successfully.
    :raises SystemExit: When help or version is requested, or parsing fails.
    """
    parser = argparse.ArgumentParser(
        prog="whatyouship",
        description="Know what you ship. Know what you install.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
