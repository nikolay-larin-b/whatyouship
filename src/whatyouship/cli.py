# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Command-line entry point for WhatYouShip."""

import argparse
from pathlib import Path

from whatyouship import __version__
from whatyouship.inspectors.directory import DirectoryInspector
from whatyouship.lint import LintEngine
from whatyouship.rules.build_artifacts import BuildArtifactRule


def main(argv: list[str] | None = None) -> int:
    """Run the WhatYouShip command-line interface.

    :param argv: Arguments to parse, or ``None`` to use command-line arguments.
    :returns: Zero when the requested command completes successfully.
    :raises SystemExit: When help or version is requested, or an error occurs.
    """
    parser = argparse.ArgumentParser(
        prog="whatyouship",
        description="Know what you ship. Know what you install.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a directory artifact.")
    inspect_parser.add_argument("directory", type=Path, help="Directory to inspect.")
    lint_parser = subparsers.add_parser("lint", help="Lint a directory artifact.")
    lint_parser.add_argument("directory", type=Path, help="Directory to lint.")

    args = parser.parse_args(argv)
    try:
        artifact = DirectoryInspector().inspect(args.directory)
    except OSError as error:
        parser.error(str(error))

    if args.command == "inspect":
        print(f"Source: {artifact.source_path}")
        print(f"Files: {len(artifact.files)}")
        print(f"Total size: {sum(file.size_bytes for file in artifact.files)} bytes")
        print()
        print("Relative path | Size (bytes) | SHA-256")
        for file in artifact.files:
            print(f"{file.relative_path} | {file.size_bytes} | {file.sha256}")
        return 0

    findings = LintEngine([BuildArtifactRule()]).run(artifact)
    if not findings:
        print("No findings.")
    else:
        for finding in findings:
            print(
                f"{finding.rule_id} | {finding.severity} | "
                f"{finding.relative_path} | {finding.message}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
