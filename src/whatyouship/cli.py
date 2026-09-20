# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Command-line entry point for WhatYouShip."""

import argparse
from pathlib import Path

from whatyouship import __version__
from whatyouship.inspectors import inspect_artifact
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
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a release artifact.")
    inspect_parser.add_argument("artifact", type=Path, help="Directory or MSI to inspect.")
    lint_parser = subparsers.add_parser("lint", help="Lint a release artifact.")
    lint_parser.add_argument("artifact", type=Path, help="Directory or MSI to lint.")

    args = parser.parse_args(argv)
    try:
        artifact = inspect_artifact(args.artifact)
    except (OSError, ValueError) as error:
        parser.error(str(error))

    if args.command == "inspect":
        print(f"Source: {artifact.source_path}")
        print(f"Files: {len(artifact.files)}")
        print(f"Total size: {sum(file.size_bytes for file in artifact.files)} bytes")
        print()
        print("Relative path | Size (bytes) | SHA-256")
        for file in artifact.files:
            print(f"{file.relative_path} | {file.size_bytes} | {file.sha256}")
            if file.binary is not None:
                details = [
                    file.binary.format,
                    f"Architecture: {file.binary.architecture}",
                    f"Kind: {file.binary.kind}",
                ]
                if file.binary.file_version is not None:
                    details.append(f"File version: {file.binary.file_version}")
                if file.binary.product_version is not None:
                    details.append(f"Product version: {file.binary.product_version}")
                print("  Binary: " + " | ".join(details))
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
