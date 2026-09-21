# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Command-line entry point for WhatYouShip."""

import argparse
from pathlib import Path

from whatyouship import __version__
from whatyouship.compare import compare_artifacts
from whatyouship.config import LintConfiguration, load_config
from whatyouship.inspectors import inspect_artifact
from whatyouship.lint import LintEngine, compare_findings


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
    lint_parser.add_argument(
        "--baseline", type=Path, help="Previous directory or MSI for finding comparison."
    )
    lint_parser.add_argument(
        "--config", type=Path, help="TOML file with lint rule settings."
    )
    compare_parser = subparsers.add_parser("compare", help="Compare two release artifacts.")
    compare_parser.add_argument("old_artifact", type=Path, help="Earlier directory or MSI.")
    compare_parser.add_argument("new_artifact", type=Path, help="Later directory or MSI.")

    args = parser.parse_args(argv)
    try:
        if args.command == "compare":
            old_artifact = inspect_artifact(args.old_artifact)
            new_artifact = inspect_artifact(args.new_artifact)
        else:
            artifact = inspect_artifact(args.artifact)
            if args.command == "lint" and args.baseline is not None:
                baseline_artifact = inspect_artifact(args.baseline)
            if args.command == "lint":
                configuration = (
                    load_config(args.config)
                    if args.config is not None else LintConfiguration()
                )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    if args.command == "compare":
        comparison = compare_artifacts(old_artifact, new_artifact)
        print(f"Old: {old_artifact.source_path}")
        print(f"New: {new_artifact.source_path}")
        print(f"Added: {len(comparison.added)}")
        print(f"Removed: {len(comparison.removed)}")
        print(f"Changed: {len(comparison.changed)}")
        print(f"Unchanged: {len(comparison.unchanged)}")
        print(f"Semantic differences: {len(comparison.semantic_differences)}")
        for label, paths in (
            ("Added", comparison.added),
            ("Removed", comparison.removed),
            ("Changed", comparison.changed),
        ):
            if paths:
                print(f"\n{label} files:")
                for path in paths:
                    print(f"  {path}")
        if comparison.semantic_differences:
            print("\nSemantic differences:")
            for difference in comparison.semantic_differences:
                warning = (
                    " [POTENTIALLY DANGEROUS: signed -> unsigned]"
                    if difference.potentially_dangerous else ""
                )
                if difference.warning_message is not None:
                    warning += f" [WARNING: {difference.warning_message}]"
                print(
                    f"  {difference.relative_path} | {difference.field}: "
                    f"{difference.old_value} -> {difference.new_value}{warning}"
                )
        return 0

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
                if file.binary.signature is not None:
                    signature = file.binary.signature
                    if signature.present is None:
                        print("  Signature: unknown")
                    elif not signature.present:
                        print("  Signature: absent")
                    else:
                        validity = (
                            "unknown" if signature.valid is None else
                            "valid" if signature.valid else "invalid"
                        )
                        details = [validity]
                        if signature.signer is not None:
                            details.append(f"Signer: {signature.signer}")
                        if signature.timestamp is not None:
                            details.append(f"Timestamp: {'present' if signature.timestamp else 'absent'}")
                        print("  Signature: " + " | ".join(details))
        return 0

    engine = LintEngine(configuration.rules())
    findings = engine.run(artifact)
    if args.baseline is not None:
        baseline_findings = engine.run(baseline_artifact)
        comparison = compare_findings(baseline_findings, findings)
        print(f"New: {len(comparison.new)}")
        print(f"Existing: {len(comparison.existing)}")
        print(f"Resolved: {len(comparison.resolved)}")
        if comparison.new:
            print("\nNew findings:")
            for finding in comparison.new:
                print(
                    f"{finding.rule_id} | {finding.severity} | "
                    f"{finding.relative_path} | {finding.message}"
                )
        else:
            print("No new findings.")
        if comparison.resolved:
            print("\nResolved findings:")
            for finding in comparison.resolved:
                print(
                    f"{finding.rule_id} | {finding.severity} | "
                    f"{finding.relative_path} | {finding.message}"
                )
        return 0
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
