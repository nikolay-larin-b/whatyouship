# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Command-line entry point for WhatYouShip."""

import argparse
from pathlib import Path
from typing import Literal

from whatyouship import __version__
from whatyouship.compare import compare_artifacts
from whatyouship.config import LintConfiguration, load_config
from whatyouship.inspectors import inspect_artifact
from whatyouship.lint import LintEngine, compare_findings
from whatyouship.model import Finding
from whatyouship.report import CompareReport, InspectReport, LintReport, Report
from whatyouship.renderers import OutputFormat, render_report


_OUTPUT_FORMATS: dict[str, OutputFormat] = {
    ".txt": "text",
    ".json": "json",
    ".csv": "csv",
}
FailThreshold = Literal["error", "warning", "never"]


class _WhatYouShipArgumentParser(argparse.ArgumentParser):
    """Add project identity above standard command help."""

    def format_help(self) -> str:
        """Prepend the version, copyright, and tagline to command help.

        :returns: Complete command help text.
        """
        banner = (
            f"WhatYouShip {__version__}\n"
            "Copyright (c) 2026 Nikolay Larin\n"
            "\n"
            "Know what you ship. Know what you install.\n"
            "\n"
        )
        return banner + super().format_help()


def _output_format(path: Path | None, command: str) -> OutputFormat:
    """Select the output format from a requested file extension.

    :param path: Output file, or ``None`` for console text.
    :param command: CLI command being rendered.
    :returns: Selected renderer format.
    :raises ValueError: If the extension or command-format pair is unsupported.
    """
    if path is None:
        return "text"
    output_format = _OUTPUT_FORMATS.get(path.suffix.lower())
    if output_format is None:
        raise ValueError(
            f"Unsupported output file extension: {path.suffix or '(none)'}"
        )
    if output_format == "csv" and command == "compare":
        raise ValueError("CSV output is not supported for compare")
    return output_format


def _lint_exit_code(findings: list[Finding], fail_on: FailThreshold) -> int:
    """Decide whether eligible lint findings fail the release gate.

    :param findings: Current findings, or only new findings with a baseline.
    :param fail_on: Minimum severity that fails lint, or ``never``.
    :returns: One when the threshold is reached, otherwise zero.
    """
    if fail_on == "never":
        return 0
    if fail_on == "warning":
        return int(bool(findings))
    return int(any(finding.severity == "error" for finding in findings))


def main(argv: list[str] | None = None) -> int:
    """Run the WhatYouShip command-line interface.

    :param argv: Arguments to parse, or ``None`` to use command-line arguments.
    :returns: One when lint findings reach the threshold, otherwise zero.
    :raises SystemExit: When help or version is requested, or an error occurs.
    """
    parser = _WhatYouShipArgumentParser(
        prog="whatyouship",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Command-specific help:\n"
            "  `whatyouship inspect --help`\n"
            "  `whatyouship lint --help`\n"
            "  `whatyouship compare --help`\n"
            "\n"
            "Report output:\n"
            "  Use `-o/--output <file>`; the extension selects the format.\n"
            "  `.txt`   Text report for inspect, lint, and compare.\n"
            "  `.json`  JSON report for inspect, lint, and compare.\n"
            "  `.csv`   CSV report for inspect and lint."
        ),
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a release artifact.")
    inspect_parser.add_argument("artifact", type=Path, help="Directory, MSI, or ZIP to inspect.")
    inspect_parser.add_argument("-o", "--output", type=Path, help="Write a .txt, .json, or .csv report.")
    lint_parser = subparsers.add_parser("lint", help="Lint a release artifact.")
    lint_parser.add_argument("artifact", type=Path, help="Directory, MSI, or ZIP to lint.")
    lint_parser.add_argument("-o", "--output", type=Path, help="Write a .txt, .json, or .csv report.")
    lint_parser.add_argument(
        "--baseline", type=Path, help="Previous directory, MSI, or ZIP for finding comparison."
    )
    lint_parser.add_argument(
        "--config", type=Path, help="TOML file with lint rule settings."
    )
    lint_parser.add_argument(
        "--fail-on", choices=("error", "warning", "never"), default="error",
        help="Minimum lint severity that fails the command (default: error).",
    )
    compare_parser = subparsers.add_parser("compare", help="Compare two release artifacts.")
    compare_parser.add_argument("old_artifact", type=Path, help="Earlier directory, MSI, or ZIP.")
    compare_parser.add_argument("new_artifact", type=Path, help="Later directory, MSI, or ZIP.")
    compare_parser.add_argument("-o", "--output", type=Path, help="Write a .txt or .json report.")

    args = parser.parse_args(argv)
    exit_code = 0
    try:
        output_format = _output_format(args.output, args.command)
        if args.command == "compare":
            old_artifact = inspect_artifact(args.old_artifact)
            new_artifact = inspect_artifact(args.new_artifact)
            report: Report = CompareReport(
                old_artifact, new_artifact, compare_artifacts(old_artifact, new_artifact)
            )
        else:
            artifact = inspect_artifact(args.artifact)
            if args.command == "inspect":
                report = InspectReport(artifact)
            else:
                baseline_artifact = (
                    inspect_artifact(args.baseline) if args.baseline is not None else None
                )
                configuration = (
                    load_config(args.config)
                    if args.config is not None else LintConfiguration()
                )
                engine = LintEngine(configuration.rules())
                findings = engine.run(artifact)
                baseline_comparison = (
                    compare_findings(engine.run(baseline_artifact), findings)
                    if baseline_artifact is not None else None
                )
                report = LintReport(
                    artifact, findings, baseline_artifact, baseline_comparison
                )
                eligible_findings = (
                    baseline_comparison.new
                    if baseline_comparison is not None else findings
                )
                exit_code = _lint_exit_code(eligible_findings, args.fail_on)
        rendered = render_report(report, output_format)
        if args.output is None:
            print(rendered, end="")
        else:
            args.output.write_text(rendered, encoding="utf-8")
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
