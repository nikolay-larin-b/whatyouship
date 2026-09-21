# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Structured results shared by report renderers."""

from dataclasses import dataclass

from whatyouship.compare import ComparisonResult
from whatyouship.lint import BaselineComparison
from whatyouship.model import Finding, ReleaseArtifact


@dataclass
class InspectReport:
    """Hold a release artifact for inspection output.

    :param artifact: Inspected release artifact.
    """

    artifact: ReleaseArtifact


@dataclass
class LintReport:
    """Hold current findings and optional baseline results.

    :param artifact: Current release artifact.
    :param findings: Findings from the current artifact.
    :param baseline_artifact: Previous release artifact, when supplied.
    :param baseline_comparison: Categorized findings, when a baseline is supplied.
    """

    artifact: ReleaseArtifact
    findings: list[Finding]
    baseline_artifact: ReleaseArtifact | None = None
    baseline_comparison: BaselineComparison | None = None


@dataclass
class CompareReport:
    """Hold two artifacts and their comparison.

    :param old_artifact: Earlier release artifact.
    :param new_artifact: Later release artifact.
    :param comparison: Classified file and semantic differences.
    """

    old_artifact: ReleaseArtifact
    new_artifact: ReleaseArtifact
    comparison: ComparisonResult


Report = InspectReport | LintReport | CompareReport
