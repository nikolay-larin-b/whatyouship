# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Apply lint rules to release artifacts."""

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol

from whatyouship.model import Finding, ReleaseArtifact


class LintRule(Protocol):
    """Define the interface for a release artifact lint rule."""

    def check(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Report findings for a release artifact.

        :param artifact: Artifact to check.
        :returns: Findings produced by this rule.
        """
        ...


class LintEngine:
    """Apply a supplied set of lint rules to an artifact."""

    def __init__(self, rules: Iterable[LintRule]) -> None:
        """Store the rules to apply.

        :param rules: Rules to run in the supplied order.
        """
        self._rules = tuple(rules)

    def run(self, artifact: ReleaseArtifact) -> list[Finding]:
        """Collect findings from every rule.

        :param artifact: Artifact to lint.
        :returns: Findings in rule order.
        """
        return [finding for rule in self._rules for finding in rule.check(artifact)]


@dataclass
class BaselineComparison:
    """Group current and previous lint findings by their baseline status.

    :param existing: Findings present in both artifacts.
    :param new: Findings present only in the current artifact.
    :param resolved: Findings present only in the previous artifact.
    """

    existing: list[Finding] = field(default_factory=list)
    new: list[Finding] = field(default_factory=list)
    resolved: list[Finding] = field(default_factory=list)


def compare_findings(
    previous: Iterable[Finding], current: Iterable[Finding]
) -> BaselineComparison:
    """Compare lint findings by rule ID and relative file path.

    :param previous: Findings from the baseline artifact.
    :param current: Findings from the current artifact.
    :returns: Existing, new, and resolved findings in stable key order.
    """
    previous_by_key = {
        (finding.rule_id, finding.relative_path): finding for finding in previous
    }
    current_by_key = {
        (finding.rule_id, finding.relative_path): finding for finding in current
    }
    previous_keys = previous_by_key.keys()
    current_keys = current_by_key.keys()
    return BaselineComparison(
        existing=[current_by_key[key] for key in sorted(previous_keys & current_keys)],
        new=[current_by_key[key] for key in sorted(current_keys - previous_keys)],
        resolved=[previous_by_key[key] for key in sorted(previous_keys - current_keys)],
    )
