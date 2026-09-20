# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Apply lint rules to release artifacts."""

from collections.abc import Iterable
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
