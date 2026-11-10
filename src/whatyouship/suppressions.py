# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Match explicit lint exceptions against artifact-relative finding paths."""

from collections.abc import Iterable
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import lru_cache

from whatyouship.model import Finding
from whatyouship.rules import RULE_IDS


@lru_cache(maxsize=4096)
def _match_parts(pattern: tuple[str, ...], path: tuple[str, ...]) -> bool:
    """Match complete path segments without host-dependent case folding.

    :param pattern: Pattern segments with ``*`` and standalone ``**`` support.
    :param path: Artifact-relative path segments.
    :returns: Whether every path segment matches the pattern.
    """
    if not pattern:
        return not path
    if pattern[0] == "**":
        return _match_parts(pattern[1:], path) or (
            bool(path) and _match_parts(pattern, path[1:])
        )
    return bool(path) and fnmatchcase(path[0], pattern[0]) and _match_parts(
        pattern[1:], path[1:]
    )


@dataclass(frozen=True)
class IgnoreSettings:
    """Suppress one rule at an exact artifact-relative path or path pattern.

    :param rule: Built-in rule ID to suppress.
    :param path: Case-sensitive POSIX path, using ``*`` within a segment and
        standalone ``**`` for zero or more segments. Use ``.`` for the artifact.
    :param reason: Optional explanation retained in structured reports.
    :raises ValueError: If the rule, path pattern, or reason is invalid.
    """

    rule: str
    path: str
    reason: str | None = None

    def __post_init__(self) -> None:
        """Validate typed settings using the same constraints as TOML input.

        :raises ValueError: If an exception contains unsupported values.
        """
        if not isinstance(self.rule, str) or self.rule not in RULE_IDS:
            raise ValueError(f"Unknown ignore rule ID: {self.rule!r}")
        if not isinstance(self.path, str) or not self.path:
            raise ValueError("Ignore path must be a non-empty string")
        parts = self.path.split("/")
        if self.path != "." and (
            any(part in ("", ".", "..") for part in parts)
            or any(character in self.path for character in "\\:?[]{}")
            or any(ord(character) < 32 for character in self.path)
            or any("**" in part and part != "**" for part in parts)
        ):
            raise ValueError(
                "Ignore path must be '.' or a relative POSIX path with only "
                "'*' and standalone '**' wildcards"
            )
        if self.reason is not None and not isinstance(self.reason, str):
            raise ValueError("Ignore reason must be a string")

    def matches(self, finding: Finding) -> bool:
        """Check both rule ID and the entire artifact-relative path.

        :param finding: Finding to check against this exception.
        :returns: Whether this exception suppresses the finding.
        """
        path = finding.relative_path.as_posix()
        if self.rule != finding.rule_id:
            return False
        if path == "." or self.path == ".":
            return path == self.path
        return _match_parts(tuple(self.path.split("/")), tuple(path.split("/")))


@dataclass(frozen=True)
class SuppressedFinding:
    """Retain a finding together with the first exception that matched it.

    :param finding: Original finding, including its stable identity.
    :param ignore: Matching exception and its optional explanation.
    """

    finding: Finding
    ignore: IgnoreSettings


def suppress_findings(
    findings: Iterable[Finding], ignores: Iterable[IgnoreSettings]
) -> tuple[list[Finding], list[SuppressedFinding]]:
    """Separate active findings from explicit exceptions in original order.

    :param findings: Findings returned by enabled lint rules.
    :param ignores: Exceptions in configuration order; first match wins.
    :returns: Active findings and separately retained suppressed findings.
    """
    settings = tuple(ignores)
    active = []
    suppressed = []
    for finding in findings:
        match = next((ignore for ignore in settings if ignore.matches(finding)), None)
        if match is None:
            active.append(finding)
        else:
            suppressed.append(SuppressedFinding(finding, match))
    return active, suppressed
