# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Provide the experimental high-level Python API for artifact operations."""

from os import PathLike
from pathlib import Path

from whatyouship.compare import compare_artifacts
from whatyouship.config import LintConfiguration, load_config
from whatyouship.inspectors import inspect_artifact
from whatyouship.lint import LintEngine, compare_findings
from whatyouship.paths import _operation_cache_scope
from whatyouship.report import CompareReport, InspectReport, LintReport


__all__ = ["compare", "inspect", "lint"]

_ArtifactPath = str | PathLike[str]
_LintConfigurationInput = LintConfiguration | _ArtifactPath


def _path(value: _ArtifactPath) -> Path:
    """Convert a public path input to the internal path representation.

    :param value: String or path-like artifact path.
    :returns: Equivalent :class:`pathlib.Path`.
    """
    return Path(value)


def inspect(source: _ArtifactPath, *, cache: bool = False) -> InspectReport:
    """Inspect one release artifact without producing command-line output.

    A temporary extraction cache is created and removed for this operation by
    default. Set ``cache`` to ``True`` to reuse the persistent user cache. An
    explicitly active outer cache scope is reused when ``cache`` is ``False``.

    :param source: Directory or supported release artifact to inspect.
    :param cache: Whether to use the persistent user cache.
    :returns: Structured inspection report.
    :raises FileNotFoundError: If the artifact does not exist.
    :raises ValueError: If the artifact is unsupported or cannot be inspected.
    """
    with _operation_cache_scope(persistent=cache):
        return InspectReport(inspect_artifact(_path(source)))


def lint(
    source: _ArtifactPath,
    *,
    baseline: _ArtifactPath | None = None,
    config: _LintConfigurationInput | None = None,
    cache: bool = False,
) -> LintReport:
    """Inspect and lint one release artifact without command-line output.

    ``config`` may be a prepared :class:`LintConfiguration` or an explicit TOML
    configuration path. When ``baseline`` is supplied, its findings are
    classified as new, existing, and resolved relative to the current artifact.

    :param source: Directory or supported release artifact to lint.
    :param baseline: Previous artifact used to classify findings.
    :param config: Lint settings or path to a TOML configuration file.
    :param cache: Whether to use the persistent user cache.
    :returns: Structured lint report, including baseline results when requested.
    :raises FileNotFoundError: If an artifact or configuration file does not exist.
    :raises ValueError: If an artifact or configuration is invalid or unsupported.
    """
    with _operation_cache_scope(persistent=cache):
        artifact = inspect_artifact(_path(source))
        baseline_artifact = (
            inspect_artifact(_path(baseline)) if baseline is not None else None
        )
        if config is None:
            configuration = LintConfiguration()
        elif isinstance(config, LintConfiguration):
            configuration = config
        else:
            configuration = load_config(_path(config))
        engine = LintEngine(configuration.rules())
        findings = engine.run(artifact)
        baseline_comparison = (
            compare_findings(engine.run(baseline_artifact), findings)
            if baseline_artifact is not None
            else None
        )
        return LintReport(
            artifact,
            findings,
            baseline_artifact,
            baseline_comparison,
        )


def compare(
    old_source: _ArtifactPath,
    new_source: _ArtifactPath,
    *,
    cache: bool = False,
) -> CompareReport:
    """Inspect and compare two release artifacts without command-line output.

    Both artifacts share one operation cache so identical inputs or payloads can
    be reused during the comparison.

    :param old_source: Earlier directory or supported release artifact.
    :param new_source: Later directory or supported release artifact.
    :param cache: Whether to use the persistent user cache.
    :returns: Structured comparison report.
    :raises FileNotFoundError: If either artifact does not exist.
    :raises ValueError: If either artifact is unsupported or cannot be inspected.
    """
    with _operation_cache_scope(persistent=cache):
        old_artifact = inspect_artifact(_path(old_source))
        new_artifact = inspect_artifact(_path(new_source))
        return CompareReport(
            old_artifact,
            new_artifact,
            compare_artifacts(old_artifact, new_artifact),
        )
