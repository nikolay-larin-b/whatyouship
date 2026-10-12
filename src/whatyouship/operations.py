# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Provide the experimental high-level Python API for artifact operations."""

from collections.abc import Iterator
from contextlib import contextmanager
from os import PathLike
from pathlib import Path

from whatyouship.compare import compare_artifacts
from whatyouship.config import LintConfiguration, load_config
from whatyouship.exceptions import (
    ArtifactInspectionError,
    ArtifactNotFoundError,
    ConfigurationError,
    WhatYouShipError,
)
from whatyouship.inspectors import inspect_artifact
from whatyouship.lint import LintEngine, compare_findings
from whatyouship.model import ReleaseArtifact
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


@contextmanager
def _operation_scope(persistent: bool) -> Iterator[None]:
    """Manage an operation cache and normalize expected filesystem failures.

    :param persistent: Whether to use the persistent user cache.
    :yields: Control while the operation cache is active.
    :raises ArtifactInspectionError: If the cache cannot be created or cleaned up.
    """
    try:
        with _operation_cache_scope(persistent=persistent):
            yield
    except WhatYouShipError:
        raise
    except OSError as error:
        raise ArtifactInspectionError(
            f"Unable to access the artifact extraction cache: {error}"
        ) from error


def _inspect_source(source: _ArtifactPath) -> ReleaseArtifact:
    """Inspect one source while normalizing expected filesystem errors.

    :param source: Artifact path accepted by the public API.
    :returns: Inspected release artifact.
    :raises WhatYouShipError: If the artifact cannot be inspected.
    """
    try:
        return inspect_artifact(source)
    except WhatYouShipError:
        raise
    except FileNotFoundError as error:
        raise ArtifactNotFoundError(str(error)) from error
    except OSError as error:
        raise ArtifactInspectionError(
            f"Unable to inspect artifact '{source}': {error}"
        ) from error


def _lint_configuration(
    config: _LintConfigurationInput | None,
) -> LintConfiguration:
    """Resolve a prepared or file-backed lint configuration.

    :param config: Prepared settings, an explicit TOML path, or ``None``.
    :returns: Validated lint configuration.
    :raises ConfigurationError: If an explicit configuration cannot be loaded.
    """
    if config is None:
        return LintConfiguration()
    if isinstance(config, LintConfiguration):
        return config
    config_path = _path(config)
    try:
        return load_config(config_path)
    except (OSError, ValueError) as error:
        raise ConfigurationError(str(error)) from error


def inspect(source: _ArtifactPath, *, cache: bool = False) -> InspectReport:
    """Inspect one release artifact without producing command-line output.

    A temporary extraction cache is created and removed for this operation by
    default. Set ``cache`` to ``True`` to reuse the persistent user cache. An
    explicitly active outer cache scope is reused when ``cache`` is ``False``.

    :param source: Directory or supported release artifact to inspect.
    :param cache: Whether to use the persistent user cache.
    :returns: Structured inspection report.
    :raises WhatYouShipError: If the artifact cannot be inspected.
    """
    with _operation_scope(persistent=cache):
        return InspectReport(_inspect_source(source))


def lint(
    source: _ArtifactPath,
    *,
    baseline: _ArtifactPath | None = None,
    config: _LintConfigurationInput | None = None,
    cache: bool = False,
) -> LintReport:
    """Inspect and lint one release artifact without command-line output.

    ``config`` may be a prepared
    :class:`whatyouship.config.LintConfiguration` or an explicit TOML
    configuration path. When ``baseline`` is supplied, its findings are
    classified as new, existing, and resolved relative to the current artifact.

    :param source: Directory or supported release artifact to lint.
    :param baseline: Previous artifact used to classify findings.
    :param config: Lint settings or path to a TOML configuration file.
    :param cache: Whether to use the persistent user cache.
    :returns: Structured lint report, including baseline results when requested.
    :raises WhatYouShipError: If an artifact or configuration cannot be processed.
    """
    with _operation_scope(persistent=cache):
        artifact = _inspect_source(source)
        baseline_artifact = (
            _inspect_source(baseline) if baseline is not None else None
        )
        configuration = _lint_configuration(config)
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
    :raises WhatYouShipError: If either artifact cannot be inspected.
    """
    with _operation_scope(persistent=cache):
        old_artifact = _inspect_source(old_source)
        new_artifact = _inspect_source(new_source)
        return CompareReport(
            old_artifact,
            new_artifact,
            compare_artifacts(old_artifact, new_artifact),
        )
