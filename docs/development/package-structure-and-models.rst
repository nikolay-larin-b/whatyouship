.. _package-structure:

Package structure and models
============================

Top-level modules
-----------------

``operations.py`` is the canonical application service for inspect, lint, and
compare. ``cli.py`` adapts it to ``argparse`` and renderers. ``report.py`` wraps
operation results. ``model.py`` defines format-neutral artifact records.
``config.py`` validates TOML and constructs built-in rules. ``lint.py`` defines
the rule protocol, engine, and baseline comparison; ``compare.py`` implements
release comparison. ``exceptions.py`` defines expected public failures.

``paths.py`` supplies temporary or persistent cache scopes, while ``cache.py``
implements user-facing persistent-cache inspection and cleanup.
``external_tools.py`` and ``macos_tools.py`` centralize executable discovery and
macOS command execution.

Packages
--------

``inspectors`` contains artifact detection, extraction backends, signature
adapters, and cache layouts. ``binary`` contains PE and Mach-O parsers plus the
internal per-file ``BinaryAnalysisError``. ``rules`` contains the built-in
lint policy. ``renderers`` converts reports to text, JSON, or CSV.

The central model
-----------------

``ReleaseArtifact`` is the boundary between acquisition and analysis policy.
It holds the source path; ``ArtifactFile`` inventory; outer
``ArtifactSignature``; app bundles; symbolic links; optional MSI
``InstallationScope``; optional license-agreement presence; and
``BinaryAnalysisDiagnostic`` records.

``ArtifactFile.binary`` optionally points to ``BinaryMetadata``. That record is
shared by PE and Mach-O and carries format, architecture, kind, versions,
dependencies, runtime paths, and optional ``SignatureMetadata``. Unsupported
metadata remains optional rather than adding backend-specific subclasses.

``Finding`` is policy output. Its rule ID, relative path, and identity form the
baseline key; its message and severity explain the current policy result.
``InspectReport``, ``LintReport``, and ``CompareReport`` keep operation context
together for renderers and Python callers.

Public boundary
---------------

The selected objects in :doc:`../python-api/index` are public but experimental
until 1.0. Importable helpers such as ``inspect_artifact``, ``LintEngine``,
individual rules, concrete inspectors, and cache implementations remain
internal. Availability for import is not a compatibility promise.
