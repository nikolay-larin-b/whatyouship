.. _python-api-models:

Reports, models, and configuration
==================================

The object graph follows the operation result down to artifact data::

   InspectReport ── artifact ── ReleaseArtifact ── files / bundles / diagnostics
   LintReport ───── artifact + findings + optional baseline comparison
   CompareReport ── old/new artifacts + ComparisonResult

These dataclasses are the observable structured contract of the operations.
Lists are mutable and no immutability guarantee is made. Paths are
:class:`pathlib.Path` objects in Python even though JSON renders relative paths
with POSIX separators.

Reports
-------

.. autoclass:: whatyouship.report.InspectReport
   :members:

.. autoclass:: whatyouship.report.LintReport
   :members:

.. autoclass:: whatyouship.report.CompareReport
   :members:

Artifact data
-------------

.. autoclass:: whatyouship.model.ReleaseArtifact
   :members:

.. autoclass:: whatyouship.model.ArtifactFile
   :members:

.. autoclass:: whatyouship.model.BinaryAnalysisDiagnostic
   :members:

.. autoclass:: whatyouship.model.BinaryMetadata
   :members:

.. autoclass:: whatyouship.model.BinaryDependency
   :members:

.. autoclass:: whatyouship.model.BinaryEntitlement
   :members:

.. autoclass:: whatyouship.model.SignatureMetadata
   :members:

.. autoclass:: whatyouship.model.ArtifactSignature
   :members:

.. autoclass:: whatyouship.model.ArtifactSymbolicLink
   :members:

.. autoclass:: whatyouship.model.InstallationScope
   :members:

.. autoclass:: whatyouship.model.InstallationScopeConflict
   :members:

.. autoclass:: whatyouship.model.AppBundleMetadata
   :members:

.. autoclass:: whatyouship.model.BundleIssue
   :members:

.. autoclass:: whatyouship.model.Finding
   :members:

Lint and comparison results
---------------------------

.. autoclass:: whatyouship.lint.BaselineComparison
   :members:

.. autoclass:: whatyouship.compare.ComparisonResult
   :members:

.. autoclass:: whatyouship.compare.SemanticDifference
   :members:

Typed lint configuration
------------------------

Typed settings are frozen dataclasses. Their Python attributes map to the TOML
IDs documented in :ref:`configuration-reference`.

.. autoclass:: whatyouship.config.LintConfiguration

.. autoclass:: whatyouship.config.BuildArtifactSettings

.. autoclass:: whatyouship.config.UnsignedBinarySettings

.. autoclass:: whatyouship.config.AppBundleSettings

.. autoclass:: whatyouship.config.DebugEntitlementSettings

.. autoclass:: whatyouship.config.RuntimeSearchPathSettings

.. autoclass:: whatyouship.config.ArtifactSignatureRuleSettings

.. autoclass:: whatyouship.config.InstallationScopeSettings

.. autoclass:: whatyouship.config.LicenseAgreementSettings
