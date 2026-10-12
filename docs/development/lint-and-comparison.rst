.. _lint-and-comparison-architecture:

Lint and comparison
===================

Lint policy
-----------

``LintRule`` is the internal structural protocol: a rule checks one
``ReleaseArtifact`` and returns findings. ``LintEngine`` runs an ordered rule
list. ``LintConfiguration.rules()`` constructs the enabled built-in rule
objects with configured severity and extensions; the public operation does not
accept an arbitrary rule list.

Baseline matching uses ``(rule_id, relative_path, identity)``. Identity captures
the stable cause—such as an extension, entitlement key, runtime path, signature
state, or bundle issue. Severity and human message are intentionally excluded,
so wording or policy-level changes do not make the same issue appear new.

Comparison
----------

``compare_artifacts`` indexes files by relative path and first classifies
added, removed, changed, and unchanged content. It then compares supported
format-neutral semantic fields: binary and signature metadata, bundles,
symbolic links, artifact signature, and installation scope.
``SemanticDifference`` can mark a change potentially dangerous and attach a
warning/severity, but comparison remains descriptive rather than a lint gate.

Binary diagnostics are carried on the old and new artifacts. They are neither
findings nor semantic differences because a parse failure is evidence of
incomplete analysis, not proof that the shipped product is defective.

Presentation
------------

Operations construct report objects; renderers contain no policy decisions.
Text emphasizes review, JSON projects a versioned machine contract, and CSV is
deliberately partial. CLI exit-code selection occurs after lint returns and
uses current findings or only ``baseline_comparison.new``.
