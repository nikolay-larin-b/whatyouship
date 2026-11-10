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

After rules run, ``suppress_findings`` separates active findings from targeted
exceptions in ``LintConfiguration.ignore``. It retains the first matching
``IgnoreSettings`` with each ``SuppressedFinding``. This happens independently
for current and baseline artifacts before baseline matching; exceptions do not
alter rules, artifact metadata, or binary diagnostics. Matching uses
case-sensitive POSIX path segments on every host.

Baseline matching uses ``(rule_id, relative_path, identity)``. Identity captures
the stable cause—such as an extension, entitlement key, runtime path, signature
state, or bundle issue. Severity and human message are intentionally excluded,
so wording or policy-level changes do not make the same issue appear new.

Runtime search path rules inspect the unique declared paths from
``runtime_search_paths`` and ``runtime_run_paths``, in first-occurrence order.
Both ELF tags are analyzed without choosing an effective loader path list or
expanding tokens against the host. The existing ``runtime-search-path:<path>``
identity is shared across tags, avoiding duplicate findings and artificial
baseline regressions when the same path moves between tags. ELF signature
metadata remains unavailable, so signature rules have no positive evidence for
unsigned, invalid, or untrusted findings.

Comparison
----------

``compare_artifacts`` indexes files by relative path and first classifies
added, removed, changed, and unchanged content. It then compares supported
format-neutral semantic fields: binary and signature metadata, bundles,
symbolic links, artifact signature, and installation scope.
``SemanticDifference`` can mark a change potentially dangerous and attach a
warning/severity, but comparison remains descriptive rather than a lint gate.

For ELF, binary comparison includes all kind transitions, separate RPATH and
RUNPATH lists, interpreter, and runtime library name. ELF dependency and path
sequences use JSON-array strings for unambiguous comparisons: ordering,
duplicates, empty elements, and punctuation are retained. Comparison uses the
original sequences rather than lint's deduplicated path view. Moving a path
between tags changes two separate fields. Loader metadata changes carry no
automatic severity or dangerous flag.

Binary diagnostics are carried on the old and new artifacts. They are neither
findings nor semantic differences because a parse failure is evidence of
incomplete analysis, not proof that the shipped product is defective.

Presentation
------------

Operations construct report objects; renderers contain no policy decisions.
Text emphasizes review, JSON projects a versioned machine contract, and CSV is
deliberately partial. CLI exit-code selection occurs after lint returns and
uses current findings or only ``baseline_comparison.new``.
