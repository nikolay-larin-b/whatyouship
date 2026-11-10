.. _report-formats:

Report formats
==============

Without ``--output``, the CLI writes text to stdout. An output path selects
text (``.txt``), JSON (``.json``), or CSV (``.csv``). The public
:py:func:`whatyouship.renderers.render_report` function uses ``"text"``,
``"json"``, or ``"csv"`` directly.

Text
----

Text is intended for people. Inspect and lint reports include a binary analysis
diagnostics section only when diagnostics exist. Compare reports show old and
new diagnostics separately. Do not parse text as a stable machine protocol.

Lint text includes ``Suppressed findings`` and ``Baseline suppressed findings``
counts when those lists are non-empty, without printing suppressed details.

.. _json-schema-v2:

JSON schema version 2
---------------------

Every JSON document has ``schema_version: 2``, ``tool_version``, and
``report_type``. Consumers should reject or deliberately adapt to unsupported
schema versions. This version describes the serializer contract; WhatYouShip
does not ship a formal JSON Schema document or perform schema validation.

An ``inspect`` report contains a full ``artifact`` object: ``source_path``,
``file_count``, ``total_size_bytes``, outer ``signature``, nullable
``installation_scope``, nullable ``license_agreement_present``,
``binary_diagnostics``, ``bundles``, ``symbolic_links``, and ``files``. Each
file carries its path, size, SHA-256, nullable ``posix_mode``, and nullable binary object.
``posix_mode`` is an integer containing original POSIX permission bits when
provided by the backend, currently TAR; other inputs use ``null``. This is an
additive schema version 2 field. Binary data
contains format, architectures, kind, versions, minimum OS, dependencies,
runtime search paths, and nullable signature data. Binary objects also expose
``runtime_run_paths`` (an array), ``interpreter`` (nullable string), and
``library_name`` (nullable string), added to schema version 2. For ELF,
``runtime_search_paths`` contains DT_RPATH while ``runtime_run_paths`` contains
DT_RUNPATH; ``interpreter`` is PT_INTERP and ``library_name`` is DT_SONAME.
These path arrays preserve order, duplicates, empty elements, and literal loader
tokens. Other binary formats default to empty/null for the new fields.

A ``lint`` report contains an artifact reference (``source_path``,
``binary_diagnostics``, and optional ``signature_verification_issue``), a
``findings`` array, and nullable ``baseline``. A baseline contains its artifact
reference plus ``new``, ``existing``, and ``resolved`` finding arrays.

Lint reports also include a ``suppressed_findings`` array; a non-null baseline
has its own ``suppressed_findings`` array. These are additive schema version 2
fields. Each entry contains the usual finding fields (``rule_id``, ``severity``,
``relative_path``, and ``message``), plus an ``ignore`` object with the matching
configured ``path`` and nullable ``reason``. The first matching exception is
retained. The ordinary finding arrays contain only active findings.

A ``compare`` report contains ``old_artifact`` and ``new_artifact`` references,
so diagnostics are associated with one side. It also contains ``added``,
``removed``, ``changed``, and ``unchanged`` arrays and
``semantic_differences``. Each difference includes path, field, old and new
values, dangerous flag, nullable severity, and nullable warning.

ELF differences use ``Dynamic dependencies``, ``RPATH``, ``RUNPATH``,
``Interpreter``, and ``Library name`` field labels, plus the shared
``Architecture`` and ``Type`` labels. ``old_value`` and ``new_value`` remain
strings. ELF dependency and path-list values encode ordered JSON arrays inside
those strings, preserving duplicate declarations and distinguishing absent
path tags (``[]``) from empty elements (``[""]``). These changes do not assign
severity or a dangerous flag automatically. Existing PE and Mach-O path and
dependency display formats are retained.

.. _binary-diagnostics:

Binary analysis diagnostics
---------------------------

Each ``binary_diagnostics`` entry has ``relative_path``, ``format`` (``PE``,
``Mach-O``, or ``ELF``), and a concise ``reason``. It means the format was recognized but
expected parsing failed. It has no traceback and is not a lint finding.

CSV
---

Inspect CSV columns, in order, are ``relative_path``, ``size_bytes``,
``sha256``, ``binary_format``, ``architecture``, ``binary_kind``,
``file_version``, ``product_version``, ``minimum_os_version``,
``dependencies``, ``runtime_search_paths``, ``signature_present``,
``signature_valid``, ``signature_trusted``, ``signature_signer``,
``signature_timestamp``, ``signature_team_id``, ``signature_type``,
``hardened_runtime``, ``entitlements``, followed by the appended columns
``runtime_run_paths``, ``interpreter``, and ``library_name``. Both path-list
columns contain JSON arrays; unavailable interpreter and library names produce
empty cells.

``posix_mode`` is appended after ``library_name`` and contains octal text such
as ``0755``, or an empty cell when unavailable.

Lint CSV columns are ``category``, ``rule_id``, ``severity``,
``relative_path``, and ``message``. Category is ``current`` without a baseline,
or ``new``, ``existing``, and ``resolved`` with one. Suppressed findings use
``suppressed`` for the current artifact and ``baseline-suppressed`` for the
baseline. CSV retains its existing columns and omits exception paths and reasons;
use JSON for those details. CSV omits artifact-level
metadata and binary diagnostics. Compare has no CSV representation; use JSON
for complete automation data.
