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
file carries its path, size, SHA-256, and nullable binary object. Binary data
contains format, architectures, kind, versions, minimum OS, dependencies,
runtime search paths, and nullable signature data.

A ``lint`` report contains an artifact reference (``source_path``,
``binary_diagnostics``, and optional ``signature_verification_issue``), a
``findings`` array, and nullable ``baseline``. A baseline contains its artifact
reference plus ``new``, ``existing``, and ``resolved`` finding arrays.

A ``compare`` report contains ``old_artifact`` and ``new_artifact`` references,
so diagnostics are associated with one side. It also contains ``added``,
``removed``, ``changed``, and ``unchanged`` arrays and
``semantic_differences``. Each difference includes path, field, old and new
values, dangerous flag, nullable severity, and nullable warning.

.. _binary-diagnostics:

Binary analysis diagnostics
---------------------------

Each ``binary_diagnostics`` entry has ``relative_path``, ``format`` (``PE`` or
``Mach-O``), and a concise ``reason``. It means the format was recognized but
expected parsing failed. It has no traceback and is not a lint finding.

CSV
---

Inspect CSV columns, in order, are ``relative_path``, ``size_bytes``,
``sha256``, ``binary_format``, ``architecture``, ``binary_kind``,
``file_version``, ``product_version``, ``minimum_os_version``,
``dependencies``, ``runtime_search_paths``, ``signature_present``,
``signature_valid``, ``signature_trusted``, ``signature_signer``,
``signature_timestamp``, ``signature_team_id``, ``signature_type``,
``hardened_runtime``, and ``entitlements``.

Lint CSV columns are ``category``, ``rule_id``, ``severity``,
``relative_path``, and ``message``. Category is ``current`` without a baseline,
or ``new``, ``existing``, and ``resolved`` with one. CSV omits artifact-level
metadata and binary diagnostics. Compare has no CSV representation; use JSON
for complete automation data.
