.. _configuration-reference:

Configuration reference
=======================

Lint configuration is an explicit TOML document passed with ``--config`` or
to :py:func:`whatyouship.operations.lint`. The root may contain a
``rules`` table and an ``ignore`` array of tables. Each child of ``rules``
is a rule ID from :ref:`lint-rules`.
Unknown root keys, rule IDs, or rule settings are errors.

Common settings
---------------

Every rule accepts ``enabled`` (boolean, default ``true``) and ``severity``
(``"warning"`` or ``"error"``). Default severities are listed in
:ref:`lint-rules`.

Only ``build-artifact-extension`` also accepts ``extensions``: an array of
strings, each beginning with one dot and containing no second dot, whitespace,
or path separator. Values are normalized to lowercase. This setting replaces,
rather than extends, the default set.

Example
-------

The repository's complete example can be :download:`downloaded here
<../../examples/whatyouship.toml>`. A smaller configuration is:

.. code-block:: toml

   [rules.build-artifact-extension]
   severity = "error"
   extensions = [".obj", ".pdb"]

   [rules.unsigned-binary]
   enabled = false

Accepted rule tables are ``build-artifact-extension``, ``invalid-app-bundle``,
``unsigned-app-bundle``, ``untrusted-app-bundle-signature``,
``invalid-app-bundle-signature``, ``incompatible-binary-architecture``,
``debug-entitlement``, ``developer-runtime-search-path``,
``absolute-runtime-search-path``, ``unsigned-binary``,
``untrusted-binary-signature``, ``invalid-binary-signature``,
``unsigned-artifact``, ``untrusted-artifact-signature``,
``invalid-artifact-signature``, ``inconsistent-installation-scope``, and
``missing-license-agreement``.

Targeted exceptions
-------------------

Use one ``[[ignore]]`` table per exception:

.. code-block:: toml

   [[ignore]]
   rule = "unsigned-binary"
   path = "vendor/helper.exe"
   reason = "Third-party tool distributed without a signature."

   [[ignore]]
   rule = "build-artifact-extension"
   path = "symbols/**/*.pdb"

``rule`` and ``path`` are required strings. The rule must be a known built-in
ID, even if that rule is disabled. ``reason`` is an optional string. Other
keys, including ``platform``, are rejected. Order matters: the first matching
exception supplies the explanation retained with a suppressed finding.

Paths match the complete artifact-relative finding path, using ``/`` on every
host. Matching is case-sensitive on every host. A literal path matches exactly;
``*`` matches zero or more characters within a single segment, and a standalone
``**`` segment matches zero or more path segments. Thus ``symbols/**/*.pdb``
matches both ``symbols/app.pdb`` and ``symbols/a/b/app.pdb``. Patterns do not
implicitly match descendants: use ``vendor/**`` for an entire subtree.

Use ``path = "."`` to suppress a finding about the artifact itself. Wildcards,
including ``**``, never match this special artifact path. Absolute paths,
backslashes, empty segments, ``.`` or ``..`` segments within a path, control
characters, and embedded globstars such as ``foo**`` are invalid. Only ``*``
and standalone ``**`` wildcards are supported; ``?``, character classes, and
brace patterns are rejected.

Exceptions affect findings, not extraction, inspected files, or binary
diagnostics. The same exceptions apply to current and baseline findings before
baseline classification. Suppressed findings never affect the lint exit code
and remain separately available in reports. Use separate configuration files
selected with ``--config`` when different release targets need different policy.

Python attribute names differ intentionally from TOML IDs. For example,
``rules.build-artifact-extension`` maps to
``LintConfiguration.build_artifacts``. Use TOML names in files and the typed
classes documented in :doc:`../python-api/data-models` in Python.
