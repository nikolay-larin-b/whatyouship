.. _configuration-reference:

Configuration reference
=======================

Lint configuration is an explicit TOML document passed with ``--config`` or
to :py:func:`whatyouship.operations.lint`. The root may contain only a
``rules`` table. Each child table name is a rule ID from :ref:`lint-rules`.
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

Python attribute names differ intentionally from TOML IDs. For example,
``rules.build-artifact-extension`` maps to
``LintConfiguration.build_artifacts``. Use TOML names in files and the typed
classes documented in :doc:`../python-api/data-models` in Python.
