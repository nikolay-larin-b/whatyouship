.. _lint-baselines:

Linting releases
================

``lint`` first performs the same artifact inspection as ``inspect``, then runs
the enabled rules from :ref:`lint-rules`.

.. code-block:: console

   $ whatyouship lint release.zip

A finding contains a stable rule ID, configured severity, relative path, human
message, and an internal identity used for baseline matching. Warnings and
errors are policy levels; use :doc:`configuration` to adapt them to a product.

Baseline classification
-----------------------

.. code-block:: console

   $ whatyouship lint release.zip --baseline previous.zip

The same configured rules run against both artifacts. A finding key consists
of rule ID, relative path, and rule-defined identity. Equal keys are
``existing``; keys only in the current release are ``new``; keys only in the
baseline are ``resolved``. Message wording and configured severity do not form
the identity.

With a baseline, only new findings are supplied to the CLI gate. The default
``--fail-on error`` fails for a new error. ``--fail-on warning`` fails for any
new finding, while ``--fail-on never`` always returns success after a completed
analysis. Without a baseline, all current findings are eligible.

Binary diagnostics remain separate from findings and never affect the gate.
They may mean a rule lacked metadata for one file, so CI systems concerned with
analysis completeness should inspect :ref:`json-schema-v2` explicitly rather
than reinterpret diagnostics as rule failures.
