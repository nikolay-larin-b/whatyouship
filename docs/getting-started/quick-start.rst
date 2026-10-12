.. _quick-start:

Quick Start
===========

This walkthrough follows two releases of the same product. Install the tool:

.. code-block:: console

   $ python -m pip install whatyouship

First inspect what the new release actually contains:

.. code-block:: console

   $ whatyouship inspect release.msi

The report inventories files, hashes them, and shows available artifact,
binary, bundle, signature, and installation-scope metadata. Next run the
built-in release rules:

.. code-block:: console

   $ whatyouship lint release.msi

Each finding has a rule ID, severity, location, and explanation. Consult
:ref:`lint-rules` before treating a warning as a universal defect: findings
reflect both policy and available platform metadata.

When the product already has known findings, analyze an earlier release as a
baseline:

.. code-block:: console

   $ whatyouship lint release.msi --baseline previous.msi

The result separates new regressions from existing and resolved findings. With
a baseline, only new findings participate in ``--fail-on``. Compare the actual
releases independently of lint policy:

.. code-block:: console

   $ whatyouship compare previous.msi release.msi

This shows added, removed, content-changed, and unchanged paths plus semantic
metadata changes such as binary versions, architectures, signatures, MSI
scope, bundles, and links.

Save the complete machine-readable lint result for CI or later processing:

.. code-block:: console

   $ whatyouship lint release.msi --baseline previous.msi \
       --fail-on error -o lint.json

JSON uses :ref:`json-schema-v2`. A command exits 0 when the selected gate
passes, 1 when eligible findings reach it, and 2 when the operation cannot be
completed. Binary analysis diagnostics describe incomplete best-effort
analysis; they are visible in the report but do not fail the lint gate.

Python callers can obtain the same structured operation result without stdout:

.. code-block:: python

   from whatyouship.operations import inspect

   report = inspect("release.msi")
   print(len(report.artifact.files))

Continue with :doc:`../user-guide/inspecting-artifacts` or
:doc:`../python-api/index`.
