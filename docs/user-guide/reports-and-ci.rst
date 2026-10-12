.. _reports-and-ci:

Reports and CI
==============

Interactive commands print text. Use ``-o`` to select a durable format by
extension:

.. code-block:: console

   $ whatyouship inspect release.zip -o inspect.json
   $ whatyouship lint release.zip -o lint.csv
   $ whatyouship compare previous.zip release.zip -o compare.txt

Choose JSON for complete structured integration, including artifact metadata
and binary diagnostics. CSV is convenient for file or finding tables but omits
artifact-level data and diagnostics; compare has no CSV output. See
:ref:`report-formats` for the exact contract.

A typical regression gate is:

.. code-block:: console

   whatyouship lint release.msi --baseline previous.msi \
       --config whatyouship.toml --fail-on error -o lint.json

Treat exit 0 as a passing completed analysis, exit 1 as a policy failure, and
exit 2 as an input/tool/configuration failure. Preserve the JSON report even on
exit 1 so reviewers can distinguish new, existing, and resolved findings.
With a baseline only new findings gate CI.

Do not infer success from an empty CSV alone: inspect JSON's
``binary_diagnostics`` if analysis completeness is part of your pipeline's
policy. WhatYouShip itself deliberately does not assign those diagnostics a
severity.
