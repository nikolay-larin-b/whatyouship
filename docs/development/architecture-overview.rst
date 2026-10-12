.. _architecture-overview:

Architecture overview
=====================

WhatYouShip separates interfaces, orchestration, analysis, policy, and
presentation. Both the CLI and Python callers enter the same application layer:

.. code-block:: text

   argparse CLI ───────┐
                      ├─> operations ─> artifact inspectors ─> ReleaseArtifact
   Python integration ┘                      │                    │
                                            │                    ├─> lint engine
                                            │                    └─> comparison
                                            └─> cache scope              │
                                                                          v
                                               text / JSON / CSV <── reports

``whatyouship.cli`` owns argument parsing, output destinations, and exit codes.
``whatyouship.operations`` owns the inspect/lint/compare workflows and returns
report objects without output. Inspectors translate different inputs into the
format-independent :py:class:`whatyouship.model.ReleaseArtifact`. The lint and
comparison layers consume that model without depending on MSI, ZIP, DMG, NSIS,
or Inno Setup implementations. Renderers consume reports and do not perform
analysis.

Dependency direction
--------------------

Core models do not import artifact backends. Format adapters may depend on
models, shared directory/binary analysis, cache helpers, and isolated external
tool adapters. Policy rules depend on models, not extractors. This boundary is
what allows one rule or comparison to work across formats when equivalent
metadata is available.

Failure boundaries
------------------

Invalid input, unsupported formats, required extractor failures, and invalid
configuration are operation failures represented by the public exception
hierarchy. A parsing failure in one recognized PE or Mach-O is different: it
is converted into a binary diagnostic, and the rest of the artifact continues.
Unexpected programming errors are not hidden by broad exception handling.

The public API is the documented application layer and result graph. Internal
classes described in this development section are not stable extension APIs.
