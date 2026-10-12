.. _inspecting-artifacts:

Inspecting artifacts
====================

``inspect`` answers a concrete question: what is present in the deliverable?
Point it at the same file or directory distributed to users, not a source or
build directory unless that directory itself is the release.

.. code-block:: console

   $ whatyouship inspect dist/product.zip

Every regular file receives a relative path, size, and SHA-256 content hash.
Recognized PE and Mach-O files add architecture, kind, version, dependency,
runtime-path, and signature metadata when available. Artifact-level data can
include an outer signature, MSI installation scope, DMG license agreement,
symbolic links, and macOS application bundles.

Unknown is not unsigned
-----------------------

Signature state reflects what the current platform and tools can establish.
``unsupported`` or an unavailable value means no supported verifier produced a
result; it must not be interpreted as ``unsigned``. Likewise, static MSI scope
and extracted installer layouts cannot reproduce every runtime condition.

.. _inspection-diagnostics:

Diagnostics versus findings
---------------------------

A binary analysis diagnostic means a file was confidently recognized as PE or
Mach-O but expected parsing failed. It records the relative path, format, and
reason. The file remains in the inventory with ``binary`` set to ``None``, and
analysis continues for other files.

Diagnostics describe incomplete analysis. Lint findings express a rule result
over successfully available metadata. Diagnostics therefore have no severity,
do not become findings, and do not affect ``lint --fail-on``. Review them when
completeness matters and retain JSON rather than CSV, because CSV omits them.

See :ref:`artifact-formats` for exact capabilities and
:ref:`report-formats` for output contracts.
