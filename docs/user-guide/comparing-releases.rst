.. _comparing-releases:

Comparing releases
==================

Use ``compare`` when you need a release-to-release inventory and metadata
review rather than a policy decision:

.. code-block:: console

   $ whatyouship compare previous.msi release.msi

Paths are classified as added, removed, changed, or unchanged by relative path
and SHA-256 content. WhatYouShip also reports semantic changes where supported:
binary architecture, kind, file/product/minimum-OS versions, dependencies,
runtime search paths, Hardened Runtime, entitlements and signatures; app-bundle
metadata and signatures; symbolic-link targets; outer artifact signatures; and
MSI installation scope.

When both sides expose original POSIX file modes, a permission change appears
as a ``POSIX mode`` semantic difference with octal old/new values. A mode-only
change leaves the file in ``unchanged`` because that category compares content
hashes. Missing permission metadata on another input format is not interpreted
as a permission change.

ELF comparison includes architecture, executable/library/other kind,
DT_NEEDED dependencies, separate ``RPATH`` and ``RUNPATH`` fields,
``Interpreter`` (PT_INTERP), and ``Library name`` (DT_SONAME). Moving a path
from RPATH to RUNPATH produces two changes because the loader declarations
have different semantics. Loader tokens remain literal; dependency and path
declaration order and duplicates are significant.

For ELF dependencies and path lists, old/new values are JSON-array strings in
both text and JSON reports. This distinguishes no path tag (``[]``) from an
empty path element (``[""]``) and avoids ambiguity in names containing commas.
Interpreter and library-name additions/removals use ``unavailable`` for the
absent value. Loader metadata changes are informational and carry no automatic
regression severity or compare failure exit code.

Some semantic differences carry a warning and severity. Examples include a
version downgrade, removal of a version, increased minimum OS, or a transition
from signed to unsigned. These annotations help review but are not lint
findings and do not introduce a compare failure exit code.

Diagnostics from the two inspections appear in separate old/new report
sections. WhatYouShip does not interpret a diagnostic appearing or disappearing
as a product semantic difference. Use JSON for automation; compare does not
support CSV. Exact fields are in :ref:`report-formats`.
