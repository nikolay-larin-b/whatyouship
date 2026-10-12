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

Some semantic differences carry a warning and severity. Examples include a
version downgrade, removal of a version, increased minimum OS, or a transition
from signed to unsigned. These annotations help review but are not lint
findings and do not introduce a compare failure exit code.

Diagnostics from the two inspections appear in separate old/new report
sections. WhatYouShip does not interpret a diagnostic appearing or disappearing
as a product semantic difference. Use JSON for automation; compare does not
support CSV. Exact fields are in :ref:`report-formats`.
