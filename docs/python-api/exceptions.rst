.. _python-api-errors:

Exception contract
==================

All expected failures from high-level operations can be caught through
:py:class:`WhatYouShipError <whatyouship.exceptions.WhatYouShipError>`:

.. code-block:: python

   from whatyouship.exceptions import WhatYouShipError
   from whatyouship.operations import inspect

   try:
       report = inspect("release.msi")
   except WhatYouShipError as exc:
       print(f"Analysis failed: {exc}")

Use specialized subclasses when recovery differs. Wrapped failures preserve
their original ``__cause__`` where appropriate, so Python callers retain full
tracebacks. Unexpected programming errors are not broadly converted into
application errors.

``BinaryAnalysisError`` is intentionally absent from this hierarchy. It is an
internal per-file signal caught by artifact inspectors and represented as
:py:class:`whatyouship.model.BinaryAnalysisDiagnostic`, preserving best-effort
artifact analysis.

.. autoclass:: whatyouship.exceptions.WhatYouShipError

.. autoclass:: whatyouship.exceptions.ArtifactNotFoundError
   :show-inheritance:

.. autoclass:: whatyouship.exceptions.UnsupportedArtifactError
   :show-inheritance:

.. autoclass:: whatyouship.exceptions.ArtifactInspectionError
   :show-inheritance:

.. autoclass:: whatyouship.exceptions.ArtifactExtractionError
   :show-inheritance:

.. autoclass:: whatyouship.exceptions.ExternalToolError
   :show-inheritance:

.. autoclass:: whatyouship.exceptions.ConfigurationError
   :show-inheritance:
