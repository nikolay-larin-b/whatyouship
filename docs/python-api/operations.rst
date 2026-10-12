.. _python-api-operations:

Operations and rendering
========================

The CLI calls these same operations, so inspection, configuration, baseline
classification, and comparison have one application-layer implementation.
Expected failures derive from :py:class:`whatyouship.exceptions.WhatYouShipError`;
programming errors retain their normal traceback.

``lint`` accepts either a TOML path or a prepared
:py:class:`whatyouship.config.LintConfiguration`. Passing ``cache=True`` to an
operation reuses the persistent cache for all artifact inspections performed
by that operation, including a lint baseline or both compare inputs.

.. autofunction:: whatyouship.operations.inspect

.. autofunction:: whatyouship.operations.lint

.. autofunction:: whatyouship.operations.compare

Rendering
---------

``render_report`` converts any operation result to text or JSON, and inspect or
lint results to CSV. Requesting compare CSV raises :class:`ValueError`. The
function returns a string and performs no file or stdout I/O.

.. autofunction:: whatyouship.renderers.render_report
