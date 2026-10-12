.. _python-api:

Python API
==========

The documented Python API is **experimental until WhatYouShip 1.0**. It is
intended for programmatic use, but backward-incompatible changes may occur
before 1.0. Material changes to documented interfaces should be called out in
release notes or a changelog. Importable but undocumented internals have no
compatibility guarantee.

The canonical high-level entry points are in ``whatyouship.operations``;
they are deliberately not re-exported from ``whatyouship`` because their
names overlap existing modules.

.. code-block:: python

   from whatyouship.operations import compare, inspect, lint
   from whatyouship.renderers import render_report

   inspection = inspect("release.msi")
   lint_report = lint("release.msi", baseline="previous.msi")
   comparison = compare("previous.msi", "release.msi")
   json_text = render_report(inspection, "json")

Operations accept strings and :class:`os.PathLike` objects, return structured
reports, and write nothing to stdout. They use a temporary cache by default;
``cache=True`` explicitly opts into persistent extraction caching.

Returned objects are dataclasses with normal Python attributes. Report and
artifact models contain mutable lists; callers must not assume immutability.
Optional values can mean absent, unknown, or unsupported depending on the
field; consult :ref:`artifact-formats` and :ref:`report-formats` when making
policy decisions.

Only interfaces on these Python API pages are supported as public. Inspectors,
parsers, cache scopes, lint engines/rules, and backend helpers remain internal.
