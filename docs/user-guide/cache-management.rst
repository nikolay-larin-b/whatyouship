.. _cache-management:

Cache management
================

Each operation uses an isolated temporary extraction cache by default and
removes it on success or exception. This is true for the CLI, the high-level
Python operations, and direct low-level inspection.

Opt into the persistent cache only when reuse is desired:

.. code-block:: console

   $ whatyouship inspect release.msi --cache

Python operations use ``cache=True``. Persistent data lives below
``~/.whatyouship/cache/`` and is addressed by the artifact's SHA-256. The hash
selects identical content; it is not an authenticity or signature check.

Extraction can be reused, but binary metadata, bundle analysis, lint rules,
and comparisons run again. Cache formats use versioned layouts so incompatible
extraction behavior need not reuse older entries.

Native DMGs with an embedded agreement may be converted to a normalized image
without accepting the agreement on the user's behalf. Before a persistent
normalized image is published, ``hdiutil verify`` checks it and a manifest
records its size and SHA-256; damaged or outdated entries are rebuilt. The
7-Zip DMG backend instead caches its regular-file tree and symbolic-link
metadata in its separate layout.

Inspect and clean persistent storage with:

.. code-block:: console

   $ whatyouship cache info
   $ whatyouship cache clear --format zip --format msi
   $ whatyouship cache clear --all

Cleanup is best-effort and returns exit 1 if paths remain. Do not clear a cache
concurrently with operations that are populating or consuming it. The cache
directory and its lifecycle are implementation details; Python integrations
should use the operation-level ``cache`` argument rather than internal cache
scope helpers.
