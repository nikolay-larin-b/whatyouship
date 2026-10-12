.. _cli-reference:

CLI reference
=============

The executable is ``whatyouship``. Global help and version information are
available with ``--help`` and ``--version``. Arguments rejected by
``argparse`` produce exit code 2.

.. _cli-inspect:

``inspect``
-----------

::

   whatyouship inspect ARTIFACT [-o OUTPUT] [--cache]

``ARTIFACT`` is a directory, DMG, MSI, NSIS or Inno Setup executable, or ZIP.
Without ``-o``/``--output``, a text report is written to stdout. The output
extension selects ``.txt``, ``.json``, or ``.csv``. ``--cache`` opts into the
persistent extraction cache; otherwise a temporary cache is removed after the
operation.

.. _cli-lint:

``lint``
--------

::

   whatyouship lint ARTIFACT [-o OUTPUT] [--baseline BASELINE]
                       [--config CONFIG]
                       [--fail-on {error,warning,never}] [--cache]

``--baseline`` analyzes an earlier artifact and classifies findings as new,
existing, and resolved. ``--config`` reads an explicit TOML file; no file is
discovered implicitly. ``--fail-on`` defaults to ``error``. ``warning`` fails
for any eligible finding and ``never`` disables the lint gate. With a
baseline, only new findings are eligible. Output may be text, JSON, or CSV.

.. _cli-compare:

``compare``
-----------

::

   whatyouship compare OLD_ARTIFACT NEW_ARTIFACT [-o OUTPUT] [--cache]

The command compares files and supported semantic metadata. Output may be
``.txt`` or ``.json``; CSV is not supported. ``--cache`` has the same opt-in
meaning as for other artifact operations.

.. _cli-cache:

``cache``
---------

::

   whatyouship cache info
   whatyouship cache clear --all
   whatyouship cache clear --format {msi,nsis,inno,zip,dmg} [--format ...]

``info`` reports entry counts and byte usage in the persistent cache.
``clear`` requires exactly one selection mode. ``--format`` may be repeated;
the ``dmg`` selection covers both native and 7-Zip DMG layouts. Cleanup is
best-effort and reports paths it could not remove.

Exit codes
----------

.. list-table::
   :header-rows: 1

   * - Code
     - Meaning
   * - 0
     - Operation completed; lint passed the selected threshold.
   * - 1
     - Eligible lint findings reached the threshold, or cache cleanup was incomplete.
   * - 2
     - Invalid arguments, input, configuration, output request, or required tool failure.

Binary analysis diagnostics are report data, not command failures or lint
findings, and therefore do not change these exit codes.
