WhatYouShip
===========

Know what you ship. Know what you install.

WhatYouShip is an open-source Python release linter for finished software
release artifacts. It aims to analyze what users actually receive, rather
than source code or build configuration.

The project is in an early stage of development. Currently available for
directory and MSI artifacts:

* ``inspect <artifact>`` to show the files in a release artifact.
* ``lint <artifact>`` to report suspicious build artifacts and unsigned binaries.
* ``compare <old-artifact> <new-artifact>`` to compare two releases.

By default, the build artifact rule checks ``.ilk``, ``.obj``, ``.iobj``,
``.ipdb``, ``.tlog``, and ``.lastbuildstate`` files.

For recognized binaries, ``inspect`` also reports architecture, executable or
library kind, version metadata, and signature information when available.
Binary inspection currently supports Windows executables and libraries.

MSI paths follow the package's target directory layout; runtime directory
properties are not resolved.

To configure lint rules for a product, provide a TOML file explicitly:

.. code-block:: text

   whatyouship lint <artifact> --config examples/whatyouship.toml

See the :download:`example configuration <../examples/whatyouship.toml>`
for supported rule settings.
