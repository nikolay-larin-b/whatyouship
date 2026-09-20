WhatYouShip
===========

Know what you ship. Know what you install.

WhatYouShip is an open-source Python release linter for finished software
release artifacts. It aims to analyze what users actually receive, rather
than source code or build configuration.

The project is in an early stage of development. Currently available for
directory artifacts:

* ``inspect <directory>`` to show the files in a directory release artifact.
* ``lint <directory>`` to warn about suspicious build artifact extensions.

Linting currently checks only ``.ilk``, ``.obj``, ``.iobj``, ``.ipdb``,
``.tlog``, and ``.lastbuildstate`` files.

Planned actions:

* ``compare`` to highlight significant changes between two releases.
