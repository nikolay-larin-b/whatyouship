# WhatYouShip

Know what you ship. Know what you install.

WhatYouShip is an open-source Python release linter for finished software release artifacts. It aims to analyze what users actually receive, rather than source code or build configuration.

Available actions for directory artifacts:

- `inspect <directory>` — show the files in a directory release artifact.
- `lint <directory>` — warn about suspicious build artifact extensions.

Planned actions:

- `compare` — highlight significant changes between two releases.

The project is in an early stage of development. Linting currently checks only `.ilk`, `.obj`, `.iobj`, `.ipdb`, `.tlog`, and `.lastbuildstate` files.
