# Development guidance for WhatYouShip

WhatYouShip is an open-source Python tool for analyzing finished software release artifacts: what users actually receive and install. Its intended actions are `inspect`, `lint`, and `compare`. It is a release linter, not an MSI validator, SBOM generator, or security scanner.

Windows MSI is the first planned format. Keep the architecture independent of MSI and Windows so that ZIP files, directories, DMG files, and other release formats can be supported later. Isolate external formats and tools behind backend or adapter layers; the core must not depend on a specific format.

Development rules:

- Work in small, logical steps.
- Implement only functionality that has been explicitly requested.
- Add dependencies only when necessary; prefer the Python standard library when it is sufficient.
- Communication with the user may be in Russian.
- Write all project code, comments, docstrings, README content, documentation, error messages, and other user-facing project text in English.
- Do not make Git commits.
- Do not publish packages or upload anything to PyPI.
