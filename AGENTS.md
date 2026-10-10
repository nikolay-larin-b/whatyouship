# Development guidance for WhatYouShip

WhatYouShip is an open-source Python tool for analyzing finished software release artifacts: what users actually receive and install. Its intended actions are `inspect`, `lint`, and `compare`. It is a release linter, not an MSI validator, SBOM generator, or security scanner.

Windows MSI is the first planned format. Keep the architecture independent of MSI and Windows so that ZIP files, directories, DMG files, and other release formats can be supported later. Isolate external formats and tools behind backend or adapter layers; the core must not depend on a specific format.

Development rules:

- Work in small, logical steps.
- Implement only functionality that has been explicitly requested.
- Add dependencies only when necessary; prefer the Python standard library when it is sufficient.
- Keep application and test code cross-platform across Windows, Linux, and macOS. Do not hard-code path separators, platform-specific filesystem locations, shell commands, or OS-specific behavior; use portable Python standard-library abstractions such as `pathlib`, `tempfile`, and `os` instead. Isolate unavoidable platform-specific code behind adapters and explicitly mark or skip platform-specific tests.
- Communication with the user may be in Russian.
- Write all project code, comments, docstrings, README content, documentation, error messages, and other user-facing project text in English.
- Use backticks to format inline code, commands, identifiers, and file names.
- Start Python files with the copyright notice for Nikolay Larin and the `SPDX-License-Identifier: MIT` marker; add a module docstring.
- Document classes and functions with Sphinx-compatible docstrings. Use reStructuredText fields for parameters, return values, and raised exceptions when applicable.
- Add type annotations to every new function and method, including tests: annotate parameters other than `self` and `cls`, and always annotate return values.
- When writing or suggesting a Git commit message, base it strictly on the current diff. Write a concise past-tense subject that identifies the primary technical or behavioral change. Format the body as a past-tense technical bullet list. Each bullet must name the concrete implementation detail, API, expression, rule, or behavior that changed and, when relevant, its resulting effect. Avoid vague summaries and do not mention unchanged behavior.
- Do not make Git commits unless explicitly requested by the user.
- Do not publish packages or upload anything to PyPI.
