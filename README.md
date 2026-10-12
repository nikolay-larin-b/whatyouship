# WhatYouShip

**Know what you ship. Know what you install.**

WhatYouShip is an open-source release artifact linter. It analyzes the finished
software package that users actually receive—not the source tree or build
configuration. Use it to inspect release contents, apply release-quality rules,
and compare two releases.

Supported top-level artifacts are directories, Windows MSI packages, ZIP
archives, NSIS installers, Inno Setup installers, and macOS DMG images.
WhatYouShip also analyzes PE and Mach-O binaries and macOS application bundles
inside those artifacts when the required metadata and platform tools are
available.

## Installation

WhatYouShip requires Python 3.11 or newer.

```console
python -m pip install whatyouship
```

Some formats require external extraction tools. See the
[installation and requirements guide](https://whatyouship.readthedocs.io/en/latest/getting-started/installation.html)
for the platform matrix.

## Quick examples

```console
whatyouship inspect release.msi
whatyouship lint release.msi
whatyouship lint release.msi --baseline previous.msi
whatyouship compare previous.msi release.msi
whatyouship lint release.msi --baseline previous.msi -o lint.json
```

WhatYouShip can identify suspicious build artifacts, unsigned or invalidly
signed binaries and packages where verification is supported, malformed macOS
application bundles, incompatible bundled architectures, non-portable runtime
search paths, inconsistent MSI installation scope, and missing supported
license metadata. Comparison covers file changes and semantic changes such as
versions, architectures, dependencies, signatures, bundles, links, and MSI
scope.

The high-level Python API returns the same structured operation results:

```python
from whatyouship.operations import inspect, lint, compare

inspection = inspect("release.msi")
lint_report = lint("release.msi", baseline="previous.msi")
comparison = compare("previous.msi", "release.msi")
```

The Python API is experimental until 1.0.

## Documentation

- [Quick Start](https://whatyouship.readthedocs.io/en/latest/getting-started/quick-start.html)
- [User Guide](https://whatyouship.readthedocs.io/en/latest/user-guide/inspecting-artifacts.html)
- [CLI and lint-rule reference](https://whatyouship.readthedocs.io/en/latest/reference/cli.html)
- [Python API](https://whatyouship.readthedocs.io/en/latest/python-api/index.html)
- [Architecture and development](https://whatyouship.readthedocs.io/en/latest/development/architecture-overview.html)
- [Changelog](https://github.com/nikolay-larin-b/whatyouship/blob/master/CHANGELOG.md)

WhatYouShip is a release linter, not an MSI validator, SBOM generator, or
security scanner. Detailed platform limitations, report contracts, cache
behavior, and contribution guidance live in the documentation.

## License

MIT
