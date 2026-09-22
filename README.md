# WhatYouShip

Know what you ship. Know what you install.

WhatYouShip is an open-source Python release linter for finished software release artifacts. It aims to analyze what users actually receive, rather than source code or build configuration.

Available actions for directory, MSI, and ZIP artifacts:

- `inspect <artifact>` — show the files in a release artifact.
- `lint <artifact>` — report release findings, including suspicious files and scope conflicts.
- `compare <old-artifact> <new-artifact>` — compare two releases.

The project is in an early stage of development. By default, the build artifact rule checks `.ilk`, `.obj`, `.iobj`, `.ipdb`, `.tlog`, and `.lastbuildstate` files.

For recognized binaries, `inspect` also reports architecture, executable or library kind, version metadata, and signature information when available. Binary inspection currently supports Windows executables and libraries.

For MSI artifacts on Windows, `inspect` separately reports the package's own signature status using system Authenticode verification. MSI signature checking is unsupported on Linux and macOS. `lint` reports unsigned artifacts and invalid artifact signatures when verification is supported; directory and ZIP artifact signatures are unsupported. Package and contained binary signatures are checked independently.

MSI installation scope is inferred statically from the `Property`, `Directory`, `Registry`, `Component`, `Shortcut`, and explicit scope-setting `CustomAction` tables on every platform. `inspect` reports `per-user`, `per-machine`, `dual-purpose`, or `ambiguous`; `lint` reports concrete conflicts with `inconsistent-installation-scope`, and `compare` shows scope changes between MSI releases. `ALLUSERS=2`, context-aware folders, and redirected registry roots are valid for dual-purpose packages. HKCU KeyPaths for components with non-advertised shortcuts are accepted in per-machine packages. Conditional components and runtime choices cannot always be resolved statically.

MSI paths follow the package's target directory layout; runtime directory properties are not resolved.
Extracted MSI files are cached by the MSI's SHA-256 under `~/.whatyouship/cache/msi/v1/`. Binary metadata is inspected again on each run.
The cache hash identifies extracted content and does not verify the package's signature or authenticity.

ZIP distributions are safely extracted under `~/.whatyouship/cache/zip/v1/`, keyed by the ZIP file's SHA-256. Their extracted files use the same inspection, binary analysis, lint rules, and comparison logic as directories. ZIP artifact signatures are not checked. On Windows, `~` is the user profile directory.

WhatYouShip keeps user data below `~/.whatyouship/`; `cache/` contains extracted artifact caches and `config/` is reserved for user configuration. Existing caches in platform-specific cache directories are not migrated.

To configure lint rules for a product, pass an explicit TOML file:

```text
whatyouship lint <artifact> --config examples/whatyouship.toml
```

See the [example configuration](examples/whatyouship.toml) for supported rule settings.

To save a report, use `-o` or `--output`; `.txt`, `.json`, and `.csv` select the format. Without an output file, commands print text to stdout. CSV is available for `inspect` and `lint` only.

```text
whatyouship inspect release.zip -o inspect.json
whatyouship lint release.zip --baseline previous.zip -o lint.csv
whatyouship compare previous.zip release.zip -o compare.txt
```

JSON reports include `schema_version` (currently `1`), `tool_version`, and the report type.

For CI, `lint` exits with `0` when the release passes, `1` when findings reach the selected threshold, and `2` for tool or input errors. The default threshold is `--fail-on error`; `--fail-on warning` fails on warnings or errors, while `--fail-on never` always ignores findings for the exit code. With `--baseline`, only new findings are checked against the threshold.

```text
whatyouship lint release.zip --fail-on warning -o lint.json
whatyouship lint release.zip --baseline previous.zip --fail-on error
```
