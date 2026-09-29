# WhatYouShip

**Know what you ship. Know what you install.**

WhatYouShip is an open-source release artifact linter. It analyzes the software package that users actually receive — not the source tree or build configuration.

It can inspect, lint, and compare directory, DMG, MSI, NSIS installer, Inno
Setup installer, and ZIP releases.

## Quick start

Inspect a release:

```text
whatyouship inspect release.msi
```

Lint it:

```text
whatyouship lint release.msi
```

Compare two releases:

```text
whatyouship compare previous.msi release.msi
```

Use the previous release as a baseline so that existing findings do not hide new regressions:

```text
whatyouship lint release.msi --baseline previous.msi
```

Save a report:

```text
whatyouship lint release.msi --baseline previous.msi -o lint.json
```

Use WhatYouShip as a CI release gate:

```text
whatyouship lint release.msi --baseline previous.msi --fail-on error
```

For available commands and options:

```text
whatyouship --help
whatyouship inspect --help
whatyouship lint --help
whatyouship compare --help
```

## What it looks for

WhatYouShip analyzes the final release rather than assumptions made by the build system.

Current checks and comparisons include:

* suspicious build artifacts accidentally included in a release;
* unsigned executables and libraries;
* untrusted signers and invalid artifact signatures where platform verification is available;
* inconsistent MSI installation scope;
* DMG releases without an embedded software license agreement;
* malformed macOS application bundles;
* added, removed, and changed files between releases;
* binary architecture changes;
* executable/library kind changes;
* file and product version changes;
* signature and signer changes between releases.

For recognized PE binaries, WhatYouShip extracts architecture, binary kind,
version metadata, and signature information. For thin and universal Mach-O
binaries, it reports all target architectures, the binary kind, and whether
every architecture slice has an ad hoc or certificate signature. It also reads
the macOS deployment target from modern and legacy Mach-O load commands.
Cryptographic validity of Mach-O signatures is not currently checked.

For macOS application bundles in directories, ZIP archives, and DMG images,
WhatYouShip reads XML and binary `Contents/Info.plist` files without using
macOS APIs. `inspect` reports the bundle identifier, name, versions, main
executable, minimum system version, and package type. `lint` checks required
metadata, the main executable, and consistency between
`LSMinimumSystemVersion` and the executable deployment target, while `compare`
reports bundle and binary metadata changes.

## Inspect, lint, compare

### `inspect`

Shows what is actually present in a release artifact.

```text
whatyouship inspect release.zip
```

For recognized binaries, the report includes metadata such as architecture, executable or library kind, versions, and signature information.

### `lint`

Runs release rules and reports findings.

```text
whatyouship lint release.msi
```

A product-specific TOML configuration can change rule settings:

```text
whatyouship lint release.msi --config examples/whatyouship.toml
```

See [`examples/whatyouship.toml`](examples/whatyouship.toml) for supported rule settings.

### Baseline linting

A previous release can be used as the baseline:

```text
whatyouship lint release.msi --baseline previous.msi
```

Findings are classified as:

* **new** — present only in the new release;
* **existing** — present in both releases;
* **resolved** — present only in the baseline.

This makes it possible to concentrate on regressions without losing track of known issues.

### `compare`

Compares the actual contents of two releases:

```text
whatyouship compare previous.msi release.msi
```

In addition to added, removed, changed, and unchanged files, WhatYouShip reports
semantic binary and application bundle changes such as version, architecture,
signature, bundle identifier, and minimum system version changes.

## Supported artifacts

| Artifact       | Inspect | Lint | Compare |
| -------------- | ------- | ---- | ------- |
| Directory      | Yes     | Yes  | Yes     |
| DMG            | Yes     | Yes  | Yes     |
| MSI            | Yes     | Yes  | Yes     |
| NSIS EXE       | Yes     | Yes  | Yes     |
| Inno Setup EXE | Yes     | Yes  | Yes     |
| ZIP            | Yes     | Yes  | Yes     |

MSI extraction and static MSI analysis are platform-independent.

On Windows, the signature of the MSI package itself is verified using the system Authenticode API. Signature status distinguishes unsigned, valid and trusted, signed but untrusted, and cryptographically invalid artifacts. Package signature verification is currently unsupported on Linux and macOS.

ZIP releases use the same file and binary analysis as ordinary directories.

On macOS, DMG releases use the system `hdiutil` command. WhatYouShip mounts a
single-volume image read-only at a private mount point, analyzes its regular
files, and detaches it after inspection. It also reports whether the original
image embeds a software license agreement; its absence is an error by default.
An image with an agreement is converted to a normalized cached DMG without
accepting the agreement on the user's behalf, then mounted read-only.

On Linux and Windows, DMG releases require `7z` or `7zz` from 7-Zip in `PATH`.
WhatYouShip supports single-volume images whose HFS or APFS filesystem is
recognized by 7-Zip and analyzes the extracted regular files. Embedded software
license agreement metadata is unavailable through this backend, so `lint` does
not report the agreement as present or absent. Encrypted and multi-volume images
are not supported. Symbolic links, extended attributes, alternate streams, and
resource forks are not represented in reports. DMG artifact signatures and
notarization status are not currently checked.

NSIS installers require `7z` or `7zz` from 7-Zip to be available in `PATH`.
WhatYouShip inspects the extracted payload; extracted paths are not an exact
simulation of runtime installation paths. On Windows, the outer installer's
Authenticode signature is checked separately from signatures of binaries in its
payload.

Inno Setup installers require `innoextract` to be available in `PATH`. Their
extracted layout is a payload representation, not an exact simulation of
runtime installation paths. On Windows, the outer installer's Authenticode
signature is checked separately from signatures of binaries in its payload.

## MSI installation scope

WhatYouShip statically analyzes MSI installation scope and distinguishes:

* `per-user`;
* `per-machine`;
* `dual-purpose`;
* `ambiguous`.

The `inconsistent-installation-scope` rule reports concrete conflicts between the declared installation context and component resources.

WhatYouShip also reports installation-scope changes when comparing MSI releases.

Because this is static analysis, runtime conditions and installer choices cannot always be resolved in advance.

## Reports

Use `-o` or `--output` to write a report to a file. The extension selects the format.

```text
whatyouship inspect release.zip -o inspect.json
whatyouship lint release.zip -o lint.csv
whatyouship compare previous.zip release.zip -o compare.txt
```

Supported formats:

| Format  | Inspect | Lint | Compare |
| ------- | ------- | ---- | ------- |
| `.txt`  | Yes     | Yes  | Yes     |
| `.json` | Yes     | Yes  | Yes     |
| `.csv`  | Yes     | Yes  | No      |

Without `--output`, commands print text to stdout.

JSON reports contain structured data and include `schema_version`, `tool_version`, and the report type.

## CI and exit codes

`lint` can be used directly as a release gate.

```text
whatyouship lint release.msi --fail-on error
```

Available thresholds:

```text
--fail-on error
--fail-on warning
--fail-on never
```

The default is `--fail-on error`.

Exit codes:

* `0` — the release passes the selected threshold;
* `1` — lint findings reach the selected threshold;
* `2` — WhatYouShip cannot complete the operation because of an input, configuration, or tool error.

With `--baseline`, only **new** findings affect the lint exit code.

For example:

```text
whatyouship lint release.msi --baseline previous.msi --fail-on error -o lint.json
```

## Cache

WhatYouShip keeps its user data under:

```text
~/.whatyouship/
```

Extracted artifacts are cached by SHA-256:

```text
~/.whatyouship/cache/msi/v1/
~/.whatyouship/cache/nsis/v1/
~/.whatyouship/cache/inno/v1/
~/.whatyouship/cache/zip/v1/
~/.whatyouship/cache/dmg/v1/
~/.whatyouship/cache/dmg-7zip/v1/
```

The cache avoids repeated extraction of the same artifact. Binary metadata and lint analysis are performed again on each run.

On macOS, DMGs without an embedded agreement are inspected directly from a
temporary read-only mount. Images with an agreement are converted once and
cached by the original image's SHA-256 under `dmg/v1`. That cache stores a
normalized disk image rather than an extracted file tree, preserving the
contained filesystem for inspection. On Linux and Windows, the regular-file
tree extracted by 7-Zip is cached separately under `dmg-7zip/v1`.

The cache hash identifies artifact content; it is not a signature or authenticity check.

On Windows, `~` refers to the user's profile directory.
