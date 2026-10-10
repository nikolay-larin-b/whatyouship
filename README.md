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
whatyouship cache --help
```

## What it looks for

WhatYouShip analyzes the final release rather than assumptions made by the build system.

Current checks and comparisons include:

* suspicious build artifacts accidentally included in a release;
* unsigned executables and libraries;
* untrusted and cryptographically invalid binary signatures;
* untrusted signers and invalid artifact signatures where platform verification is available;
* inconsistent MSI installation scope;
* DMG releases without an embedded software license agreement;
* unsigned, untrusted, or invalid DMG container signatures;
* malformed macOS application bundles;
* unsigned, untrusted, or invalid macOS application bundle signatures;
* invalid application resource seals and nested code signed by another team;
* missing required Mach-O libraries expected inside an application bundle;
* bundled Mach-O libraries missing an architecture required by their importer;
* runtime search paths tied to developer machines or absolute filesystem locations;
* release Mach-O binaries with debugger attachment enabled;
* added, removed, and changed files between releases;
* binary architecture changes;
* executable/library kind changes;
* file and product version changes;
* signature and signer changes between releases.

For recognized PE binaries, WhatYouShip extracts architecture, binary kind,
version metadata, and signature information. For thin and universal Mach-O
binaries, it reports all target architectures, the binary kind, and whether
every architecture slice has an ad hoc or certificate signature. It also reads
the macOS deployment target, dynamic library dependencies, and runtime search
paths from Mach-O load commands. Dynamic libraries and framework executables
also expose their `LC_ID_DYLIB` current version as the file version when every
architecture slice agrees. Embedded signatures expose the Hardened Runtime
flag and XML entitlements. `lint` treats an enabled
`com.apple.security.get-task-allow` entitlement as an error. Runtime search
paths below developer home or temporary directories are errors by default;
other absolute runtime search paths are warnings. Cryptographic
verification checks the signed ranges and embedded special slots in every
architecture slice, then verifies certificate-backed CMS signatures. On macOS,
the signing identity is also evaluated against the system trust roots.

For macOS application bundles in directories, ZIP archives, and DMG images,
WhatYouShip reads XML and binary `Contents/Info.plist` files without using
macOS APIs. `inspect` reports the bundle identifier, name, versions, main
executable, minimum system version, and package type. `lint` checks required
metadata, the main executable, and consistency between
`LSMinimumSystemVersion` and the executable deployment target, while `compare`
reports bundle and binary metadata changes. Bundle validation resolves
`@executable_path`, `@loader_path`, and `@rpath` references and reports required
libraries that should be present inside the application bundle but are missing.
It also reports a bundled library when it lacks an architecture required by
the Mach-O file that imports it.
On macOS, WhatYouShip also uses `codesign` to verify the complete bundle,
including its sealed resources and nested code, and checks the signing identity
against Apple's trust requirement. It reports the bundle signer, timestamp, and
Team ID; `lint` distinguishes unsigned, untrusted, and invalid bundles and
reports nested Mach-O code signed by a different team. Bundle signature
verification is reported as unsupported on other operating systems.

## Commands

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

A product-specific TOML configuration can change rule settings. Download or
adapt [`examples/whatyouship.toml`](https://github.com/nikolay-larin-b/whatyouship/blob/main/examples/whatyouship.toml),
then pass its local path:

```text
whatyouship lint release.msi --config whatyouship.toml
```

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

### `cache`

Shows or removes persistent artifact cache data:

```text
whatyouship cache info
whatyouship cache clear --format zip
```

See [Cache](#cache) for persistent cache behavior and removal options.

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
files and symbolic links, and detaches it after inspection. It also reports
whether the original image embeds a software license agreement; its absence is
an error by default. Application bundle validation uses the mounted filesystem's
native mode bits and reports a main executable with no execute bit.
An image with an agreement is converted to a normalized DMG without accepting
the agreement on the user's behalf, then mounted read-only. The normalized
image is temporary by default and is stored persistently only with `--cache`.

On Linux and Windows, DMG releases require `7z` or `7zz` from 7-Zip in `PATH`.
WhatYouShip supports single-volume images whose HFS or APFS filesystem is
recognized by 7-Zip and analyzes the extracted regular files. Embedded software
license agreement metadata is unavailable through this backend, so `lint` does
not report the agreement as present or absent. Encrypted and multi-volume images
are not supported. Symbolic links are reported with their stored targets and
whether they point outside the artifact, without being materialized or followed.
Extended attributes, alternate streams, and resource forks are not represented.

DMG container signatures are inspected independently from their files on every
platform. WhatYouShip always detects unsigned images, verifies CodeDirectory
content and trailer digests, and reports the Team ID and presence of a stapled
notarization ticket. On macOS, the system `codesign` command verifies CMS
integrity and Apple trust and reports the signer and timestamp. On other
platforms, `rcodesign` provides the same metadata when available in `PATH`.
A missing or failed `rcodesign` does not stop DMG inspection. For a signed image,
the signature status is reported as unsupported together with the verification
issue and platform-specific installation guidance. Pre-built binaries are
available from the apple-platform-rs releases, or the tool can be installed
with `cargo install apple-codesign`.
A signature with valid digests and CMS cryptography that does not chain to an
Apple root is reported as untrusted. Current Gatekeeper policy and online
notarization status are not evaluated.

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

JSON reports contain the complete structured result and include `schema_version`,
`tool_version`, and the report type. Inspect CSV reports are file tables with one
row per contained file. They include file and binary metadata, but omit
artifact-level metadata such as the source path, the artifact or container
signature, installation scope, and license-agreement state. Use JSON when the
complete inspect result is required.

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

By default, WhatYouShip extracts artifacts into a temporary cache that is
removed when the command finishes. Pass `--cache` to `inspect`, `lint`, or
`compare` to reuse and populate the persistent cache between commands.

WhatYouShip keeps persistent user data under:

```text
~/.whatyouship/
```

Persistently cached artifacts are keyed by SHA-256:

```text
~/.whatyouship/cache/msi/v1/
~/.whatyouship/cache/nsis/v1/
~/.whatyouship/cache/inno/v1/
~/.whatyouship/cache/zip/v1/
~/.whatyouship/cache/dmg/v1/
~/.whatyouship/cache/dmg-7zip/v2/
```

The persistent cache avoids repeated extraction of the same artifact. Binary
metadata and lint analysis are performed again on each run.

Inspect persistent cache usage with:

```text
whatyouship cache info
```

Cache information includes completed entries, interrupted temporary entries,
logical file size, and the cache layouts present for each artifact format.

Clear the complete persistent cache or selected artifact formats with:

```text
whatyouship cache clear --all
whatyouship cache clear --format zip
whatyouship cache clear --format dmg --format msi
```

The target is mandatory, so cache removal cannot accidentally default to the
complete cache. Supported format names are `msi`, `nsis`, `inno`, `zip`, and
`dmg`. Clearing `dmg` removes both native and 7-Zip DMG cache layouts.

Do not run `cache clear` concurrently with `inspect`, `lint`, or `compare`
using `--cache`. Cache removal is not coordinated with active cache readers.

On macOS, DMGs without an embedded agreement are inspected directly from a
temporary read-only mount. Images with an agreement are converted to a
normalized image that preserves the contained filesystem for inspection. With
`--cache`, that image is stored by the original image's SHA-256 under `dmg/v1`.
Before publication, the normalized image is checked with `hdiutil verify`.
Its size and SHA-256 are recorded in the cache manifest; a damaged or outdated
entry is rebuilt automatically.
On Linux and Windows, `--cache` stores the regular-file tree and symbolic-link
metadata extracted by 7-Zip separately under `dmg-7zip/v2`.

The cache hash identifies artifact content; it is not a signature or authenticity check.

On Windows, `~` refers to the user's profile directory.
