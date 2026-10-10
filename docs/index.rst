WhatYouShip
===========

Know what you ship. Know what you install.

WhatYouShip is an open-source Python release linter for finished software
release artifacts. It aims to analyze what users actually receive, rather
than source code or build configuration.

The project is in an early stage of development. Currently available for
directory, DMG, MSI, NSIS installer, Inno Setup installer, and ZIP artifacts:

* ``inspect <artifact>`` to show the files in a release artifact.
* ``lint <artifact>`` to report release findings, including suspicious files and scope conflicts.
* ``compare <old-artifact> <new-artifact>`` to compare two releases.

External tools
--------------

WhatYouShip uses external tools only for the artifact operations listed below.
Required tools produce a fatal tool error with exit code ``2`` when an
extraction needs them but they are unavailable.

.. list-table:: External tool requirements
   :header-rows: 1
   :widths: 12 13 24 17 34

   * - Tool
     - Platforms
     - Used for
     - Requirement
     - Installation
   * - `7-Zip <https://www.7-zip.org/download.html>`_ (``7zz``, ``7z``, or ``7z.exe``)
     - Windows, macOS, Linux
     - NSIS payload extraction on every platform; DMG extraction on Linux and Windows
     - Required for extraction
     - Windows: use the official download. macOS: ``brew install sevenzip``.
       Debian/Ubuntu: ``sudo apt install 7zip``. Fedora:
       ``sudo dnf install 7zip``. Arch/Manjaro: ``sudo pacman -S 7zip``.
   * - `innoextract <https://constexpr.org/innoextract/>`_
     - Windows, macOS, Linux
     - Inno Setup payload extraction
     - Required for extraction
     - Windows: use the official download. macOS: ``brew install innoextract``.
       Debian/Ubuntu: ``sudo apt install innoextract``. Fedora:
       ``sudo dnf install innoextract``. Arch/Manjaro:
       ``sudo pacman -S innoextract``.
   * - ``hdiutil``
     - macOS
     - DMG verification, normalization, and mounting
     - Required for DMG content inspection on macOS
     - Included with macOS.
   * - `OpenSSL <https://www.openssl.org/>`_ (``openssl``)
     - Windows, macOS, Linux
     - CMS integrity, signer, and timestamp inspection for certificate-signed Mach-O binaries
     - Optional verification backend
     - Windows: install an OpenSSL distribution. macOS: ``brew install openssl``.
       Debian/Ubuntu: ``sudo apt install openssl``. Fedora:
       ``sudo dnf install openssl``. Arch/Manjaro:
       ``sudo pacman -S openssl``. Ensure ``openssl`` is in ``PATH``.
   * - ``security``
     - macOS
     - System-root trust evaluation for OpenSSL-based Mach-O verification
     - Optional verification backend
     - Included with macOS.
   * - ``codesign``
     - macOS
     - Native trust and signature verification for DMG, Mach-O, and application bundles
     - Optional verification backend
     - Included with macOS. Verification falls back or is reported as
       unsupported when it is unavailable, depending on the artifact.
   * - `rcodesign <https://github.com/indygreg/apple-platform-rs/releases>`_
     - Windows and Linux; fallback on macOS when ``codesign`` is unavailable
     - Cross-platform DMG CMS and trust verification
     - Optional verification backend
     - Install a pre-built platform binary, or run
       ``cargo install apple-codesign``, and add ``rcodesign`` or
       ``rcodesign.exe`` to ``PATH``.

All commands except ``hdiutil`` are discovered through ``PATH``; ``hdiutil`` is
used from its standard macOS system location. A valid persistent extraction
cache can be reused without the corresponding required extractor; the tool is
needed again on a cache miss. Missing optional verification tools do not stop
artifact inspection. Missing or failed ``rcodesign`` leaves complete
verification of a signed DMG unsupported.

By default, the build artifact rule checks ``.ilk``, ``.obj``, ``.iobj``,
``.ipdb``, ``.tlog``, and ``.lastbuildstate`` files, along with ``.dSYM``
debug-symbol bundles.

For recognized binaries, ``inspect`` also reports architecture, executable or
library kind, version metadata, and signature information when available.
PE inspection reports architecture, binary kind, version metadata, and
signature information. Thin and universal Mach-O inspection reports all target
architectures, the binary kind, and whether every architecture slice has an ad
hoc or certificate signature. It also reads the macOS deployment target from
modern and legacy Mach-O load commands, along with dynamic library dependencies
and runtime search paths. Dynamic libraries and framework executables also
expose their ``LC_ID_DYLIB`` current version as the file version when every
architecture slice agrees. Embedded signatures expose the Hardened Runtime
flag and XML entitlements. ``lint`` reports an executable or library when any
slice is unsigned and treats an enabled
``com.apple.security.get-task-allow`` entitlement as an error. Runtime search
paths below developer home or temporary directories are errors by default;
other absolute runtime search paths are warnings. Cryptographic
verification checks the signed ranges and embedded special slots in every
architecture slice, then verifies certificate-backed CMS signatures. On macOS,
the signing identity is also evaluated against the system trust roots. Invalid
binary signatures are errors by default, while untrusted signatures are warnings.

For macOS application bundles in directories, ZIP archives, and DMG images,
WhatYouShip reads XML and binary ``Contents/Info.plist`` files without using
macOS APIs. ``inspect`` reports bundle identity, versions, the main executable,
minimum system version, and package type. ``lint`` reports malformed bundles,
including cases where ``LSMinimumSystemVersion`` is lower than the main
executable's deployment target. ``compare`` reports bundle and binary metadata
changes. Bundle validation resolves ``@executable_path``, ``@loader_path``, and
``@rpath`` references and reports required libraries that should be present
inside the application bundle but are missing. It also reports a bundled
library when it lacks an architecture required by the Mach-O file that imports
it. Architecture incompatibilities are errors by default. On macOS,
WhatYouShip uses
``codesign`` to verify each complete bundle, including its sealed resources and
nested code, and evaluates the signing identity against Apple's trust
requirement. ``inspect`` reports the bundle signer, timestamp, and Team ID;
``lint`` distinguishes unsigned, untrusted, and invalid bundles and reports
nested Mach-O code signed by a different team. Bundle signature verification is
unsupported on other operating systems.

For MSI artifacts on Windows, ``inspect`` separately reports the package's own
signature status using system Authenticode verification. MSI signature checking
is unsupported on Linux and macOS. ``lint`` reports unsigned artifacts,
signatures whose signer is not trusted, and cryptographically invalid artifact
signatures when verification is supported. Directory and ZIP artifact
signatures are unsupported. Package and contained binary signatures are checked
independently.

MSI installation scope is inferred statically from the ``Property``,
``Directory``, ``Registry``, ``Component``, ``Shortcut``, and explicit scope-setting
``CustomAction`` tables on every platform. ``inspect`` reports ``per-user``,
``per-machine``, ``dual-purpose``, or ``ambiguous``. ``lint`` reports concrete
conflicts with ``inconsistent-installation-scope``, and ``compare`` shows scope
changes between MSI releases. ``ALLUSERS=2``, context-aware folders, and
redirected registry roots are valid for dual-purpose packages. HKCU KeyPaths
for components with non-advertised shortcuts are accepted in per-machine
packages. Conditional components and runtime choices cannot always be resolved
statically.

MSI paths follow the package's target directory layout; runtime directory
properties are not resolved.
With ``--cache``, extracted MSI files are cached by the MSI's SHA-256 under
``~/.whatyouship/cache/msi/v1/``. Binary metadata is inspected again on each run.
The cache hash identifies extracted content and does not verify the package's
signature or authenticity.

With ``--cache``, ZIP distributions are safely extracted under
``~/.whatyouship/cache/zip/v1/``,
keyed by the ZIP file's SHA-256. Their extracted files use the same inspection,
binary analysis, lint rules, and comparison logic as directories. ZIP artifact
signatures are not checked. On Windows, ``~`` is the user profile directory.

On macOS, DMG releases use the system ``hdiutil`` command. WhatYouShip mounts a
single-volume image read-only at a private mount point, analyzes its regular
files and symbolic links with the same inspection, lint, and comparison logic
as directories, and detaches it afterwards. It also reports whether the
original image embeds a software license agreement; ``lint`` treats its absence
as an error by default. Application bundle validation uses the mounted
filesystem's native mode bits and reports a main executable with no execute bit.
Images with an agreement are converted to a normalized DMG without accepting
the agreement on the user's behalf. With ``--cache``, the normalized image is
cached by the original image's SHA-256 under
``~/.whatyouship/cache/dmg/v1/``. It preserves the contained filesystem instead
of copying it into an extracted file tree.

On Linux and Windows, DMG releases require ``7z`` or ``7zz`` from 7-Zip in
``PATH``. WhatYouShip supports single-volume images whose HFS or APFS filesystem
is recognized by 7-Zip. With ``--cache``, extracted regular-file trees are
cached by the image's SHA-256 under
``~/.whatyouship/cache/dmg-7zip/v2/``. Embedded software license
agreement metadata is unavailable through this backend, so ``lint`` does not
report the agreement as present or absent. Encrypted and multi-volume images are
not supported. Symbolic links are reported with their stored targets and whether
they point outside the artifact, without being materialized or followed.
Extended attributes, alternate streams, and resource forks are not represented.

DMG container signatures are inspected independently from their files on every
platform. WhatYouShip detects unsigned images, verifies CodeDirectory content
and trailer digests, and reports the Team ID and presence of a stapled
notarization ticket. On macOS, the system ``codesign`` command verifies CMS
integrity and Apple trust and reports the signer and timestamp. On other
platforms, ``rcodesign`` provides the same metadata when available in ``PATH``.
A missing or failed ``rcodesign`` does not stop DMG inspection. For a signed
image, the signature status is reported as unsupported together with the
verification issue and platform-specific installation guidance. Pre-built
binaries are available from the apple-platform-rs releases, or the tool can be
installed with ``cargo install apple-codesign``.
A cryptographically valid signature that does not chain to an Apple root is
reported as untrusted. Current Gatekeeper policy and online notarization status
are not evaluated.

NSIS installer ``.exe`` files are detected before extraction and require
``7z`` or ``7zz`` from 7-Zip in ``PATH``. With ``--cache``, their payloads are
cached by installer SHA-256 under ``~/.whatyouship/cache/nsis/v1/`` and use the
same inspection, binary analysis, lint rules, and comparison logic as
directories. Extracted paths describe the payload and are not an exact
simulation of runtime installation paths. On Windows, the outer installer's
Authenticode signature is checked separately from signatures of binaries in
the payload.

Inno Setup installer ``.exe`` files are detected independently from NSIS and
require ``innoextract`` in ``PATH``. With ``--cache``, their payloads are cached
by installer SHA-256 under ``~/.whatyouship/cache/inno/v1/`` and use the same
inspection, binary analysis, lint rules, and comparison logic as directories.
Extracted paths are a payload representation rather than an exact simulation
of runtime installation paths. On Windows, the outer installer's Authenticode
signature is checked separately from signatures of binaries in the payload.

By default, extracted data is kept only for the duration of the command. Pass
``--cache`` to ``inspect``, ``lint``, or ``compare`` to reuse persistent data
between commands. WhatYouShip keeps persistent user data below
``~/.whatyouship/``; ``cache/`` contains extracted artifact caches and
normalized DMG images, including separate
``dmg/v1`` and ``dmg-7zip/v2`` backend caches, while ``config/`` is reserved for
user configuration. A normalized native DMG is checked with ``hdiutil verify``
before publication. Its size and SHA-256 are stored in the manifest so that a
damaged or outdated cache entry can be rebuilt automatically.
Use ``whatyouship cache info`` to display persistent cache entries, interrupted
temporary entries, sizes, and layout versions. Use
``whatyouship cache clear --all`` to remove the complete cache or repeat
``--format`` to remove selected artifact formats. Clearing the ``dmg`` format
removes both native and 7-Zip DMG caches.

Existing caches in platform-specific cache directories are not migrated.

To configure lint rules for a product, provide a TOML file explicitly:

.. code-block:: text

   whatyouship lint <artifact> --config examples/whatyouship.toml

See the :download:`example configuration <../examples/whatyouship.toml>`
for supported rule settings.

Use ``-o`` or ``--output`` to save a report. The ``.txt``, ``.json``, and
``.csv`` extensions select the format; without an output file, commands print
text to stdout. CSV is available for ``inspect`` and ``lint`` only.

.. code-block:: text

   whatyouship inspect release.zip -o inspect.json
   whatyouship lint release.zip --baseline previous.zip -o lint.csv
   whatyouship compare previous.zip release.zip -o compare.txt

JSON reports contain the complete structured result and include
``schema_version`` (currently ``1``), ``tool_version``, and the report type.
Inspect CSV reports are file tables with one row per contained file. They
include file and binary metadata, but omit artifact-level metadata such as the
source path, the artifact or container signature, installation scope, and
license-agreement state. Use JSON when the complete inspect result is required.

For CI, ``lint`` exits with ``0`` when the release passes, ``1`` when findings
reach the selected threshold, and ``2`` for tool or input errors. The default
threshold is ``--fail-on error``. Use ``--fail-on warning`` to fail on warnings
or errors, or ``--fail-on never`` to ignore findings for the exit code. With
``--baseline``, only new findings are checked against the threshold.

.. code-block:: text

   whatyouship lint release.zip --fail-on warning -o lint.json
   whatyouship lint release.zip --baseline previous.zip --fail-on error
