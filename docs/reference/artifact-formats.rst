.. _artifact-formats:

Artifact formats
================

.. list-table:: Top-level artifacts
   :header-rows: 1

   * - Format
     - Detection and extraction
     - Important limitations
   * - Directory
     - Existing directory; traversed directly
     - No outer signature, installation scope, or license metadata
   * - MSI
     - MSI signature; extracted with ``pymsi``
     - Outer Authenticode verification is Windows-only
   * - ZIP
     - ZIP signature; safely extracted with the standard library
     - Represents archived layout, not installer behavior
   * - NSIS EXE
     - NSIS markers; extracted by 7-Zip
     - Requires ``7z``/``7zz``; payload paths are approximate
   * - Inno Setup EXE
     - Inno markers; extracted by ``innoextract``
     - Payload paths are approximate
   * - DMG
     - ``hdiutil`` on macOS; 7-Zip on Linux/Windows
     - Platform-dependent metadata and filesystem support

All extracted trees receive shared file hashing, PE/Mach-O, symbolic-link, and
macOS application-bundle analysis. Persistent cache namespaces are ``msi/v1``,
``zip/v1``, ``nsis/v1``, ``inno/v1``, native ``dmg/v1``, and
``dmg-7zip/v2``. See :ref:`cache-management` for policy.

MSI
---

MSI extraction and table-based installation-scope analysis are
platform-independent. Scope is classified as ``per-user``, ``per-machine``,
``dual-purpose``, or ``ambiguous`` and includes concrete conflicts. This is
static analysis: runtime conditions, transforms, and user choices may change
the actual installation. Extracted paths model target layout.

The inference reads the ``Property``, ``Directory``, ``Registry``,
``Component``, ``Shortcut``, and explicit scope-setting ``CustomAction``
tables. ``ALLUSERS=2``, context-aware folders, and redirected registry roots
are valid dual-purpose signals. HKCU KeyPaths used by components with
non-advertised shortcuts are accepted in per-machine packages. Conditional
components and runtime directory properties cannot always be resolved.

On Windows, the package's Authenticode signature is verified through the
system API. On Linux and macOS, package verification is unsupported rather
than interpreted as unsigned. Embedded PE payload files are still analyzed on
all supported hosts.

ZIP, NSIS, and Inno Setup
-------------------------

ZIP uses safe extraction and rejects paths escaping the extraction root. NSIS
requires 7-Zip (``7zz``, ``7z``, or ``7z.exe``). Inno Setup requires
``innoextract``. The two installer extractors expose a payload representation,
not an exact simulation of runtime installation paths or conditions. On
Windows, the outer executable's Authenticode signature is checked separately
from payload binary signatures.

DMG
---

On macOS, ``hdiutil`` verifies, normalizes when necessary, mounts read-only,
and detaches images. This path preserves native filesystem behavior and reads
software license agreement metadata. On Linux and Windows, 7-Zip extracts
supported single-volume HFS+/APFS images; encrypted or multi-volume images are
not supported. The fallback cannot promise resource forks, extended
attributes, native permissions, or license metadata, though available
symbolic-link information is retained.

DMG signature inspection reads embedded signing data. ``codesign`` is used on
macOS and ``rcodesign`` may be used elsewhere or as a fallback. Results can
include signer/team information and a stapled notarization ticket, but do not
perform Gatekeeper policy assessment or an online Apple notarization check.

Contained binaries
------------------

PE recognition validates the DOS ``MZ`` header, its ``e_lfanew`` offset, and
the ``PE\\0\\0`` signature. Recognized files can expose architecture, binary
kind, version information, and Authenticode status. Trust verification through
WinVerifyTrust is available on Windows; unavailable checks remain unknown.

Mach-O recognition uses thin and universal magic values. Analysis can expose
architectures, executable/library kind, minimum OS, dylib identity/version,
dependencies, runtime search paths, code-signature data, Hardened Runtime, and
entitlements. OpenSSL and macOS ``security`` may enrich CMS/trust information;
their absence is not a parse failure.

Universal results combine all slices. Dynamic-library and framework versions
come from ``LC_ID_DYLIB`` when slices agree. Signature verification checks
signed ranges and embedded special slots in each slice before optional CMS and
trust evaluation; mixed, ad-hoc, and certificate signatures remain distinct.

Recognized but malformed PE or Mach-O files produce :ref:`binary-diagnostics`
and do not abort the artifact. A matching ``.exe`` or ``.dll`` extension alone
does not establish a PE file.

Application bundles
-------------------

Directories named ``.app`` are inspected as macOS bundles. XML and binary
``Info.plist`` files are supported. WhatYouShip records identifiers, versions,
package type, minimum system version, and the main executable, then resolves
supported ``@rpath``, ``@loader_path``, and ``@executable_path`` dependencies
inside the bundle and checks architecture compatibility. Native ``codesign``
verification, including resource seals and Apple trust, is macOS-only; other
hosts report signature verification as unsupported, not invalid.

Bundle issues include required metadata and main-executable failures, a bundle
minimum system version below its executable's deployment target, missing
required bundled libraries, architecture-incompatible libraries, and—where
native verification is available—nested Mach-O code signed by a different
team. A native DMG mount also preserves the execute bit needed for executable
validation.

External tool installation is summarized in :ref:`installation-tools`.
