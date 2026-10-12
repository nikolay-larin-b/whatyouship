.. _artifact-backends:

Artifact backends
=================

``DirectoryInspector`` is the common content analyzer. It walks regular files,
hashes them, invokes ``PeInspector`` and ``MachOInspector``, retains symbolic
links, discovers ``.app`` directories, and aggregates binary diagnostics.
``AppBundleInspector`` parses plist metadata, locates the main executable,
resolves bundled Mach-O dependencies, and records structural and architecture
issues. ``app_signature`` isolates native bundle verification.

Container inspectors
--------------------

``MsiInspector`` uses ``pymsi`` to extract payload and read MSI tables. The
``msi_scope`` module derives a static scope model, while ``msi_signature`` and
``windows_authenticode`` isolate Windows package verification.

``ZipInspector`` uses the standard library and safe path handling, then
delegates the resulting tree. ``NsisInspector`` detects NSIS and uses the
``seven_zip`` adapter. ``InnoInspector`` detects Inno Setup and uses the
``innoextract`` executable. Their cache modules wrap a shared content-addressed
extracted-tree cache.

``DmgInspector`` selects ``MacOSDiskImage`` on macOS or the 7-Zip path on other
hosts. Native handling verifies, normalizes, mounts read-only, captures license
metadata, and reliably detaches. The fallback has a separate cache version
because its extracted representation and preserved metadata differ.

Platform and tool adapters
--------------------------

Required extraction tools are checked at operation time and raise
``ExternalToolError`` when missing. Optional verification tools—OpenSSL,
``security``, ``codesign``, ``rcodesign``, and WinVerifyTrust—are isolated so
their absence yields an unsupported or unknown status. Platform-specific
imports and native calls do not run merely by importing the public API, which
keeps Linux documentation builds viable.

Adding a backend requires more than extraction: implement robust detection,
safe lifecycle cleanup, a cache namespace/version, relative-path normalization,
model population, expected error translation, platform tests, and updates to
CLI help and capability documentation. Dispatch is explicit; there is no
third-party backend registry or plugin discovery mechanism.

User-visible limitations and tool requirements are canonical in
:ref:`artifact-formats` rather than repeated here.
