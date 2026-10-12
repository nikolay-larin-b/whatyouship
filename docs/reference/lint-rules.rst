.. _lint-rules:

Lint rules reference
====================

All built-in rules are enabled by default. Each rule accepts ``enabled`` and
``severity`` in TOML; :ref:`configuration-reference` defines validation.
Findings depend on metadata WhatYouShip could obtain. An unsupported signature
check, for example, is not treated as an unsigned signature.

File and binary rules
---------------------

``build-artifact-extension`` (warning)
   Reports a file or containing directory whose case-insensitive extension is
   one of ``.ilk``, ``.obj``, ``.iobj``, ``.ipdb``, ``.tlog``,
   ``.lastbuildstate``, or ``.dsym``. ``extensions`` replaces this set.

``unsigned-binary`` (warning)
   Reports recognized PE or Mach-O executables and libraries when signature
   metadata explicitly says no signature is present.

``untrusted-binary-signature`` (warning)
   Reports an executable or library with a present, valid signature whose
   trust result is explicitly false.

``invalid-binary-signature`` (error)
   Reports an executable or library with a present signature whose validity is
   explicitly false.

``debug-entitlement`` (error)
   Reports an enabled ``com.apple.security.get-task-allow`` or
   ``get-task-allow`` entitlement in recognized binary signature metadata.

``developer-runtime-search-path`` (error)
   Reports Mach-O runtime search paths rooted in known user or temporary
   directories such as ``/Users/``, ``/home/``, or ``/tmp/``.

``absolute-runtime-search-path`` (warning)
   Reports other absolute Mach-O runtime search paths. Paths handled by the
   developer-path rule are not duplicated.

Application bundle rules
------------------------

``invalid-app-bundle`` (error)
   Reports structural and metadata issues discovered in macOS ``.app``
   bundles, including invalid ``Info.plist`` values and executable problems.

``incompatible-binary-architecture`` (error)
   Reports a required bundled library that lacks an architecture required by
   the importing Mach-O, where dependency resolution found a bundled target.

``unsigned-app-bundle`` (warning)
   Reports a bundle whose signature status is explicitly ``unsigned``.

``untrusted-app-bundle-signature`` (warning)
   Reports a valid bundle signature without an Apple-trusted identity.

``invalid-app-bundle-signature`` (error)
   Reports an invalid bundle signature or resource seal.

Artifact-level rules
--------------------

``unsigned-artifact`` (warning)
   Reports the outer artifact only when its signature status is explicitly
   ``unsigned``. Unsupported checks do not trigger it.

``untrusted-artifact-signature`` (warning)
   Reports an intact outer signature whose signer is explicitly untrusted.

``invalid-artifact-signature`` (error)
   Reports an outer signature that is cryptographically invalid.

``inconsistent-installation-scope`` (warning)
   Reports each conflict produced by static MSI installation-scope analysis.
   Runtime conditions and installer choices are not evaluated.

``missing-license-agreement`` (error)
   Reports only when the format exposes license-agreement metadata and it
   explicitly states that no agreement is present.

Interpretation limits
---------------------

Severity expresses policy, not certainty. Extraction may be a payload
representation rather than the final installed layout, and trust checks vary
by platform. :ref:`binary-diagnostics` identify files for which binary
metadata is incomplete; they are deliberately not lint findings.
