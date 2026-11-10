# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Lint rules for release artifacts."""


RULE_IDS = frozenset({
    "build-artifact-extension", "unsigned-binary", "unsigned-artifact",
    "untrusted-binary-signature", "invalid-binary-signature",
    "untrusted-artifact-signature", "invalid-artifact-signature",
    "inconsistent-installation-scope", "missing-license-agreement",
    "invalid-app-bundle", "unsigned-app-bundle",
    "untrusted-app-bundle-signature", "invalid-app-bundle-signature",
    "incompatible-binary-architecture", "debug-entitlement",
    "developer-runtime-search-path", "absolute-runtime-search-path",
})
