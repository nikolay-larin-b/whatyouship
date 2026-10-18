# Changelog

All notable user-facing changes to WhatYouShip are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and version numbers follow [PEP 440](https://peps.python.org/pep-0440/).

## [Unreleased]

## [0.1.0b3] - 2026-10-18

### Added

- Added cryptographic signature verification for Mach-O binaries and macOS application bundles, plus deeper DMG signature verification with actionable diagnostics when complete verification is unavailable.
- Added lint rules for invalid or untrusted binary and application signatures, unsigned application bundles, incompatible bundled architectures, and non-portable Mach-O runtime search paths.
- Added a high-level Python API for `inspect`, `lint`, and `compare`, with structured reports, path-like inputs, and a public exception hierarchy.
- Added comprehensive Sphinx documentation for installation, workflows, configuration, reports, the Python API, and project architecture, with Read the Docs integration.

### Changed

- Extended Mach-O inspection with dynamic-library versions and slice-specific dependency metadata, and marked increased minimum OS requirements as comparison warnings.
- Reported recognized PE and Mach-O analysis failures as diagnostics instead of silently omitting their metadata, and improved external-tool errors with platform-specific installation guidance.

### Fixed

- Prevented false missing-library findings when resolving Mach-O dependencies in application bundles extracted from DMG images.
- Improved cache cleanup around inaccessible entries and hardened normalized DMG cache validation against incomplete or changed content.

## [0.1.0b2] - 2026-10-03

### Added

- Added native macOS and cross-platform 7-Zip backends for inspecting DMG images, including license, signature, and symbolic-link metadata where available.
- Added thin and universal Mach-O analysis for architectures, deployment targets, dependencies, runtime search paths, signatures, Hardened Runtime, and entitlements.
- Added macOS application bundle inspection with structural, dependency, and debug-entitlement lint checks.
- Added commands for inspecting and selectively clearing the persistent artifact cache.

### Changed

- Made extraction caches temporary by default and required explicit `--cache` opt-in for persistent reuse.

### Fixed

- Improved Windows report portability and handling of HFS private directories in extracted DMG images.

## [0.1.0b1] - 2026-09-26

### Added

- Introduced `inspect`, `lint`, and `compare` workflows for directories, MSI packages, ZIP archives, NSIS installers, and Inno Setup installers.
- Added PE metadata and Authenticode inspection, semantic binary comparison, and static MSI installation-scope analysis.
- Added configurable lint rules, baseline classification, and CI-oriented `--fail-on` exit behavior.
- Added text, JSON, and CSV reports plus content-addressed extraction caching.

### Fixed

- Corrected baseline finding matching, common per-machine MSI shortcut false positives, and transient Windows cache promotion failures.

## Initial development - 2026-09-20

- Established the Python package, CLI foundation, project conventions, licensing, and test layout that became the first beta.

[Unreleased]: https://github.com/nikolay-larin-b/whatyouship/compare/v0.1.0b3...HEAD
[0.1.0b3]: https://github.com/nikolay-larin-b/whatyouship/compare/v0.1.0b2...v0.1.0b3
[0.1.0b2]: https://github.com/nikolay-larin-b/whatyouship/compare/v0.1.0b1...v0.1.0b2
[0.1.0b1]: https://github.com/nikolay-larin-b/whatyouship/releases/tag/v0.1.0b1
