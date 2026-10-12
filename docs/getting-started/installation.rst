.. _installation:

Installation and requirements
=============================

WhatYouShip is published on PyPI. Install it into a Python 3.11 or newer
environment:

.. code-block:: console

   $ python -m pip install whatyouship
   $ whatyouship --version

The current PyPI release is a prerelease. Use an isolated virtual environment
for predictable dependency resolution. The Python package supplies the CLI and
public API; some artifact formats additionally require native tools.

.. _installation-tools:

External tools
--------------

.. list-table::
   :header-rows: 1

   * - Tool
     - Required for
     - Hosts
     - Discovery
   * - 7-Zip
     - NSIS extraction; DMG extraction outside macOS
     - Linux, Windows, macOS for NSIS
     - ``7zz``, ``7z``, or ``7z.exe`` in ``PATH``
   * - ``innoextract``
     - Inno Setup extraction
     - All
     - ``innoextract`` in ``PATH``
   * - ``hdiutil``
     - Native DMG handling
     - macOS
     - System tool
   * - ``codesign``
     - Native DMG, Mach-O, and app-bundle verification
     - macOS
     - System ``/usr/bin/codesign``
   * - ``rcodesign``
     - Optional DMG signature verification fallback
     - All
     - ``rcodesign`` in ``PATH``
   * - OpenSSL
     - Optional Mach-O CMS signature details
     - All
     - ``openssl`` in ``PATH``
   * - ``security``
     - Optional Apple trust evaluation
     - macOS
     - System tool
   * - WinVerifyTrust
     - Authenticode trust for PE/MSI/installer files
     - Windows
     - Operating-system API

Required extractors cause an operation error when a matching artifact must be
extracted and the tool is unavailable. Optional signature tools instead leave
status unknown or unsupported. A persistent cache hit may avoid rerunning an
extractor, but relying on that is not a deployment substitute for installing
required tools.

Common installation commands
----------------------------

Install `7-Zip <https://www.7-zip.org/download.html>`_ from its official
Windows packages, with ``brew install sevenzip`` on macOS, ``sudo apt install
7zip`` on Debian/Ubuntu, ``sudo dnf install 7zip`` on Fedora, or ``sudo pacman
-S 7zip`` on Arch/Manjaro. Install
`innoextract <https://constexpr.org/innoextract/>`_ from its Windows packages,
with ``brew install innoextract``, or with the corresponding
``apt``, ``dnf``, or ``pacman`` package.

OpenSSL is commonly installed as ``openssl`` through the same platform package
manager. For cross-platform Apple signature verification, install a prebuilt
`apple-codesign release
<https://github.com/indygreg/apple-platform-rs/releases>`_ or run ``cargo
install apple-codesign`` and ensure ``rcodesign`` is in ``PATH``. macOS system
tools need no separate installation.

See :ref:`artifact-formats` for platform-specific analysis depth and
:doc:`quick-start` for a first workflow.
