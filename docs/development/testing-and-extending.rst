.. _testing-and-extending:

Testing and extending
=====================

Tests mirror subsystems in ``tests/``: operations and CLI contracts, model and
renderer behavior, lint/configuration/comparison, cache lifecycle, binary
parsers, application bundles, and each artifact backend. Run the suite in the
project environment:

.. code-block:: console

   $ python -m pytest
   $ python -m sphinx -W --keep-going -b html docs /tmp/whatyouship-docs

Tests that require a host platform or native tool should use explicit skips or
mock the adapter boundary. Keep path construction portable with ``pathlib`` and
temporary directories. Cache tests must verify cleanup on success and
exceptions. Backend tests should distinguish detection, extraction, metadata,
and required-tool failures.

Continuous integration
----------------------

The ``Checks`` GitHub Actions workflow in ``.github/workflows/checks.yml`` runs
on pushes, pull requests, and manual requests. Its test matrix covers Python
3.11 and 3.14 on Linux, Windows, and macOS.

Each matrix job builds a wheel, installs it and pytest into a fresh virtual
environment, checks dependency consistency, and runs the test suite outside
the checkout directory. It then runs the installed CLI's version, help,
``inspect``, ``lint``, and ``compare`` commands against a temporary directory
artifact. Native DMG integration tests run on macOS; platform-specific skips
still apply elsewhere. These jobs do not add real MSI, NSIS, or Inno Setup
integration fixtures or native signature-verification scenarios.

A separate Linux job builds the documentation on Python 3.13 with warnings
treated as errors.

After pushing the workflow to GitHub, open the repository's **Actions** tab
and select **Checks** to inspect job logs. To start a manual run, select
**Run workflow** once the workflow is present on the default branch. A failed
job identifies the step and command that failed.

Adding a built-in lint rule
---------------------------

Implement a focused rule in ``whatyouship.rules`` that consumes only
``ReleaseArtifact`` data and returns stable ``Finding`` identities. Add a typed
settings field and TOML validation in ``config.py``, include the rule in
``LintConfiguration.rules()`` order, then test default/configured behavior,
baseline identity, CLI gating, and rendering. Update :ref:`lint-rules` and
:ref:`configuration-reference` in the same change.

Adding an artifact format
-------------------------

Keep detection and external tooling behind an inspector/adapter. Define safe
extraction cleanup and cache versioning, feed extracted content through shared
analysis where possible, and translate expected failures into the public error
contract. Add cross-platform tests plus explicit platform-specific cases. Then
update CLI help, :ref:`artifact-formats`, cache management, and architecture.

Extension status
----------------

``LintRule`` and inspector boundaries make built-in development tractable, but
they are internal seams. There is currently no supported plugin API for custom
rules or artifact backends: no discovery, packaging, namespace, compatibility,
or failure-isolation contract exists. Third-party code should rely only on the
documented Python API until such a contract is designed explicitly.
