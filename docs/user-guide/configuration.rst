.. _configuring-lint:

Configuring lint policy
=======================

Start with :download:`the complete example
<../../examples/whatyouship.toml>` and keep the project-specific file in source
control. Pass it explicitly:

.. code-block:: console

   $ whatyouship lint release.msi --config whatyouship.toml

Rules can be disabled or assigned ``warning`` or ``error``. The build-artifact
rule also accepts a replacement extension list. Use the same configuration
with ``--baseline``: both current and baseline artifacts are evaluated under
the same policy, which keeps finding identities comparable.

Configuration is strict. Misspelled rule IDs, extra keys, non-boolean
``enabled`` values, invalid severity names, malformed extensions, and invalid
TOML stop the operation with exit code 2. No configuration file is discovered
automatically.

Python callers may pass a path or build an immutable typed configuration:

.. code-block:: python

   from whatyouship.config import LintConfiguration, UnsignedBinarySettings
   from whatyouship.operations import lint

   config = LintConfiguration(
       unsigned_binary=UnsignedBinarySettings(severity="error")
   )
   report = lint("release.msi", config=config)

The exact TOML contract lives in :ref:`configuration-reference`; typed classes
are in :doc:`../python-api/data-models`.

Ignoring an expected finding
----------------------------

Keep a rule enabled for the release while exempting a specific path:

.. code-block:: toml

   [[ignore]]
   rule = "unsigned-binary"
   path = "vendor/helper.exe"
   reason = "Third-party tool distributed without a signature."

The reason is optional. Paths use ``/`` on all platforms; matching is
case-sensitive and rooted at the artifact. Use ``*`` within one path segment
or ``**`` as a complete segment to match nested paths. For example,
``symbols/**/*.pdb`` matches PDB files directly in ``symbols`` and below it.
Use ``.`` for artifact-level findings. Consult :ref:`configuration-reference`
for validation and exact matching rules.

The Python equivalent is:

.. code-block:: python

   from whatyouship.config import LintConfiguration
   from whatyouship.operations import lint
   from whatyouship.suppressions import IgnoreSettings

   config = LintConfiguration(ignore=(
       IgnoreSettings("unsigned-binary", "vendor/helper.exe", "Approved tool."),
   ))
   report = lint("release.zip", config=config)
   suppressed = report.suppressed_findings

Only active findings appear in ``report.findings`` or baseline categories.
Suppressed findings retain their original finding and matching exception.
Text reports show suppression counts; JSON preserves the exception path and
reason. CSV uses separate suppression categories. Select a different
configuration with ``--config`` for release targets with different exceptions.
