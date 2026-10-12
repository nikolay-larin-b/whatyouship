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
