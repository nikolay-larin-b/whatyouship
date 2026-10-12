.. _home:

WhatYouShip
===========

**Know what you ship. Know what you install.**

WhatYouShip is an open-source release artifact linter. It inspects the package
that users actually receive, runs release-quality rules, and compares finished
releases. It is not an MSI validator, SBOM generator, or security scanner.

WhatYouShip currently accepts directories, MSI packages, ZIP archives, NSIS
installers, Inno Setup installers, and DMG images. Analysis depth depends on
the format, host platform, and available external tools; see
:ref:`artifact-formats` for the exact support matrix.

Start from the command line::

   whatyouship inspect release.msi
   whatyouship lint release.msi
   whatyouship compare previous.msi release.msi

Or use the structured Python API::

   from whatyouship.operations import inspect

   report = inspect("release.msi")
   for file in report.artifact.files:
       print(file.relative_path, file.sha256)

Choose a route
--------------

* **Use the CLI:** install the tool, then follow the connected scenario in
  :doc:`getting-started/quick-start`.
* **Integrate from Python:** read :doc:`python-api/index` and the selected API
  reference.
* **Understand or change the project:** begin with
  :doc:`development/architecture-overview`.

.. toctree::
   :maxdepth: 2
   :caption: Getting Started

   getting-started/installation
   getting-started/quick-start

.. toctree::
   :maxdepth: 2
   :caption: User Guide

   user-guide/inspecting-artifacts
   user-guide/linting-releases
   user-guide/comparing-releases
   user-guide/configuration
   user-guide/reports-and-ci
   user-guide/cache-management

.. toctree::
   :maxdepth: 2
   :caption: Reference

   reference/cli
   reference/artifact-formats
   reference/lint-rules
   reference/configuration
   reference/report-formats

.. toctree::
   :maxdepth: 2
   :caption: Python API

   python-api/index
   python-api/operations
   python-api/data-models
   python-api/exceptions

.. toctree::
   :maxdepth: 2
   :caption: Architecture & Development

   development/architecture-overview
   development/package-structure-and-models
   development/artifact-processing-pipeline
   development/artifact-backends
   development/lint-and-comparison
   development/testing-and-extending

.. toctree::
   :maxdepth: 1
   :caption: Project

   changelog
