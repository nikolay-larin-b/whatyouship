.. _artifact-processing-pipeline:

Artifact processing pipeline
============================

An operation enters a cache scope before inspecting any input. The default
scope creates a temporary directory and removes it in ``finally``-style context
manager cleanup. Explicit ``cache=True`` selects the persistent root, allowing
both sides of a comparison or lint baseline to share extraction results.

Routing and normalization
-------------------------

``inspect_artifact`` normalizes a ``str`` or ``os.PathLike`` once to
``pathlib.Path``, validates existence, then dispatches explicitly. Directories
go to ``DirectoryInspector``. Files are tested for MSI, ZIP, DMG, NSIS, and
Inno Setup using backend detection logic rather than extensions alone where a
reliable signature exists. An unmatched file raises
``UnsupportedArtifactError``.

Container flow
--------------

.. code-block:: text

   source ─> detect ─> hash/cache lookup ─> extract/normalize
                                             │
                                             v
                              DirectoryInspector / MSI payload walk
                                  │      │       │       │
                                  hash   PE/Mach-O/ELF   .app bundles
                                  │      └── diagnostics ─┘
                                  v
                            ReleaseArtifact ─> operation report

ZIP, NSIS, Inno, and DMG backends extract or mount content and reuse shared
directory-tree analysis. MSI has specialized table extraction and scope
analysis, then builds the same file, PE, and ELF models. Paths stored in models are
relative and portable; hashes cover file content.

Best-effort binary analysis
---------------------------

For each file, ``DirectoryInspector`` asks ``PeInspector``, ``MachOInspector``,
and ``ElfInspector`` for metadata in order. ``None`` means the format was not recognized.
Successful parsing returns ``BinaryMetadata``. An expected parser failure after
recognition raises internal ``BinaryAnalysisError`` with format and reason;
the container inspector records ``BinaryAnalysisDiagnostic`` and leaves the
file's binary metadata ``None``. MSI performs the same per-payload recovery.

PE recognition validates both the DOS and PE signatures. Mach-O uses its magic
values. ELF uses its magic, identification fields, and complete class-specific
header. ``ElfInspector`` reads architecture and kind; ET_DYN with PT_INTERP or
DF_1_PIE is classified as executable, while other ET_DYN files are libraries.
DT_NEEDED entries populate shared ``BinaryDependency`` records. DT_RPATH maps
to ``runtime_search_paths`` and DT_RUNPATH to ``runtime_run_paths``; these
remain distinct rather than modeling host loader policy. PT_INTERP and
DT_SONAME populate ``interpreter`` and ``library_name``. Strings are read
statically without token expansion or host dependency resolution.
MSI payload analysis tries PE followed by ELF. ELF signature metadata remains
unavailable. Optional signature-tool absence produces unknown/unsupported signature
state, not a malformed-binary diagnostic. Unexpected exceptions propagate so
defects remain visible.

After inspection, ``operations.inspect`` wraps the artifact directly;
``operations.lint`` loads/configures rules and may inspect a baseline;
``operations.compare`` inspects both artifacts. Renderers run only after these
structured results exist.
