# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect and clear the persistent artifact cache."""

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from whatyouship.paths import cache_root_directory


CACHE_FORMAT_NAMESPACES: dict[str, tuple[str, ...]] = {
    "msi": ("msi",),
    "nsis": ("nsis",),
    "inno": ("inno",),
    "zip": ("zip",),
    "dmg": ("dmg", "dmg-7zip"),
}


@dataclass(frozen=True)
class CacheFormatInfo:
    """Summarize persistent cache data for one artifact format.

    :param format_name: User-facing artifact format name.
    :param entries: Number of completed cache entries.
    :param temporary_entries: Number of interrupted staging entries.
    :param size_bytes: Logical size of files below the format namespaces.
    :param layouts: Present namespace and layout version pairs.
    """

    format_name: str
    entries: int
    temporary_entries: int
    size_bytes: int
    layouts: tuple[str, ...]


@dataclass(frozen=True)
class CacheInfo:
    """Summarize the persistent artifact cache.

    :param root: Persistent cache root.
    :param entries: Total number of completed cache entries.
    :param temporary_entries: Total number of interrupted staging entries.
    :param size_bytes: Logical size of all files below the cache root.
    :param formats: Per-format cache summaries.
    """

    root: Path
    entries: int
    temporary_entries: int
    size_bytes: int
    formats: tuple[CacheFormatInfo, ...]


@dataclass(frozen=True)
class CacheRemovalFailure:
    """Describe one cache path that could not be removed.

    :param path: Cache path left on disk.
    :param error: Operating-system error reported for the path.
    """

    path: Path
    error: str


@dataclass(frozen=True)
class CacheClearResult:
    """Describe the result of a best-effort cache cleanup.

    :param root: Persistent cache root.
    :param selected: Data selected before removal, or ``None`` when it could
        not be fully inspected.
    :param failures: Paths that could not be removed.
    """

    root: Path
    selected: CacheInfo | None
    failures: tuple[CacheRemovalFailure, ...]


def _path_size(path: Path) -> int:
    """Calculate logical file size without following symbolic links.

    :param path: File or directory to measure.
    :returns: Total size in bytes, including symbolic link records themselves.
    :raises OSError: If the path cannot be inspected.
    """
    if path.is_symlink() or not path.is_dir():
        return path.lstat().st_size

    size = 0
    pending = [path]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as children:
            for child in children:
                if child.is_symlink():
                    size += child.stat(follow_symlinks=False).st_size
                elif child.is_dir(follow_symlinks=False):
                    pending.append(Path(child.path))
                else:
                    size += child.stat(follow_symlinks=False).st_size
    return size


def _namespace_info(
    root: Path, namespace: str
) -> tuple[int, int, int, tuple[str, ...]]:
    """Summarize one internal cache namespace.

    :param root: Persistent cache root.
    :param namespace: Internal backend cache directory name.
    :returns: Completed entries, temporary entries, bytes, and layouts.
    :raises OSError: If cache data cannot be inspected.
    """
    namespace_root = root / namespace
    if not namespace_root.exists() and not namespace_root.is_symlink():
        return 0, 0, 0, ()
    if namespace_root.is_symlink() or not namespace_root.is_dir():
        return 0, 0, _path_size(namespace_root), ()

    entries = 0
    temporary_entries = 0
    layouts: list[str] = []
    for version in sorted(namespace_root.iterdir(), key=lambda path: path.name):
        if version.is_symlink() or not version.is_dir():
            continue
        layouts.append(f"{namespace}/{version.name}")
        for entry in version.iterdir():
            if entry.name.startswith(".tmp-"):
                temporary_entries += 1
            else:
                entries += 1
    return entries, temporary_entries, _path_size(namespace_root), tuple(layouts)


def _format_info(
    root: Path, format_name: str, namespaces: tuple[str, ...]
) -> CacheFormatInfo | None:
    """Summarize the cache namespaces belonging to one artifact format.

    :param root: Persistent cache root.
    :param format_name: User-facing artifact format name.
    :param namespaces: Internal cache namespaces belonging to the format.
    :returns: Format information, or ``None`` when no cache data is present.
    :raises OSError: If cache data cannot be inspected.
    """
    entries = 0
    temporary_entries = 0
    size_bytes = 0
    layouts: list[str] = []
    for namespace in namespaces:
        (
            namespace_entries,
            namespace_temporary,
            namespace_size,
            namespace_layouts,
        ) = _namespace_info(root, namespace)
        entries += namespace_entries
        temporary_entries += namespace_temporary
        size_bytes += namespace_size
        layouts.extend(namespace_layouts)
    if not (entries or temporary_entries or size_bytes or layouts):
        return None
    return CacheFormatInfo(
        format_name,
        entries,
        temporary_entries,
        size_bytes,
        tuple(layouts),
    )


def inspect_cache(root: Path | None = None) -> CacheInfo:
    """Inspect the persistent artifact cache without modifying it.

    :param root: Cache root override for tests, or ``None`` for the user cache.
    :returns: Aggregate and per-format cache information.
    :raises OSError: If cache data cannot be inspected.
    """
    selected_root = cache_root_directory() if root is None else root
    if not selected_root.exists() and not selected_root.is_symlink():
        return CacheInfo(selected_root, 0, 0, 0, ())

    namespace_formats = {
        namespace: format_name
        for format_name, namespaces in CACHE_FORMAT_NAMESPACES.items()
        for namespace in namespaces
    }
    present_namespaces = (
        {path.name for path in selected_root.iterdir()}
        if selected_root.is_dir() and not selected_root.is_symlink()
        else set()
    )
    format_names = set(CACHE_FORMAT_NAMESPACES)
    format_names.update(
        namespace
        for namespace in present_namespaces
        if namespace not in namespace_formats
    )

    formats: list[CacheFormatInfo] = []
    for format_name in sorted(format_names):
        namespaces = CACHE_FORMAT_NAMESPACES.get(format_name, (format_name,))
        info = _format_info(selected_root, format_name, namespaces)
        if info is not None:
            formats.append(info)

    return CacheInfo(
        selected_root,
        sum(item.entries for item in formats),
        sum(item.temporary_entries for item in formats),
        _path_size(selected_root),
        tuple(formats),
    )


def _restore_tree_access(path: Path) -> None:
    """Restore owner access where a cache directory cannot be traversed.

    Symbolic links are never followed or modified.

    :param path: Cache tree that is about to be removed.
    :raises OSError: If access cannot be restored or the tree cannot be read.
    """
    if path.is_symlink() or not path.is_dir():
        return

    pending = [path]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                children = list(iterator)
        except PermissionError:
            os.chmod(directory, stat.S_IRWXU)
            with os.scandir(directory) as iterator:
                children = list(iterator)
        pending.extend(
            Path(child.path)
            for child in children
            if child.is_dir(follow_symlinks=False) and not child.is_symlink()
        )


def _restore_owner_permissions(path: Path) -> None:
    """Add owner permissions without following a symbolic link.

    :param path: File or directory whose access must be restored.
    :raises OSError: If metadata cannot be read or permissions cannot be changed.
    """
    mode = path.stat(follow_symlinks=False).st_mode
    os.chmod(path, mode | stat.S_IRWXU)


def _record_removal_failure(
    failures: list[CacheRemovalFailure], path: Path, error: OSError
) -> None:
    """Record one removal error for a cache path.

    :param failures: Mutable failure collection.
    :param path: Cache path left on disk.
    :param error: Operating-system error reported for the path.
    """
    failures.append(CacheRemovalFailure(path, str(error)))


def _remove_path_best_effort(
    path: Path, failures: list[CacheRemovalFailure]
) -> None:
    """Remove a cache tree while continuing past independent failures.

    Symbolic links are unlinked without being followed. Directories are removed
    bottom-up so an inaccessible child does not prevent attempts on its siblings.

    :param path: Cache path to remove when present.
    :param failures: Mutable collection for paths that remain on disk.
    """
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as error:
        _record_removal_failure(failures, path, error)
        return

    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        try:
            path.unlink()
        except PermissionError as error:
            if stat.S_ISLNK(metadata.st_mode):
                _record_removal_failure(failures, path, error)
                return
            try:
                _restore_owner_permissions(path)
                path.unlink()
            except OSError as error:
                _record_removal_failure(failures, path, error)
        except FileNotFoundError:
            pass
        except OSError as error:
            _record_removal_failure(failures, path, error)
        return

    try:
        with os.scandir(path) as iterator:
            children = [Path(child.path) for child in iterator]
    except PermissionError:
        try:
            _restore_owner_permissions(path)
            with os.scandir(path) as iterator:
                children = [Path(child.path) for child in iterator]
        except OSError as error:
            _record_removal_failure(failures, path, error)
            return
    except OSError as error:
        _record_removal_failure(failures, path, error)
        return

    failures_before_children = len(failures)
    for child in children:
        _remove_path_best_effort(child, failures)
    if len(failures) != failures_before_children:
        return

    try:
        path.rmdir()
    except PermissionError:
        try:
            _restore_owner_permissions(path)
            path.rmdir()
        except OSError as error:
            _record_removal_failure(failures, path, error)
    except FileNotFoundError:
        pass
    except OSError as error:
        _record_removal_failure(failures, path, error)


def _remove_path(path: Path) -> tuple[CacheRemovalFailure, ...]:
    """Remove one cache path without following symbolic links.

    :param path: Cache path to remove when present.
    :returns: Paths that could not be removed.
    """
    failures: list[CacheRemovalFailure] = []
    _remove_path_best_effort(path, failures)
    return tuple(failures)


def clear_cache(
    formats: tuple[str, ...] | None = None, root: Path | None = None
) -> CacheClearResult:
    """Clear all persistent cache data or selected artifact formats.

    :param formats: Formats to clear, or ``None`` to clear the complete cache.
    :param root: Cache root override for tests, or ``None`` for the user cache.
    :returns: Selection information and paths that could not be removed.
    :raises ValueError: If an unsupported format is requested.
    """
    selected_root = cache_root_directory() if root is None else root
    if formats is None:
        try:
            _restore_tree_access(selected_root)
            selected_info = inspect_cache(selected_root)
        except OSError:
            selected_info = None
        failures = _remove_path(selected_root)
        return CacheClearResult(selected_root, selected_info, failures)

    unsupported = sorted(set(formats) - CACHE_FORMAT_NAMESPACES.keys())
    if unsupported:
        raise ValueError(f"Unsupported cache format: {unsupported[0]}")

    selected = set(formats)
    try:
        for format_name in sorted(selected):
            for namespace in CACHE_FORMAT_NAMESPACES[format_name]:
                _restore_tree_access(selected_root / namespace)
        selected_formats = tuple(
            info
            for format_name in sorted(selected)
            if (
                info := _format_info(
                    selected_root,
                    format_name,
                    CACHE_FORMAT_NAMESPACES[format_name],
                )
            )
            is not None
        )
        selected_info = CacheInfo(
            selected_root,
            sum(item.entries for item in selected_formats),
            sum(item.temporary_entries for item in selected_formats),
            sum(item.size_bytes for item in selected_formats),
            selected_formats,
        )
    except OSError:
        selected_info = None

    failures: list[CacheRemovalFailure] = []
    for format_name in sorted(selected):
        for namespace in CACHE_FORMAT_NAMESPACES[format_name]:
            failures.extend(_remove_path(selected_root / namespace))
    if not selected_root.is_symlink() and selected_root.is_dir():
        try:
            root_is_empty = not any(selected_root.iterdir())
        except OSError as error:
            _record_removal_failure(failures, selected_root, error)
        else:
            if root_is_empty:
                failures.extend(_remove_path(selected_root))
    return CacheClearResult(selected_root, selected_info, tuple(failures))
