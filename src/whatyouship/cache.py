# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Inspect and clear the persistent artifact cache."""

import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Callable

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


def _retry_remove_readonly(
    function: Callable[[str], object],
    path: str,
    exception: tuple[type[BaseException], BaseException, TracebackType],
) -> None:
    """Retry removal after restoring owner permissions on one cache path.

    :param function: Removal function that failed.
    :param path: File or directory that could not be removed.
    :param exception: Exception information supplied by :func:`shutil.rmtree`.
    :raises BaseException: If the path is a symbolic link or retry fails.
    """
    target = Path(path)
    if target.is_symlink():
        raise exception[1]
    mode = target.stat(follow_symlinks=False).st_mode
    os.chmod(target, mode | stat.S_IRWXU)
    function(path)


def _remove_path(path: Path) -> None:
    """Remove one cache path without following a symbolic link.

    :param path: Cache path to remove when present.
    :raises OSError: If the path cannot be removed.
    """
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path, onerror=_retry_remove_readonly)


def clear_cache(
    formats: tuple[str, ...] | None = None, root: Path | None = None
) -> CacheInfo:
    """Clear all persistent cache data or selected artifact formats.

    :param formats: Formats to clear, or ``None`` to clear the complete cache.
    :param root: Cache root override for tests, or ``None`` for the user cache.
    :returns: Information about the data selected for removal.
    :raises ValueError: If an unsupported format is requested.
    :raises OSError: If cache data cannot be inspected or removed.
    """
    selected_root = cache_root_directory() if root is None else root
    if formats is None:
        _restore_tree_access(selected_root)
        removed = inspect_cache(selected_root)
        _remove_path(selected_root)
        return removed

    unsupported = sorted(set(formats) - CACHE_FORMAT_NAMESPACES.keys())
    if unsupported:
        raise ValueError(f"Unsupported cache format: {unsupported[0]}")

    selected = set(formats)
    for format_name in selected:
        for namespace in CACHE_FORMAT_NAMESPACES[format_name]:
            _restore_tree_access(selected_root / namespace)
    removed_formats = tuple(
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
    removed = CacheInfo(
        selected_root,
        sum(item.entries for item in removed_formats),
        sum(item.temporary_entries for item in removed_formats),
        sum(item.size_bytes for item in removed_formats),
        removed_formats,
    )
    for format_name in selected:
        for namespace in CACHE_FORMAT_NAMESPACES[format_name]:
            _remove_path(selected_root / namespace)
    if not selected_root.is_symlink() and selected_root.is_dir() and not any(
        selected_root.iterdir()
    ):
        selected_root.rmdir()
    return removed
