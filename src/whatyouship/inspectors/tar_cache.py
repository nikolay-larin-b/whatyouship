# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Cache TAR contents without creating archive-supplied filesystem links."""

import json
import shutil
import tarfile
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

from whatyouship.inspectors.extraction_cache import ExtractionCache
from whatyouship.model import ArtifactSymbolicLink, symbolic_link_is_external
from whatyouship.paths import cache_directory


TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz", ".tbz2")


def _member_path(name: str) -> Path:
    """Normalize a TAR path while rejecting unsafe or nonportable components.

    :param name: POSIX member name or archive-root hard-link target.
    :returns: Normalized relative path; ``.`` denotes a root directory entry.
    :raises ValueError: If a path can escape extraction or alias a device.
    """
    if (
        not name or name.startswith("/") or "\\" in name or ":" in name
        or PureWindowsPath(name).is_absolute()
        or any(ord(character) < 32 for character in name)
    ):
        raise ValueError(f"Unsafe TAR entry path: {name!r}")
    parts = [part for part in name.split("/") if part not in ("", ".")]
    reserved = {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    reserved.update(f"{prefix}{number}" for prefix in ("COM", "LPT") for number in "123456789¹²³")
    if any(
        part == ".." or part.endswith((".", " "))
        or part.split(".", 1)[0].rstrip(" ").upper() in reserved
        or any(character in part for character in '<>"|?*')
        for part in parts
    ):
        raise ValueError(f"Unsafe TAR entry path: {name!r}")
    return Path(*parts)


@dataclass(frozen=True)
class TarTree:
    """Hold extracted regular files and archive-native metadata.

    :param files_root: Tree containing regular files and directories only.
    :param symbolic_links: Links represented as metadata, never created on disk.
    :param modes: Original POSIX permission bits indexed by regular file path.
    """

    files_root: Path
    symbolic_links: tuple[ArtifactSymbolicLink, ...]
    modes: dict[Path, int]


class TarExtractionCache:
    """Publish validated TAR payload trees in the versioned extraction cache."""

    def __init__(self) -> None:
        """Select the TAR cache namespace."""
        self._root = cache_directory("tar")

    def load_or_populate(self, digest: str, source_path: Path) -> TarTree:
        """Load a complete entry or extract it through staging.

        :param digest: SHA-256 of the complete source archive.
        :param source_path: TAR archive with optional gzip, xz, or bzip2 compression.
        :returns: Validated file tree and metadata.
        """
        return ExtractionCache(self._root).load_or_populate(
            digest, lambda entry: self._extract(source_path, entry), self._load
        )

    def _extract(self, source_path: Path, entry: Path) -> None:
        """Copy supported members without restoring ownership, links, or host modes.

        :param source_path: Archive to read.
        :param entry: Private staging entry.
        :raises ValueError: If names, links, or member types are unsupported.
        :raises tarfile.TarError: If the archive is malformed.
        """
        files_root = entry / "files"
        files_root.mkdir()
        records = []
        links = []
        with source_path.open("rb") as stream:
            magic = stream.read(6)
        mode = (
            "r:gz" if magic.startswith(b"\x1f\x8b") else
            "r:bz2" if magic.startswith(b"BZh") else
            "r:xz" if magic.startswith(b"\xfd7zXZ\x00") else "r:"
        )
        with tarfile.open(source_path, mode) as archive:
            members: dict[Path, tarfile.TarInfo] = {}
            for member in archive:
                path = _member_path(member.name)
                if path == Path("."):
                    if member.isdir():
                        continue
                    raise ValueError("TAR root entry must be a directory")
                if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                    raise ValueError(f"Unsupported TAR entry type: {member.name!r}")
                if path in members and not (member.isdir() and members[path].isdir()):
                    raise ValueError(f"Conflicting TAR entry path: {member.name!r}")
                members[path] = member
            for path in members:
                for parent in path.parents:
                    if parent in members and not members[parent].isdir():
                        raise ValueError(f"Conflicting TAR entry path: {path.as_posix()!r}")
            for path, member in members.items():
                target = files_root / path
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                if member.issym():
                    if not member.linkname or "\0" in member.linkname:
                        raise ValueError(f"Invalid TAR symbolic link: {member.name!r}")
                    links.append({"relative_path": path.as_posix(), "target": member.linkname})
                    continue
                original = member
                seen = {path}
                while original.islnk():
                    linked = _member_path(original.linkname)
                    if linked in seen or linked not in members:
                        raise ValueError(f"Unresolved TAR hard link: {member.name!r}")
                    seen.add(linked)
                    original = members[linked]
                if not original.isfile():
                    raise ValueError(f"TAR hard link does not target a regular file: {member.name!r}")
                source = archive.extractfile(original)
                if source is None:
                    raise ValueError(f"Unable to read TAR entry: {member.name!r}")
                with source, target.open("xb") as destination:
                    shutil.copyfileobj(source, destination)
                records.append({
                    "relative_path": path.as_posix(), "size_bytes": original.size,
                    "posix_mode": original.mode & 0o7777,
                })
            while archive.fileobj.read(1024 * 1024):
                pass
        (entry / "manifest.json").write_text(
            json.dumps({"version": 1, "files": records, "symbolic_links": links}),
            encoding="utf-8",
        )

    def _load(self, entry: Path) -> TarTree | None:
        """Validate cached regular files and archive-native link/mode metadata.

        :param entry: Candidate cache entry.
        :returns: Complete tree or ``None`` if invalid or inaccessible.
        """
        try:
            root = entry / "files"
            manifest_path = entry / "manifest.json"
            if entry.is_symlink() or root.is_symlink() or not root.is_dir() or manifest_path.is_symlink():
                return None
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
            if (
                not isinstance(data, dict) or type(data.get("version")) is not int
                or data["version"] != 1 or not isinstance(data.get("files"), list)
                or not isinstance(data.get("symbolic_links"), list)
            ):
                return None
            actual = set()
            for path in root.rglob("*"):
                if path.is_symlink():
                    return None
                if path.is_file():
                    actual.add(path.relative_to(root))
                elif not path.is_dir():
                    return None
            modes = {}
            for record in data["files"]:
                if not isinstance(record, dict) or not isinstance(record.get("relative_path"), str):
                    return None
                path = _member_path(record["relative_path"])
                size, mode = record.get("size_bytes"), record.get("posix_mode")
                if (
                    path == Path(".") or path in modes or path not in actual
                    or type(size) is not int or size < 0
                    or type(mode) is not int or not 0 <= mode <= 0o7777
                    or (root / path).stat().st_size != size
                ):
                    return None
                modes[path] = mode
            if set(modes) != actual:
                return None
            links = []
            occupied = set(modes)
            for record in data["symbolic_links"]:
                if not isinstance(record, dict) or not isinstance(record.get("relative_path"), str):
                    return None
                path = _member_path(record["relative_path"])
                target = record.get("target")
                if (
                    path == Path(".") or path in occupied or (root / path).exists()
                    or not isinstance(target, str) or not target or "\0" in target
                ):
                    return None
                occupied.add(path)
                links.append(ArtifactSymbolicLink(path, target, symbolic_link_is_external(path, target)))
            if any(parent in occupied for path in occupied for parent in path.parents):
                return None
            return TarTree(root, tuple(sorted(links, key=lambda link: link.relative_path)), modes)
        except (OSError, ValueError, TypeError, KeyError):
            return None
