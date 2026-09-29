# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Cache single-volume DMG trees extracted by 7-Zip."""

import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any

from whatyouship.inspectors.extracted_tree_cache import ExtractedTreeCache
from whatyouship.model import ArtifactSymbolicLink, symbolic_link_is_external
from whatyouship.paths import cache_directory


_SEVEN_ZIP_NAMES = ("7zz", "7z", "7z.exe")
_SEVEN_ZIP_REQUIRED = (
    "DMG extraction requires 7-Zip. Add '7z' or '7zz' to PATH."
)
_FILESYSTEM_TYPES = {"APFS", "HFS"}
_MAX_LINK_TARGET_SIZE = 1024 * 1024
_LINK_ARGUMENT_LIMIT = 16 * 1024
_HFS_PRIVATE_DIRECTORY_NAMES = {
    ".HFS+ Private Directory Data_",
    "[HFS+ Private Data]",
}


@dataclass(frozen=True)
class DmgExtractedVolume:
    """Describe an extracted DMG volume and non-materialized links.

    :param root: Directory containing extracted regular files.
    :param symbolic_links: Symbolic links read from archive metadata.
    """

    root: Path
    symbolic_links: tuple[ArtifactSymbolicLink, ...]


@dataclass(frozen=True)
class _ListedLink:
    """Describe one symbolic-link entry in a 7-Zip listing."""

    path: str
    size: int
    target: str | None = None


def find_7zip() -> str:
    """Find a supported 7-Zip executable using ``PATH`` only.

    :returns: Resolved executable path.
    :raises FileNotFoundError: If no supported executable is on ``PATH``.
    """
    for name in _SEVEN_ZIP_NAMES:
        executable = shutil.which(name)
        if executable is not None:
            return executable
    raise FileNotFoundError(_SEVEN_ZIP_REQUIRED)


def _output_text(value: str | bytes) -> str:
    """Decode subprocess output for diagnostics.

    :param value: Text or raw process output.
    :returns: Decoded text with invalid bytes replaced.
    """
    return value if isinstance(value, str) else value.decode("utf-8", "replace")


def _failure_detail(result: subprocess.CompletedProcess[Any]) -> str:
    """Select bounded diagnostics from a failed 7-Zip command.

    :param result: Completed 7-Zip process.
    :returns: Diagnostic text suitable for a one-line error.
    """
    output = _output_text(result.stderr).strip() or _output_text(result.stdout).strip()
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return " | ".join(lines[-6:])[:1000]


def _archive_types(output: str) -> list[str]:
    """Read archive types from 7-Zip technical listing output.

    :param output: Standard output from ``7z l -slt``.
    :returns: Archive types in traversal order.
    """
    prefix = "Type = "
    return [
        line[len(prefix):].strip()
        for line in output.splitlines()
        if line.startswith(prefix)
    ]


def _technical_records(output: str) -> tuple[dict[str, str], ...]:
    """Parse records from a 7-Zip technical listing.

    :param output: Standard output from ``7z l -slt``.
    :returns: Key/value records in archive order.
    """
    records = []
    current: dict[str, str] = {}
    for line in output.splitlines():
        if not line:
            if current:
                records.append(current)
                current = {}
            continue
        key, separator, value = line.partition(" = ")
        if separator:
            current[key] = value
    if current:
        records.append(current)
    return tuple(records)


def _listed_links(output: str) -> tuple[_ListedLink, ...]:
    """Read symbolic-link records from a technical listing.

    :param output: Standard output from ``7z l -slt``.
    :returns: Link paths, target byte sizes, and directly reported targets.
    :raises ValueError: If a link record is incomplete or unreasonable.
    """
    links = []
    for record in _technical_records(output):
        if not record.get("Mode", "").startswith("l"):
            continue
        path = record.get("Path")
        size_text = record.get("Size")
        if path is None or size_text is None:
            raise ValueError("7-Zip reported an incomplete symbolic-link record")
        try:
            size = int(size_text)
        except ValueError as error:
            raise ValueError("7-Zip reported an invalid symbolic-link size") from error
        if size <= 0 or size > _MAX_LINK_TARGET_SIZE:
            raise ValueError("7-Zip reported an invalid symbolic-link target size")
        links.append(_ListedLink(path, size, record.get("Symbolic Link")))
    return tuple(links)


def _relative_link_path(archive_path: str, volume_name: str) -> Path:
    """Convert a listed archive path to a safe volume-relative path.

    :param archive_path: POSIX path emitted by 7-Zip.
    :param volume_name: Extracted top-level volume directory name.
    :returns: Safe path relative to the volume root.
    :raises ValueError: If the path is absolute, ambiguous, or outside the volume.
    """
    path = PurePosixPath(archive_path.replace("\\", "/"))
    if (
        path.is_absolute()
        or len(path.parts) < 2
        or path.parts[0] != volume_name
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("7-Zip reported an unsafe symbolic-link path")
    return Path(*path.parts[1:])


def _hfs_private_directories(listing: str) -> tuple[Path, ...]:
    """Find empty HFS implementation directories exposed by 7-Zip.

    These directories contain filesystem bookkeeping rather than mounted-volume
    contents. Populated directories can back HFS hard links and are rejected
    until the 7-Zip backend can prove that every link was resolved correctly.

    :param listing: Technical listing emitted by ``7z l -slt``.
    :returns: Safe paths of empty private directories.
    :raises ValueError: If a private-directory path is unsafe or populated.
    """
    records = _technical_records(listing)
    listed_paths = tuple(
        PurePosixPath(record["Path"].replace("\\", "/"))
        for record in records
        if "Path" in record
    )
    private_paths = []
    for record in records:
        archive_path = record.get("Path")
        if (
            archive_path is None
            or record.get("Folder") != "+"
            or record.get("Mode", "")[:1] != "d"
        ):
            continue
        path = PurePosixPath(archive_path.replace("\\", "/"))
        if len(path.parts) != 2 or path.name not in _HFS_PRIVATE_DIRECTORY_NAMES:
            continue
        if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise ValueError("7-Zip reported an unsafe HFS private-directory path")
        if any(
            len(other.parts) > len(path.parts)
            and other.parts[:len(path.parts)] == path.parts
            for other in listed_paths
        ):
            raise ValueError(
                "7-Zip reported a populated HFS private directory; "
                "HFS hard links are not supported"
            )
        private_paths.append(Path(*path.parts))
    return tuple(private_paths)


def _discard_hfs_private_directories(
    private_paths: tuple[Path, ...], files_root: Path
) -> None:
    """Remove empty HFS implementation directories extracted by 7-Zip.

    7-Zip can apply their HFS modes on Windows, making the extracted tree
    impossible to traverse or clean up until owner permissions are restored.

    :param private_paths: Validated empty private-directory paths.
    :param files_root: Temporary directory containing the extracted volume.
    :raises ValueError: If a private directory materializes as a symbolic link.
    """
    for path in private_paths:
        extracted = files_root / path
        if extracted.is_symlink():
            raise ValueError("7-Zip extracted an unsafe HFS private-directory link")
        if extracted.is_dir():
            os.chmod(extracted, stat.S_IRWXU)
            shutil.rmtree(extracted)


def _decode_target(data: bytes, expected_size: int) -> str:
    """Decode one bounded symbolic-link target.

    :param data: Raw target bytes stored in the filesystem entry.
    :param expected_size: Size reported by the technical listing.
    :returns: UTF-8 target text.
    :raises ValueError: If the data is truncated, invalid, or empty.
    """
    if len(data) != expected_size:
        raise ValueError("7-Zip returned inconsistent symbolic-link target data")
    try:
        target = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("7-Zip returned a non-UTF-8 symbolic-link target") from error
    if not target or "\x00" in target:
        raise ValueError("7-Zip returned an invalid symbolic-link target")
    return target


def _link_batches(
    links: tuple[_ListedLink, ...],
) -> tuple[tuple[_ListedLink, ...], ...]:
    """Bound command-line size while preserving archive entry order.

    :param links: Listed links whose target data must be extracted.
    :returns: Ordered link batches.
    """
    batches = []
    current: list[_ListedLink] = []
    size = 0
    for link in links:
        argument_size = len(link.path.encode("utf-8")) + 1
        if current and size + argument_size > _LINK_ARGUMENT_LIMIT:
            batches.append(tuple(current))
            current = []
            size = 0
        current.append(link)
        size += argument_size
    if current:
        batches.append(tuple(current))
    return tuple(batches)


class DmgSevenZipExtractionCache:
    """Store regular files from a single-volume DMG by source digest."""

    def __init__(self) -> None:
        """Select the versioned 7-Zip DMG cache directory."""
        self._root = cache_directory("dmg-7zip", "v2")

    def load_or_populate(self, digest: str, source_path: Path) -> DmgExtractedVolume:
        """Return the single extracted volume root.

        :param digest: SHA-256 of the complete DMG artifact.
        :param source_path: DMG artifact to extract on a cache miss.
        :returns: Extracted volume and symbolic-link metadata.
        :raises FileNotFoundError: If 7-Zip is unavailable.
        :raises ValueError: If the image cannot be inspected or extracted.
        """
        entry = ExtractedTreeCache(
            self._root, "7-Zip"
        ).load_or_populate_with_metadata(
            digest,
            lambda output: self._extract(source_path, output),
            self._validate_metadata,
        )
        volume_root = self._volume_root(entry.files_root)
        links = tuple(
            ArtifactSymbolicLink(
                Path(record["relative_path"]),
                record["target"],
                symbolic_link_is_external(
                    Path(record["relative_path"]), record["target"]
                ),
            )
            for record in entry.metadata["symbolic_links"]
            if isinstance(record, dict)
            and isinstance(record.get("relative_path"), str)
            and isinstance(record.get("target"), str)
        )
        return DmgExtractedVolume(volume_root, links)

    def _extract(
        self, source_path: Path, files_root: Path
    ) -> dict[str, object]:
        """Validate and extract one DMG filesystem into staging.

        Symbolic links are read as metadata without creating or following them.
        Alternate streams are omitted.

        :param source_path: DMG artifact to extract.
        :param files_root: Temporary directory for extracted files.
        :raises FileNotFoundError: If 7-Zip is unavailable.
        :returns: Symbolic-link records for the cache manifest.
        :raises ValueError: If listing, extraction, or link parsing fails.
        """
        executable = find_7zip()
        listing = subprocess.run(
            [executable, "l", "-slt", "-sccUTF-8", "-bd", str(source_path)],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        if listing.returncode != 0:
            detail = _failure_detail(listing)
            suffix = f": {detail}" if detail else ""
            raise ValueError(
                f"7-Zip DMG listing failed with exit code "
                f"{listing.returncode}{suffix}"
            )
        types = _archive_types(listing.stdout)
        filesystems = [value for value in types if value in _FILESYSTEM_TYPES]
        if not types or types[0] != "Dmg" or len(filesystems) != 1:
            raise ValueError(
                "7-Zip did not find exactly one supported filesystem in the DMG"
            )
        private_paths = _hfs_private_directories(listing.stdout)

        result = subprocess.run(
            [
                executable,
                "x",
                "-y",
                "-bd",
                "-bb0",
                "-sns-",
                "-snl-",
                "-sccUTF-8",
                f"-o{files_root}",
                str(source_path),
            ],
            capture_output=True,
            text=True,
            errors="replace",
            check=False,
        )
        if result.returncode != 0:
            detail = _failure_detail(result)
            suffix = f": {detail}" if detail else ""
            raise ValueError(
                f"7-Zip DMG extraction failed with exit code "
                f"{result.returncode}{suffix}"
            )
        _discard_hfs_private_directories(private_paths, files_root)
        volume_root = self._volume_root(files_root)
        links = self._extract_links(
            executable,
            source_path,
            volume_root.name,
            _listed_links(listing.stdout),
        )
        return {
            "symbolic_links": [
                {
                    "relative_path": link.relative_path.as_posix(),
                    "target": link.target,
                }
                for link in links
            ]
        }

    def _extract_links(
        self,
        executable: str,
        source_path: Path,
        volume_name: str,
        listed: tuple[_ListedLink, ...],
    ) -> tuple[ArtifactSymbolicLink, ...]:
        """Read link targets through standard output without materializing them.

        :param executable: Resolved 7-Zip executable.
        :param source_path: DMG artifact containing the entries.
        :param volume_name: Extracted volume directory name.
        :param listed: Symbolic links found in the technical listing.
        :returns: Safe volume-relative link metadata.
        :raises ValueError: If target extraction or decoding fails.
        """
        relative_paths: dict[str, Path] = {}
        seen: set[Path] = set()
        for link in listed:
            relative_path = _relative_link_path(link.path, volume_name)
            if relative_path in seen or link.path in relative_paths:
                raise ValueError("7-Zip reported a duplicate symbolic-link path")
            seen.add(relative_path)
            relative_paths[link.path] = relative_path

        targets: dict[str, str] = {}
        pending = tuple(link for link in listed if link.target is None)
        for link in listed:
            if link.target is not None:
                targets[link.path] = _decode_target(
                    link.target.encode("utf-8"), link.size
                )
        for batch in _link_batches(pending):
            result = subprocess.run(
                [
                    executable,
                    "x",
                    "-so",
                    "-snl-",
                    "-spd",
                    "-sccUTF-8",
                    str(source_path),
                    "--",
                    *(link.path for link in batch),
                ],
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                detail = _failure_detail(result)
                suffix = f": {detail}" if detail else ""
                raise ValueError(
                    f"7-Zip symbolic-link extraction failed with exit code "
                    f"{result.returncode}{suffix}"
                )
            output = bytes(result.stdout)
            expected_size = sum(link.size for link in batch)
            if len(output) != expected_size:
                raise ValueError(
                    "7-Zip returned inconsistent symbolic-link target data"
                )
            offset = 0
            for link in batch:
                targets[link.path] = _decode_target(
                    output[offset:offset + link.size], link.size
                )
                offset += link.size

        links = []
        for link in listed:
            relative_path = relative_paths[link.path]
            target = targets[link.path]
            links.append(ArtifactSymbolicLink(
                relative_path,
                target,
                symbolic_link_is_external(relative_path, target),
            ))
        return tuple(links)

    def _validate_metadata(self, value: object) -> dict[str, object] | None:
        """Validate cached symbolic-link records.

        :param value: Manifest metadata value.
        :returns: Normalized metadata, or ``None`` when invalid.
        """
        if not isinstance(value, dict) or set(value) != {"symbolic_links"}:
            return None
        records = value["symbolic_links"]
        if not isinstance(records, list):
            return None
        validated = []
        seen: set[Path] = set()
        for record in records:
            if not isinstance(record, dict) or set(record) != {
                "relative_path", "target"
            }:
                return None
            name = record["relative_path"]
            target = record["target"]
            if not isinstance(name, str) or not isinstance(target, str):
                return None
            path = Path(name)
            if (
                path.is_absolute()
                or path.parts in {(), (".",)}
                or ".." in path.parts
                or path in seen
                or not target
                or "\x00" in target
                or len(target.encode("utf-8")) > _MAX_LINK_TARGET_SIZE
            ):
                return None
            seen.add(path)
            validated.append({"relative_path": path.as_posix(), "target": target})
        return {"symbolic_links": validated}

    def _volume_root(self, files_root: Path) -> Path:
        """Select the only top-level directory produced for the volume.

        :param files_root: Validated extraction root.
        :returns: Single extracted volume directory.
        :raises ValueError: If extraction did not produce one volume root.
        """
        entries = list(files_root.iterdir())
        if len(entries) != 1 or entries[0].is_symlink() or not entries[0].is_dir():
            raise ValueError(
                "7-Zip did not extract exactly one DMG volume directory"
            )
        return entries[0]
