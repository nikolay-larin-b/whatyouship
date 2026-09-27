# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Mount disk images through the native macOS disk image service."""

import os
import plistlib
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path


_HDIUTIL = "/usr/bin/hdiutil"


def _failure_detail(result: subprocess.CompletedProcess[bytes]) -> str:
    """Select bounded diagnostics from a failed system command.

    :param result: Completed ``hdiutil`` process.
    :returns: Diagnostic text suitable for a one-line error.
    """
    output = result.stderr or result.stdout
    lines = [
        line.strip()
        for line in output.decode("utf-8", errors="replace").splitlines()
        if line.strip()
    ]
    return " | ".join(lines[-6:])[:1000]


def _reported_mount_point(output: bytes) -> Path:
    """Read the single mounted volume path from ``hdiutil`` plist output.

    :param output: Standard output from ``hdiutil attach -plist``.
    :returns: Absolute path reported for the mounted volume.
    :raises ValueError: If the output is malformed or does not name one volume.
    """
    try:
        document = plistlib.loads(output)
    except (plistlib.InvalidFileException, ValueError, TypeError) as error:
        raise ValueError("hdiutil returned an invalid property list") from error

    if not isinstance(document, dict):
        raise ValueError("hdiutil returned an invalid attachment property list")
    entities = document.get("system-entities")
    if not isinstance(entities, list):
        raise ValueError("hdiutil attachment result has no system entities")

    mount_points: list[Path] = []
    for entity in entities:
        if not isinstance(entity, dict):
            raise ValueError("hdiutil returned an invalid system entity")
        value = entity.get("mount-point")
        if value is None:
            continue
        if not isinstance(value, str) or not value:
            raise ValueError("hdiutil returned an invalid mount point")
        mount_point = Path(value)
        if not mount_point.is_absolute():
            raise ValueError("hdiutil returned a non-absolute mount point")
        mount_points.append(mount_point)

    if len(mount_points) != 1:
        raise ValueError(
            "Disk image must contain exactly one mountable volume; "
            f"found {len(mount_points)}"
        )
    return mount_points[0]


def _remove_empty_mount_directories(mount_point: Path, temporary_root: Path) -> None:
    """Remove empty private mount directories without traversing their contents.

    :param mount_point: Mount point created for the disk image.
    :param temporary_root: Private directory containing the mount point.
    """
    for directory in (mount_point, temporary_root):
        try:
            directory.rmdir()
        except OSError:
            pass


class MacOSDiskImageMounter:
    """Temporarily mount a single-volume disk image on macOS."""

    @contextmanager
    def mount(self, source_path: Path) -> Iterator[Path]:
        """Mount a disk image read-only and detach it after use.

        The mount point is private to this operation. An attachment reported at
        any other path is rejected and is never detached, because it may belong
        to the user or another process.

        :param source_path: Disk image to attach.
        :returns: Context manager yielding the mounted volume root.
        :raises FileNotFoundError: If the image or ``hdiutil`` does not exist.
        :raises IsADirectoryError: If the image path is not a regular file.
        :raises ValueError: If the platform or attachment result is unsupported.
        """
        if sys.platform != "darwin":
            raise ValueError("Disk image mounting requires macOS")
        if not source_path.exists():
            raise FileNotFoundError(f"Disk image does not exist: {source_path}")
        if not source_path.is_file():
            raise IsADirectoryError(f"Disk image is not a file: {source_path}")

        resolved_source = source_path.resolve(strict=True)
        temporary_root = Path(tempfile.mkdtemp(prefix="whatyouship-disk-image-"))
        mount_point = temporary_root / "volume"
        mount_point.mkdir()
        attachment_owned = False
        active_error: BaseException | None = None
        detached = False

        try:
            try:
                result = subprocess.run(
                    [
                        _HDIUTIL,
                        "attach",
                        "-readonly",
                        "-nobrowse",
                        "-noautoopen",
                        "-mountpoint",
                        str(mount_point),
                        "-plist",
                        "-stdinpass",
                        str(resolved_source),
                    ],
                    input=b"\0",
                    capture_output=True,
                    check=False,
                )
            except OSError as error:
                raise FileNotFoundError(
                    f"Unable to run macOS disk image utility '{_HDIUTIL}': {error}"
                ) from error

            if result.returncode != 0:
                detail = _failure_detail(result)
                suffix = f": {detail}" if detail else ""
                raise ValueError(
                    f"hdiutil attach failed with exit code {result.returncode}{suffix}"
                )

            attachment_owned = os.path.ismount(mount_point)
            reported_mount_point = _reported_mount_point(result.stdout)
            if reported_mount_point.resolve() != mount_point.resolve():
                raise ValueError(
                    "hdiutil attached the disk image outside the private mount point; "
                    "the image may already be mounted"
                )

            attachment_owned = True
            yield mount_point
        except BaseException as error:
            active_error = error
            raise
        finally:
            attachment_owned = attachment_owned or os.path.ismount(mount_point)
            if attachment_owned:
                try:
                    self._detach(mount_point)
                    detached = True
                except (OSError, ValueError) as error:
                    if active_error is None:
                        raise
                    active_error.add_note(
                        f"Additionally, disk image cleanup failed: {error}"
                    )

            if not attachment_owned or detached:
                _remove_empty_mount_directories(mount_point, temporary_root)

    def _detach(self, mount_point: Path) -> None:
        """Detach an image through its private mount point.

        :param mount_point: Mounted volume root owned by this operation.
        :raises OSError: If ``hdiutil`` cannot be executed.
        :raises ValueError: If detaching the image fails.
        """
        result = subprocess.run(
            [_HDIUTIL, "detach", str(mount_point)],
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            detail = _failure_detail(result)
            suffix = f": {detail}" if detail else ""
            raise ValueError(
                f"hdiutil detach failed with exit code {result.returncode}{suffix}"
            )
