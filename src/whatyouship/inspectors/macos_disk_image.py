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
from dataclasses import dataclass
from pathlib import Path


_HDIUTIL = "/usr/bin/hdiutil"


@dataclass(frozen=True)
class DiskImageMetadata:
    """Describe security-relevant disk image properties.

    :param encrypted: Whether the image payload is encrypted.
    :param license_agreement_present: Whether the image embeds a software
        license agreement.
    """

    encrypted: bool
    license_agreement_present: bool


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


def inspect_disk_image_metadata(source_path: Path) -> DiskImageMetadata:
    """Read disk image metadata without attaching the image.

    :param source_path: Disk image whose metadata should be queried.
    :returns: Parsed disk image properties.
    :raises FileNotFoundError: If ``hdiutil`` cannot be executed.
    :raises ValueError: If metadata cannot be read or is malformed.
    """
    if sys.platform != "darwin":
        raise ValueError("Disk image inspection requires macOS")
    try:
        result = subprocess.run(
            [
                _HDIUTIL,
                "imageinfo",
                "-plist",
                "-stdinpass",
                str(source_path),
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
            f"hdiutil imageinfo failed with exit code {result.returncode}{suffix}"
        )
    try:
        document = plistlib.loads(result.stdout)
    except (plistlib.InvalidFileException, ValueError, TypeError) as error:
        raise ValueError("hdiutil returned invalid disk image metadata") from error
    if not isinstance(document, dict):
        raise ValueError("hdiutil returned invalid disk image metadata")
    properties = document.get("Properties")
    if not isinstance(properties, dict):
        raise ValueError("hdiutil disk image metadata has no properties")
    encrypted = properties.get("Encrypted", False)
    license_agreement = properties.get("Software License Agreement", False)
    if type(encrypted) is not bool or type(license_agreement) is not bool:
        raise ValueError("hdiutil returned invalid disk image properties")
    return DiskImageMetadata(encrypted, license_agreement)


def convert_disk_image(source_path: Path, destination_path: Path) -> None:
    """Convert a disk image to a compressed image without presentation data.

    Conversion preserves the contained filesystem while omitting the source
    image's interactive software license agreement resource.

    :param source_path: Disk image to convert.
    :param destination_path: Exact path for the converted image.
    :raises FileNotFoundError: If ``hdiutil`` cannot be executed.
    :raises ValueError: If conversion fails.
    """
    raw_path = destination_path.parent / "intermediate.cdr"
    try:
        for input_path, output_path, image_format in (
            (source_path, raw_path, "UDTO"),
            (raw_path, destination_path, "UDZO"),
        ):
            try:
                result = subprocess.run(
                    [
                        _HDIUTIL,
                        "convert",
                        str(input_path),
                        "-format",
                        image_format,
                        "-o",
                        str(output_path),
                        "-stdinpass",
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
                    "hdiutil convert failed while creating "
                    f"{image_format} with exit code {result.returncode}{suffix}"
                )
            if output_path.is_symlink() or not output_path.is_file():
                raise ValueError(
                    f"hdiutil did not create the {image_format} disk image"
                )
    finally:
        try:
            raw_path.unlink()
        except FileNotFoundError:
            pass


def verify_disk_image(source_path: Path) -> None:
    """Verify a disk image against its internal checksums.

    :param source_path: Disk image to verify.
    :raises FileNotFoundError: If the image or ``hdiutil`` does not exist.
    :raises IsADirectoryError: If the image path is not a regular file.
    :raises ValueError: If verification is unavailable or fails.
    """
    if sys.platform != "darwin":
        raise ValueError("Disk image verification requires macOS")
    if not source_path.exists():
        raise FileNotFoundError(f"Disk image does not exist: {source_path}")
    if not source_path.is_file():
        raise IsADirectoryError(f"Disk image is not a file: {source_path}")
    try:
        result = subprocess.run(
            [
                _HDIUTIL,
                "verify",
                "-nocache",
                "-stdinpass",
                str(source_path.resolve(strict=True)),
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
            f"hdiutil verify failed with exit code {result.returncode}{suffix}"
        )


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
                if (
                    "attach canceled" in detail.lower()
                    and self._has_license_agreement(resolved_source)
                ):
                    raise ValueError(
                        "Disk image contains an embedded software license "
                        "agreement that cannot be accepted non-interactively"
                    )
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

    def _has_license_agreement(self, source_path: Path) -> bool:
        """Best-effort diagnose an attachment canceled by an agreement.

        :param source_path: Disk image whose metadata should be queried.
        :returns: Whether an embedded agreement is present.
        """
        try:
            return inspect_disk_image_metadata(source_path).license_agreement_present
        except (OSError, ValueError):
            return False

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
