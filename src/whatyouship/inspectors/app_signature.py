# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Verify macOS application bundle signatures with ``codesign``."""

import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from whatyouship.macos_tools import CODESIGN
from whatyouship.model import ArtifactSignature, ArtifactSignatureStatus


def _parse_timestamp(value: str) -> datetime | None:
    """Parse the C-locale UTC timestamp emitted by ``codesign``.

    :param value: Timestamp text from verbose signature output.
    :returns: UTC timestamp, or ``None`` when the value is unrecognized.
    """
    months = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
        "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
    }
    parts = value.split()
    if len(parts) != 5 or parts[3] != "at" or parts[1] not in months:
        return None
    try:
        hour, minute, second = (int(component) for component in parts[4].split(":"))
        return datetime(
            int(parts[2]),
            months[parts[1]],
            int(parts[0]),
            hour,
            minute,
            second,
            tzinfo=timezone.utc,
        )
    except (TypeError, ValueError):
        return None


def _is_unsigned(output: str) -> bool:
    """Recognize the stable diagnostics for an unsigned code object.

    :param output: Combined ``codesign`` verification output.
    :returns: Whether the failure specifically reports missing signatures.
    """
    normalized = output.lower()
    return any(message in normalized for message in (
        "code object is not signed at all",
        "code object is not signed",
        "not signed at all",
    ))


class AppSignatureInspector:
    """Verify the resource seal and nested code of a macOS application bundle."""

    def inspect(self, bundle: Path) -> ArtifactSignature:
        """Verify one ``.app`` bundle with the native macOS service.

        :param bundle: Application bundle directory.
        :returns: Bundle signature status and signing identity metadata.
        """
        if sys.platform != "darwin":
            return ArtifactSignature(status="unsupported")
        path = str(bundle.resolve())
        common = [
            CODESIGN,
            "--verify",
            "--deep",
            "--strict=all",
            "--verbose=4",
        ]
        environment = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        try:
            integrity = subprocess.run(
                [*common, path],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=environment,
            )
            trust = subprocess.run(
                [*common, "--test-requirement", "=anchor apple generic", path],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=environment,
            )
            display = subprocess.run(
                [CODESIGN, "--display", "--verbose=4", path],
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=environment,
            )
        except OSError:
            return ArtifactSignature(status="unsupported")

        integrity_output = integrity.stdout + "\n" + integrity.stderr
        status: ArtifactSignatureStatus
        if integrity.returncode == 0:
            status = "valid" if trust.returncode == 0 else "untrusted"
        elif _is_unsigned(integrity_output):
            status = "unsigned"
        else:
            status = "invalid"

        signer = None
        timestamp = None
        team_id = None
        display_output = display.stdout + "\n" + display.stderr
        for line in display_output.splitlines():
            if line.startswith("Authority=") and signer is None:
                value = line.split("=", 1)[1]
                if value and value != "(unavailable)":
                    signer = value
            elif line.startswith("Timestamp="):
                value = line.split("=", 1)[1]
                if value.lower() != "none":
                    timestamp = _parse_timestamp(value)
            elif line.startswith("TeamIdentifier="):
                value = line.split("=", 1)[1]
                if value and value != "not set":
                    team_id = value
        return ArtifactSignature(
            status=status,
            signer=signer,
            timestamp=timestamp,
            team_id=team_id,
        )
