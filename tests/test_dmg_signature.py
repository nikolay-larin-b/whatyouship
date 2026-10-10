# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for cross-platform DMG container signature verification."""

import hashlib
import os
import struct
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from whatyouship.inspectors.dmg_signature import DmgSignatureInspector


def _koly_trailer(signature_offset: int, signature_size: int) -> bytes:
    """Create a minimal DMG trailer with signature coordinates.

    :param signature_offset: Embedded signature file offset.
    :param signature_size: Embedded signature byte length.
    :returns: Serialized 512-byte trailer.
    """
    trailer = bytearray(512)
    trailer[:4] = b"koly"
    struct.pack_into(">I", trailer, 4, 4)
    struct.pack_into(">I", trailer, 8, 512)
    struct.pack_into(">QQ", trailer, 216, signature_offset, 0)
    struct.pack_into(">QQ", trailer, 296, signature_offset, signature_size)
    return bytes(trailer)


def _code_directory(content: bytes, trailer: bytes, team_id: str) -> bytes:
    """Create a CodeDirectory covering one DMG content range.

    :param content: Bytes before the signature superblob.
    :param trailer: Final DMG trailer.
    :param team_id: Team identifier to embed.
    :returns: Serialized CodeDirectory blob.
    """
    identifier = b"com.example.release\x00"
    team = team_id.encode("ascii") + b"\x00"
    header_size = 52
    digest_size = 32
    special_count = 6
    digest_offset = (
        header_size + len(identifier) + len(team) + special_count * digest_size
    )
    length = digest_offset + digest_size
    header = struct.pack(
        ">9I4BI2I",
        0xFADE0C02,
        length,
        0x20200,
        0,
        digest_offset,
        header_size,
        special_count,
        1,
        len(content),
        digest_size,
        2,
        0,
        0,
        0,
        0,
        header_size + len(identifier),
    )
    trailer_copy = bytearray(trailer)
    struct.pack_into(">Q", trailer_copy, 304, 0)
    special = bytearray(special_count * digest_size)
    special[:digest_size] = hashlib.sha256(trailer_copy).digest()
    return (
        header
        + identifier
        + team
        + special
        + hashlib.sha256(content).digest()
    )


def _signed_dmg(ticket: bool = True) -> tuple[bytes, bytes]:
    """Create a synthetic structurally valid signed DMG.

    :param ticket: Whether to include a notarization ticket slot.
    :returns: Complete DMG and primary CodeDirectory bytes.
    """
    content = b"synthetic disk image payload"
    placeholder_entries = 3 if ticket else 2
    placeholder_signature_size = 12 + placeholder_entries * 8
    trailer = _koly_trailer(len(content), placeholder_signature_size)
    code_directory = _code_directory(content, trailer, "TEAM123456")
    cms = struct.pack(">II", 0xFADE0B01, 9) + b"\x30"
    blobs = [(0, code_directory), (0x10000, cms)]
    if ticket:
        blobs.append((0x10002, struct.pack(">II", 0xFADE0B01, 9) + b"T"))
    index_size = 12 + len(blobs) * 8
    offsets = []
    offset = index_size
    for slot, blob in blobs:
        offsets.append((slot, offset))
        offset += len(blob)
    superblob = (
        struct.pack(">III", 0xFADE0CC0, offset, len(blobs))
        + b"".join(struct.pack(">II", *entry) for entry in offsets)
        + b"".join(blob for _, blob in blobs)
    )
    trailer = _koly_trailer(len(content), len(superblob))
    code_directory = _code_directory(content, trailer, "TEAM123456")
    blobs[0] = (0, code_directory)
    superblob = (
        struct.pack(">III", 0xFADE0CC0, offset, len(blobs))
        + b"".join(struct.pack(">II", *entry) for entry in offsets)
        + b"".join(blob for _, blob in blobs)
    )
    return content + superblob + trailer, code_directory


def _rcodesign_output(
    code_directory: bytes,
    *,
    valid: bool = True,
    trusted: bool = True,
) -> str:
    """Create the relevant subset of ``rcodesign`` YAML output.

    :param code_directory: CodeDirectory whose CMS digest is reported.
    :param valid: Whether CMS verification should succeed.
    :param trusted: Whether the leaf certificate chains to an Apple root.
    :returns: Synthetic YAML report.
    """
    digest = hashlib.sha256(code_directory).hexdigest()
    state = "true" if valid else "false"
    trust_state = "true" if trusted else "false"
    return f"""- entity:
    dmg:
      signature:
        cms:
          certificates:
          - subject: CN=Apple Root CA
            is_apple_root_ca: true
            is_apple_intermediate_ca: false
            chains_to_apple_root_ca: true
          - subject: 'CN=Developer ID Application: Example (TEAM123456)'
            is_apple_root_ca: false
            is_apple_intermediate_ca: false
            chains_to_apple_root_ca: {trust_state}
            apple_certificate_profile: developer-id-application
          signers:
          - issuer: CN=Developer ID Certification Authority
            digest_algorithm: SHA-256
            message_digest: {digest}
            signature_verifies: {state}
            time_stamp_token:
              signers:
              - issuer: CN=Apple Timestamp Certification Authority
                signing_time: 2026-09-29T01:50:28Z
                signature_verifies: true
"""


class DmgSignatureInspectorTests(unittest.TestCase):
    """Verify DMG signature and notarization metadata extraction."""

    def setUp(self) -> None:
        """Create a disposable DMG path."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.source = Path(temporary.name) / "release.dmg"

    def test_verifies_content_cms_signer_team_and_ticket(self) -> None:
        """Combine static CodeDirectory checks with CMS metadata."""
        payload, code_directory = _signed_dmg()
        self.source.write_bytes(payload)
        with patch(
            "whatyouship.inspectors.dmg_signature.shutil.which",
            side_effect=lambda name: "rcodesign" if name == "rcodesign" else None,
        ), patch(
            "whatyouship.inspectors.dmg_signature.subprocess.run"
        ) as run:
            run.return_value.returncode = 0
            run.return_value.stdout = _rcodesign_output(code_directory)
            signature = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(signature.status, "valid")
        self.assertEqual(
            signature.signer,
            "CN=Developer ID Application: Example (TEAM123456)",
        )
        self.assertEqual(signature.team_id, "TEAM123456")
        self.assertEqual(
            signature.timestamp,
            datetime(2026, 9, 29, 1, 50, 28, tzinfo=timezone.utc),
        )
        self.assertTrue(signature.notarization_ticket)
        run.assert_called_once_with(
            [
                "rcodesign",
                "-C",
                os.devnull,
                "print-signature-info",
                str(self.source.resolve()),
            ],
            capture_output=True,
            check=False,
            text=True,
            encoding="utf-8",
            errors="replace",
        )

    def test_reports_signed_image_as_unsupported_without_rcodesign(self) -> None:
        """Preserve static metadata and explain how to enable CMS verification."""
        payload, _ = _signed_dmg()
        self.source.write_bytes(payload)
        with (
            patch(
                "whatyouship.inspectors.dmg_signature.shutil.which",
                return_value=None,
            ),
            patch("whatyouship.external_tools.sys.platform", "linux"),
        ):
            signature = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(signature.status, "unsupported")
        self.assertEqual(signature.team_id, "TEAM123456")
        self.assertTrue(signature.notarization_ticket)
        self.assertIn("rcodesign was not found in PATH", signature.verification_issue)
        self.assertIn("Download the Linux binary", signature.verification_issue)
        self.assertIn("cargo install apple-codesign", signature.verification_issue)

    def test_reports_rcodesign_start_failure(self) -> None:
        """Distinguish an installed tool that cannot be started."""
        payload, _ = _signed_dmg()
        self.source.write_bytes(payload)
        with patch(
            "whatyouship.inspectors.dmg_signature.shutil.which",
            side_effect=lambda name: "rcodesign" if name == "rcodesign" else None,
        ), patch(
            "whatyouship.inspectors.dmg_signature.subprocess.run",
            side_effect=OSError("permission denied"),
        ):
            signature = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(signature.status, "unsupported")
        self.assertIn("could not be started: permission denied", signature.verification_issue)

    def test_reports_rcodesign_command_failure(self) -> None:
        """Include bounded diagnostics from a failed verification command."""
        payload, _ = _signed_dmg()
        self.source.write_bytes(payload)
        failure = subprocess.CompletedProcess(
            ["rcodesign"], 2, "ordinary output", "verification failed"
        )
        with patch(
            "whatyouship.inspectors.dmg_signature.shutil.which",
            side_effect=lambda name: "rcodesign" if name == "rcodesign" else None,
        ), patch(
            "whatyouship.inspectors.dmg_signature.subprocess.run",
            return_value=failure,
        ):
            signature = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(signature.status, "unsupported")
        self.assertIn(
            "rcodesign failed with exit code 2: verification failed",
            signature.verification_issue,
        )

    def test_reports_unrecognized_rcodesign_output(self) -> None:
        """Explain that successful but incompatible output could not be parsed."""
        payload, _ = _signed_dmg()
        self.source.write_bytes(payload)
        result = subprocess.CompletedProcess(["rcodesign"], 0, "unexpected", "")
        with patch(
            "whatyouship.inspectors.dmg_signature.shutil.which",
            side_effect=lambda name: "rcodesign" if name == "rcodesign" else None,
        ), patch(
            "whatyouship.inspectors.dmg_signature.subprocess.run",
            return_value=result,
        ):
            signature = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(signature.status, "unsupported")
        self.assertIn("could not understand", signature.verification_issue)

    def test_uses_native_codesign_before_cross_platform_fallback(self) -> None:
        """Prefer native integrity and Apple-anchor checks on macOS."""
        payload, _ = _signed_dmg()
        self.source.write_bytes(payload)
        display = """Authority=Developer ID Application: Example (TEAM123456)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=29 Sep 2026 at 01:50:28
TeamIdentifier=TEAM123456
"""
        results = [
            SimpleNamespace(returncode=0, stdout="", stderr="valid on disk"),
            SimpleNamespace(returncode=0, stdout="", stderr="requirement satisfied"),
            SimpleNamespace(returncode=0, stdout="", stderr=display),
        ]
        with patch(
            "whatyouship.inspectors.dmg_signature.shutil.which",
            side_effect=lambda name: "codesign" if name == "codesign" else None,
        ), patch(
            "whatyouship.inspectors.dmg_signature.subprocess.run",
            side_effect=results,
        ) as run:
            signature = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(signature.status, "valid")
        self.assertEqual(
            signature.signer,
            "Developer ID Application: Example (TEAM123456)",
        )
        self.assertEqual(signature.team_id, "TEAM123456")
        self.assertEqual(
            signature.timestamp,
            datetime(2026, 9, 29, 1, 50, 28, tzinfo=timezone.utc),
        )
        self.assertTrue(signature.notarization_ticket)
        self.assertEqual(run.call_count, 3)
        self.assertIn("--verify", run.call_args_list[0].args[0])
        self.assertIn("=anchor apple generic", run.call_args_list[1].args[0])
        self.assertIn("--display", run.call_args_list[2].args[0])

    def test_native_codesign_distinguishes_untrusted_and_invalid(self) -> None:
        """Separate Apple-anchor failure from damaged signed content."""
        payload, _ = _signed_dmg()
        self.source.write_bytes(payload)
        for integrity_code, trust_code, expected in (
            (0, 1, "untrusted"),
            (1, 1, "invalid"),
        ):
            with self.subTest(expected=expected), patch(
                "whatyouship.inspectors.dmg_signature.shutil.which",
                side_effect=lambda name: "codesign" if name == "codesign" else None,
            ), patch(
                "whatyouship.inspectors.dmg_signature.subprocess.run",
                side_effect=[
                    SimpleNamespace(
                        returncode=integrity_code,
                        stdout="",
                        stderr="",
                    ),
                    SimpleNamespace(
                        returncode=trust_code,
                        stdout="",
                        stderr="",
                    ),
                    SimpleNamespace(returncode=0, stdout="", stderr=""),
                ],
            ):
                signature = DmgSignatureInspector().inspect(self.source)

            self.assertEqual(signature.status, expected)

    def test_rejects_modified_signed_content_before_cms_verification(self) -> None:
        """Report a CodeDirectory content digest mismatch as invalid."""
        payload, _ = _signed_dmg()
        self.source.write_bytes(b"X" + payload[1:])
        with patch(
            "whatyouship.inspectors.dmg_signature.subprocess.run"
        ) as run:
            signature = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(signature.status, "invalid")
        run.assert_not_called()

    def test_rejects_invalid_cms_signature(self) -> None:
        """Report CMS verification failures after static checks pass."""
        payload, code_directory = _signed_dmg(ticket=False)
        self.source.write_bytes(payload)
        with patch(
            "whatyouship.inspectors.dmg_signature.shutil.which",
            side_effect=lambda name: "rcodesign" if name == "rcodesign" else None,
        ), patch(
            "whatyouship.inspectors.dmg_signature.subprocess.run"
        ) as run:
            run.return_value.returncode = 0
            run.return_value.stdout = _rcodesign_output(code_directory, valid=False)
            signature = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(signature.status, "invalid")
        self.assertFalse(signature.notarization_ticket)

    def test_reports_valid_untrusted_certificate_chain(self) -> None:
        """Distinguish valid CMS cryptography from an Apple-trusted chain."""
        payload, code_directory = _signed_dmg()
        self.source.write_bytes(payload)
        with patch(
            "whatyouship.inspectors.dmg_signature.shutil.which",
            side_effect=lambda name: "rcodesign" if name == "rcodesign" else None,
        ), patch(
            "whatyouship.inspectors.dmg_signature.subprocess.run"
        ) as run:
            run.return_value.returncode = 0
            run.return_value.stdout = _rcodesign_output(
                code_directory,
                trusted=False,
            )
            signature = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(signature.status, "untrusted")

    def test_reports_malformed_embedded_signature_as_invalid(self) -> None:
        """Reject a signed trailer whose declared superblob is malformed."""
        signature = b"not a superblob"
        self.source.write_bytes(
            b"payload"
            + signature
            + _koly_trailer(len(b"payload"), len(signature))
        )

        result = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(result.status, "invalid")

    def test_reports_unsigned_image_without_rcodesign(self) -> None:
        """Recognize an unsigned valid DMG trailer without external tools."""
        self.source.write_bytes(b"payload" + _koly_trailer(0, 0))
        with patch(
            "whatyouship.inspectors.dmg_signature.shutil.which"
        ) as which:
            signature = DmgSignatureInspector().inspect(self.source)

        self.assertEqual(signature.status, "unsigned")
        self.assertFalse(signature.notarization_ticket)
        which.assert_not_called()
