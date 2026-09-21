# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Tests for platform-specific release artifact signature verification."""

import ctypes
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from whatyouship.config import LintConfiguration
from whatyouship.inspectors.msi import MsiInspector
from whatyouship.inspectors.msi_signature import MsiSignatureInspector
from whatyouship.inspectors.windows_authenticode import (
    WindowsAuthenticodeVerifier,
    _Guid,
    _WintrustData,
    _WintrustFileInfo,
)
from whatyouship.lint import LintEngine
from whatyouship.model import ArtifactSignature, ReleaseArtifact


class MsiSignatureTests(unittest.TestCase):
    """Verify platform routing and Windows trust result mapping."""

    def test_windows_dispatches_to_system_verifier(self) -> None:
        """Use the Windows backend for the original MSI file."""
        source = Path("release.msi")
        expected = ArtifactSignature("valid")
        with (
            patch("whatyouship.inspectors.msi_signature.sys.platform", "win32"),
            patch(
                "whatyouship.inspectors.windows_authenticode.WindowsAuthenticodeVerifier.verify",
                return_value=expected,
            ) as verify,
        ):
            signature = MsiSignatureInspector().inspect(source)

        self.assertEqual(signature, expected)
        verify.assert_called_once_with(source)

    def test_linux_and_macos_are_unsupported(self) -> None:
        """Skip system verification on platforms without a Windows backend."""
        for platform in ("linux", "darwin"):
            with self.subTest(platform=platform):
                with (
                    patch("whatyouship.inspectors.msi_signature.sys.platform", platform),
                    patch(
                        "whatyouship.inspectors.windows_authenticode.WindowsAuthenticodeVerifier.verify"
                    ) as verify,
                ):
                    signature = MsiSignatureInspector().inspect(Path("release.msi"))

                self.assertEqual(signature, ArtifactSignature("unsupported"))
                verify.assert_not_called()

    def test_unsupported_msi_has_no_artifact_signature_findings(self) -> None:
        """Avoid flagging MSI files when signature checking is unsupported."""
        with patch("whatyouship.inspectors.msi_signature.sys.platform", "linux"):
            signature = MsiSignatureInspector().inspect(Path("release.msi"))
        artifact = ReleaseArtifact(Path("release.msi"), signature=signature)

        findings = LintEngine(LintConfiguration().rules()).run(artifact)

        self.assertEqual(findings, [])

    def test_windows_maps_system_trust_results(self) -> None:
        """Classify verified, absent, and failed signatures distinctly."""
        for result, expected in (
            (0, "valid"),
            (0x800B0100, "unsigned"),
            (0x80096010, "invalid"),
        ):
            with self.subTest(result=result):
                verify_trust = Mock(side_effect=[result, 0])
                with patch(
                    "whatyouship.inspectors.windows_authenticode.ctypes.WinDLL",
                    create=True,
                    return_value=Mock(WinVerifyTrust=verify_trust),
                ) as load_library:
                    signature = WindowsAuthenticodeVerifier().verify(Path("release.msi"))

                self.assertEqual(signature.status, expected)
                self.assertEqual(verify_trust.call_count, 2)
                load_library.assert_called_once_with("wintrust", use_last_error=True)

    def test_windows_passes_file_and_closes_trust_state(self) -> None:
        """Use file verification and release provider state after checking."""
        actions: list[int] = []
        checked_paths: list[str] = []

        def verify_trust(window: object, policy: object, data_pointer: object) -> int:
            """Record the parameters supplied to the system call.

            :param window: Optional owner window.
            :param policy: Authenticode action identifier.
            :param data_pointer: Pointer to Windows trust data.
            :returns: Successful verification status.
            """
            data = ctypes.cast(data_pointer, ctypes.POINTER(_WintrustData)).contents
            action = ctypes.cast(policy, ctypes.POINTER(_Guid)).contents
            self.assertEqual(action.data1, 0x00AAC56B)
            self.assertEqual(action.data2, 0xCD44)
            actions.append(data.dwStateAction)
            if data.dwStateAction == 1:
                file_info = ctypes.cast(
                    data.pFile, ctypes.POINTER(_WintrustFileInfo)
                ).contents
                checked_paths.append(file_info.pcwszFilePath)
                self.assertEqual(data.dwUnionChoice, 1)
                self.assertEqual(data.dwUIChoice, 2)
            return 0

        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "release.msi"
            source.write_bytes(b"synthetic MSI")
            with patch(
                "whatyouship.inspectors.windows_authenticode.ctypes.WinDLL",
                create=True,
                return_value=Mock(WinVerifyTrust=Mock(side_effect=verify_trust)),
            ):
                signature = WindowsAuthenticodeVerifier().verify(source)

        self.assertEqual(signature.status, "valid")
        self.assertEqual(actions, [1, 2])
        self.assertEqual(checked_paths, [str(source.resolve())])

    def test_msi_inspector_keeps_signature_separate_from_cache(self) -> None:
        """Verify the source package on each run even when payloads are cached."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            source = Path(temporary_directory) / "release.msi"
            source.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1synthetic")
            with (
                patch(
                    "whatyouship.inspectors.msi_cache.platformdirs.user_cache_dir",
                    return_value=str(Path(temporary_directory) / "cache"),
                ),
                patch.object(
                    MsiInspector, "_extract_payloads",
                    return_value=iter([(Path("app.bin"), b"abc")]),
                ) as extract,
                patch(
                    "whatyouship.inspectors.msi.MsiSignatureInspector.inspect",
                    side_effect=[ArtifactSignature("valid"), ArtifactSignature("invalid")],
                ) as verify,
            ):
                first = MsiInspector().inspect(source)
                second = MsiInspector().inspect(source)

        extract.assert_called_once_with(source)
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(first.signature.status, "valid")
        self.assertEqual(second.signature.status, "invalid")


if __name__ == "__main__":
    unittest.main()
