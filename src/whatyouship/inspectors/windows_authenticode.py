# Copyright (c) 2026 Nikolay Larin
# SPDX-License-Identifier: MIT

"""Verify a release artifact with the Windows Authenticode trust provider."""

import ctypes
from pathlib import Path

from whatyouship.model import ArtifactSignature


class _Guid(ctypes.Structure):
    """Represent a Windows GUID used to select the trust policy."""

    _fields_ = [
        ("data1", ctypes.c_uint32),
        ("data2", ctypes.c_uint16),
        ("data3", ctypes.c_uint16),
        ("data4", ctypes.c_ubyte * 8),
    ]


class _WintrustFileInfo(ctypes.Structure):
    """Identify the file passed to the Windows trust provider."""

    _fields_ = [
        ("cbStruct", ctypes.c_uint32),
        ("pcwszFilePath", ctypes.c_wchar_p),
        ("hFile", ctypes.c_void_p),
        ("pgKnownSubject", ctypes.c_void_p),
    ]


class _WintrustData(ctypes.Structure):
    """Pass a file and verification options to WinVerifyTrust."""

    _fields_ = [
        ("cbStruct", ctypes.c_uint32),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.c_uint32),
        ("fdwRevocationChecks", ctypes.c_uint32),
        ("dwUnionChoice", ctypes.c_uint32),
        ("pFile", ctypes.c_void_p),
        ("dwStateAction", ctypes.c_uint32),
        ("hWVTStateData", ctypes.c_void_p),
        ("pwszURLReference", ctypes.c_void_p),
        ("dwProvFlags", ctypes.c_uint32),
        ("dwUIContext", ctypes.c_uint32),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


_AUTHENTICODE_POLICY = _Guid(
    0x00AAC56B,
    0xCD44,
    0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
)
_TRUST_E_NOSIGNATURE = 0x800B0100
_WTD_UI_NONE = 2
_WTD_CHOICE_FILE = 1
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_REVOCATION_CHECK_NONE = 0x10
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000


class WindowsAuthenticodeVerifier:
    """Use Windows system trust policy to verify a file signature."""

    def verify(self, source_path: Path) -> ArtifactSignature:
        """Verify a file using WinVerifyTrust's Authenticode policy.

        :param source_path: Release artifact to verify.
        :returns: Valid, unsigned, or invalid signature status.
        :raises OSError: If the Windows trust provider cannot be loaded.
        """
        wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
        verify_trust = wintrust.WinVerifyTrust
        verify_trust.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_Guid),
            ctypes.POINTER(_WintrustData),
        ]
        verify_trust.restype = ctypes.c_int32

        file_info = _WintrustFileInfo()
        file_info.cbStruct = ctypes.sizeof(_WintrustFileInfo)
        file_info.pcwszFilePath = str(source_path.resolve())

        data = _WintrustData()
        data.cbStruct = ctypes.sizeof(_WintrustData)
        data.dwUIChoice = _WTD_UI_NONE
        data.dwUnionChoice = _WTD_CHOICE_FILE
        data.pFile = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
        data.dwStateAction = _WTD_STATEACTION_VERIFY
        data.dwProvFlags = _WTD_REVOCATION_CHECK_NONE | _WTD_CACHE_ONLY_URL_RETRIEVAL

        try:
            result = verify_trust(None, ctypes.byref(_AUTHENTICODE_POLICY), ctypes.byref(data))
        finally:
            data.dwStateAction = _WTD_STATEACTION_CLOSE
            verify_trust(None, ctypes.byref(_AUTHENTICODE_POLICY), ctypes.byref(data))

        if result == 0:
            return ArtifactSignature(status="valid")
        if result & 0xFFFFFFFF == _TRUST_E_NOSIGNATURE:
            return ArtifactSignature(status="unsigned")
        return ArtifactSignature(status="invalid")
