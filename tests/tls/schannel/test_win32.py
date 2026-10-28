"""
Linux-runnable unit tests for tls.schannel.win32 bindings loader.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import pytest


def _reset_win32_module():
    """Restore win32 module to pre-load state (safe on Linux CI)."""
    import tls.schannel.win32 as win32_mod

    win32_mod._win32_loaded = False
    win32_mod.crypt32 = None
    win32_mod.secur32 = None
    win32_mod.kernel32 = None
    win32_mod.CERT_CONTEXT = None
    win32_mod.CredHandle = None
    win32_mod.CtxtHandle = None
    win32_mod.SecBuffer = None
    win32_mod.SecBufferDesc = None
    win32_mod.SCH_CREDENTIALS = None
    win32_mod.TLS_PARAMETERS = None
    win32_mod.SecPkgContext_StreamSizes = None
    win32_mod.SecPkgContext_ConnectionInfo = None
    win32_mod.SecPkgContext_CipherInfo = None
    win32_mod.POINTER = None
    win32_mod.byref = None
    win32_mod.cast = None
    win32_mod.create_string_buffer = None
    win32_mod.pointer = None
    win32_mod.c_void_p = None
    win32_mod.c_char = None
    win32_mod.DWORD = None
    win32_mod.ULONG = None
    win32_mod.WCHAR = None
    win32_mod.LPCWSTR = None
    win32_mod.LPWSTR = None
    win32_mod.FILETIME = None
    win32_mod.BOOL = None
    win32_mod.ULONG_PTR = None
    win32_mod.c_size_t = None
    win32_mod.Structure = None
    win32_mod.WinDLL = None
    win32_mod.create_unicode_buffer = None


@pytest.fixture(autouse=True)
def _win32_module_reset():
    yield
    _reset_win32_module()


def _mock_dlls(mocker):
    crypt32 = mocker.Mock(name='crypt32')
    secur32 = mocker.Mock(name='secur32')
    kernel32 = mocker.Mock(name='kernel32')

    def fake_windll(name, use_last_error=True):
        return {'crypt32': crypt32, 'secur32': secur32, 'kernel32': kernel32}[name]

    # WinDLL is absent on Linux; create=True injects it for ensure_win32's import.
    mocker.patch('ctypes.WinDLL', create=True, side_effect=fake_windll)
    return crypt32, secur32, kernel32


def test_ensure_win32_loads_bindings_on_win32_platform(mocker):
    import tls.schannel.win32 as win32_mod

    win32_mod._win32_loaded = False
    crypt32, secur32, kernel32 = _mock_dlls(mocker)
    mocker.patch.object(win32_mod.sys, 'platform', 'win32')

    win32_mod.ensure_win32()

    assert win32_mod._win32_loaded is True
    assert win32_mod.crypt32 is crypt32
    assert win32_mod.secur32 is secur32
    assert win32_mod.kernel32 is kernel32

    # Structures and ctypes helpers are populated from real ctypes imports.
    assert win32_mod.CERT_CONTEXT is not None
    assert win32_mod.CredHandle is not None
    assert win32_mod.SecBuffer is not None
    assert win32_mod.SCH_CREDENTIALS is not None
    assert win32_mod.POINTER is not None
    assert win32_mod.c_char is not None
    assert win32_mod.create_unicode_buffer is not None

    # argtypes/restype wiring on mocked DLL entry points.
    assert crypt32.CertOpenStore.restype is win32_mod.c_void_p
    assert len(crypt32.CertOpenStore.argtypes) == 5
    assert crypt32.CertEnumCertificatesInStore.restype is not None
    assert crypt32.CertGetNameStringW.restype is win32_mod.DWORD
    assert kernel32.GetLastError.restype is win32_mod.DWORD
    assert secur32.AcquireCredentialsHandleW.restype is win32_mod.DWORD
    assert secur32.AcceptSecurityContext.argtypes is not None
    assert secur32.DecryptMessage.argtypes is not None
    assert secur32.FreeContextBuffer.argtypes is not None


def test_ensure_win32_second_call_is_idempotent(mocker):
    import tls.schannel.win32 as win32_mod

    _mock_dlls(mocker)
    mocker.patch.object(win32_mod.sys, 'platform', 'win32')

    win32_mod.ensure_win32()
    first_crypt32 = win32_mod.crypt32
    win32_mod.ensure_win32()
    assert win32_mod.crypt32 is first_crypt32


def test_module_constants_available_without_loading():
    """Module-level Schannel constants are importable without ensure_win32."""
    import tls.schannel.win32 as win32_mod

    assert win32_mod.SEC_E_OK == 0
    assert win32_mod.UNISP_NAME == "Microsoft Unified Security Protocol Provider"
    assert win32_mod.PROTOCOL_FLAG_NAMES[win32_mod.SP_PROT_TLS1_2_SERVER] == 'TLSv1.2'
    # sspi.h: 0x8000 is extended-error; stream request and return are 0x10000.
    assert win32_mod.ASC_REQ_EXTENDED_ERROR == 0x00008000
    assert win32_mod.ASC_REQ_STREAM == 0x00010000
    assert win32_mod.ASC_RET_STREAM == 0x00010000
    assert win32_mod.ASC_REQ_BASE & win32_mod.ASC_REQ_STREAM
    assert win32_mod.ASC_REQ_BASE & win32_mod.ASC_REQ_EXTENDED_ERROR
