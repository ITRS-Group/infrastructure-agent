"""
Unit tests for Schannel client certificate chain validation (Linux-runnable).

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from tls.schannel.errors import SchannelError


def _patch_chain_win32(chain_mod, mocker):
    mocker.patch.object(chain_mod.win32, 'ensure_win32')
    mocker.patch.object(chain_mod.win32, 'byref', side_effect=lambda x: x)
    mocker.patch.object(chain_mod.win32, 'HCCE_LOCAL_MACHINE', 0x1)
    mocker.patch.object(chain_mod.win32, 'CERT_CHAIN_POLICY_BASE', 1)
    mocker.patch.object(
        chain_mod.win32, 'CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT', 0x40000000,
    )
    mocker.patch.object(
        chain_mod.win32, 'CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS', 0xF00,
    )

    class FakeChainPara:
        def __init__(self):
            self.cbSize = 0
            self.RequestedUsage = SimpleNamespace(
                dwType=0,
                Usage=SimpleNamespace(cUsageIdentifier=0, rgpszUsageIdentifier=None),
            )

    class FakePolicyPara:
        def __init__(self):
            self.cbSize = 0
            self.dwFlags = 0
            self.pvExtraPolicyPara = None

    class FakePolicyStatus:
        def __init__(self):
            self.cbSize = 0
            self.dwError = 0
            self.lChainIndex = -1
            self.lElementIndex = -1

    mocker.patch.object(chain_mod.win32, 'CERT_CHAIN_PARA', FakeChainPara)
    mocker.patch.object(chain_mod.win32, 'CERT_CHAIN_POLICY_PARA', FakePolicyPara)
    mocker.patch.object(chain_mod.win32, 'CERT_CHAIN_POLICY_STATUS', FakePolicyStatus)
    mocker.patch.object(chain_mod.win32, 'CERT_CHAIN_CONTEXT', object)
    mocker.patch('tls.schannel.chain.sizeof', return_value=32)


def _chain_pointer(mocker, *, trust_error=0, trust_info=0):
    """POINTER(CERT_CHAIN_CONTEXT) stand-in with TrustStatus for debug logging."""
    pp_chain_holder = mocker.Mock()
    pp_chain_holder.__bool__ = lambda self: True
    pp_chain_holder.contents.TrustStatus.dwErrorStatus = trust_error
    pp_chain_holder.contents.TrustStatus.dwInfoStatus = trust_info
    return pp_chain_holder


def test_verify_client_certificate_chain_trusted(mocker):
    import tls.schannel.chain as chain_mod

    _patch_chain_win32(chain_mod, mocker)
    pp_chain_holder = _chain_pointer(mocker)

    mocker.patch.object(chain_mod.win32, 'POINTER', return_value=lambda: pp_chain_holder)

    crypt32 = mocker.Mock()
    crypt32.CertGetCertificateChain.return_value = True
    crypt32.CertVerifyCertificateChainPolicy.return_value = True
    mocker.patch.object(chain_mod.win32, 'crypt32', crypt32)
    mocker.patch.object(chain_mod.win32, 'kernel32', mocker.Mock())

    chain_mod.verify_client_certificate_chain(mocker.Mock())

    crypt32.CertGetCertificateChain.assert_called_once()
    assert (
        crypt32.CertGetCertificateChain.call_args[0][5] ==
        chain_mod.win32.CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
    )
    crypt32.CertVerifyCertificateChainPolicy.assert_called_once()
    policy_para = crypt32.CertVerifyCertificateChainPolicy.call_args[0][2]
    assert (
        policy_para.dwFlags ==
        chain_mod.win32.CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS
    )
    crypt32.CertFreeCertificateChain.assert_called_once_with(pp_chain_holder)


def test_verify_client_certificate_chain_policy_error(mocker):
    import tls.schannel.chain as chain_mod

    _patch_chain_win32(chain_mod, mocker)
    pp_chain_holder = _chain_pointer(mocker)
    mocker.patch.object(chain_mod.win32, 'POINTER', return_value=lambda: pp_chain_holder)

    crypt32 = mocker.Mock()
    crypt32.CertGetCertificateChain.return_value = True

    def verify_policy(_oid, _chain, _para, status):
        # byref is identity in this suite — status is the FakePolicyStatus instance
        status.dwError = 0x800B0109  # CERT_E_UNTRUSTEDROOT
        return True

    crypt32.CertVerifyCertificateChainPolicy.side_effect = verify_policy
    mocker.patch.object(chain_mod.win32, 'crypt32', crypt32)
    mocker.patch.object(chain_mod.win32, 'kernel32', mocker.Mock())

    with pytest.raises(SchannelError, match=r'0x800B0109'):
        chain_mod.verify_client_certificate_chain(mocker.Mock())

    crypt32.CertFreeCertificateChain.assert_called_once()


def test_verify_client_certificate_chain_policy_api_fails(mocker):
    import tls.schannel.chain as chain_mod

    _patch_chain_win32(chain_mod, mocker)
    pp_chain_holder = _chain_pointer(mocker)
    mocker.patch.object(chain_mod.win32, 'POINTER', return_value=lambda: pp_chain_holder)

    crypt32 = mocker.Mock()
    crypt32.CertGetCertificateChain.return_value = True
    crypt32.CertVerifyCertificateChainPolicy.return_value = False
    kernel32 = mocker.Mock()
    kernel32.GetLastError.return_value = 87
    mocker.patch.object(chain_mod.win32, 'crypt32', crypt32)
    mocker.patch.object(chain_mod.win32, 'kernel32', kernel32)

    with pytest.raises(SchannelError, match='CertVerifyCertificateChainPolicy'):
        chain_mod.verify_client_certificate_chain(mocker.Mock())

    crypt32.CertFreeCertificateChain.assert_called_once()


def test_verify_client_certificate_chain_get_chain_fails(mocker):
    import tls.schannel.chain as chain_mod

    _patch_chain_win32(chain_mod, mocker)
    empty = mocker.Mock()
    empty.__bool__ = lambda self: False
    mocker.patch.object(chain_mod.win32, 'POINTER', return_value=lambda: empty)

    crypt32 = mocker.Mock()
    crypt32.CertGetCertificateChain.return_value = False
    kernel32 = mocker.Mock()
    kernel32.GetLastError.return_value = 57
    mocker.patch.object(chain_mod.win32, 'crypt32', crypt32)
    mocker.patch.object(chain_mod.win32, 'kernel32', kernel32)

    with pytest.raises(SchannelError, match='CertGetCertificateChain'):
        chain_mod.verify_client_certificate_chain(mocker.Mock())


def test_verify_client_certificate_chain_no_context(mocker):
    import tls.schannel.chain as chain_mod

    mocker.patch.object(chain_mod.win32, 'ensure_win32')
    with pytest.raises(SchannelError, match='no certificate context'):
        chain_mod.verify_client_certificate_chain(None)
