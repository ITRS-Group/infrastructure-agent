"""
Client certificate chain validation against LocalMachine trust.

Schannel does not auto-validate client certificates; when check_client_cert is
enabled the agent must ask Windows to evaluate the peer chain after
AcceptSecurityContext. Trust anchors and policy come from the OS (LocalMachine
stores / base chain policy); the agent does not apply its own trust mask.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import logging
from ctypes import sizeof

from tls.schannel import win32
from tls.schannel.errors import SchannelError, status_hex

logger = logging.getLogger('tls')


def verify_client_certificate_chain(p_cert_context) -> None:
    """
    Fail closed if LocalMachine base chain policy rejects the client leaf.

    Uses CertGetCertificateChain(HCCE_LOCAL_MACHINE) with
    CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, then
    CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE) with soft-fail
    for unknown/offline revocation (IGNORE_ALL_REV_UNKNOWN). Known-revoked
    certificates still fail.
    """
    win32.ensure_win32()
    if not p_cert_context:
        raise SchannelError("Client certificate chain validation failed: no certificate context")

    chain_para = win32.CERT_CHAIN_PARA()
    chain_para.cbSize = sizeof(chain_para)
    chain_para.RequestedUsage.dwType = 0
    chain_para.RequestedUsage.Usage.cUsageIdentifier = 0
    chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = None

    pp_chain = win32.POINTER(win32.CERT_CHAIN_CONTEXT)()
    ok = win32.crypt32.CertGetCertificateChain(
        win32.HCCE_LOCAL_MACHINE,
        p_cert_context,
        None,  # current time
        None,  # no additional store
        win32.byref(chain_para),
        win32.CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
        None,
        win32.byref(pp_chain),
    )
    if not ok or not pp_chain:
        err = win32.kernel32.GetLastError()
        raise SchannelError(
            "Client certificate chain validation failed: CertGetCertificateChain "
            f"{status_hex(err)}",
            winerror=err,
        )

    try:
        logger.debug(
            "CertGetCertificateChain TrustStatus dwErrorStatus=%s dwInfoStatus=%s",
            int(pp_chain.contents.TrustStatus.dwErrorStatus) & 0xFFFFFFFF,
            int(pp_chain.contents.TrustStatus.dwInfoStatus) & 0xFFFFFFFF,
        )

        policy_para = win32.CERT_CHAIN_POLICY_PARA()
        policy_para.cbSize = sizeof(policy_para)
        policy_para.dwFlags = win32.CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS
        policy_para.pvExtraPolicyPara = None

        policy_status = win32.CERT_CHAIN_POLICY_STATUS()
        policy_status.cbSize = sizeof(policy_status)
        policy_status.dwError = 0

        # CERT_CHAIN_POLICY_BASE is an integer ID cast to LPCSTR (like store providers).
        ok = win32.crypt32.CertVerifyCertificateChainPolicy(
            win32.CERT_CHAIN_POLICY_BASE,
            pp_chain,
            win32.byref(policy_para),
            win32.byref(policy_status),
        )
        if not ok:
            err = win32.kernel32.GetLastError()
            raise SchannelError(
                "Client certificate chain validation failed: "
                f"CertVerifyCertificateChainPolicy {status_hex(err)}",
                winerror=err,
            )
        policy_error = int(policy_status.dwError) & 0xFFFFFFFF
        logger.debug(
            "CertVerifyCertificateChainPolicy dwError=%s lChainIndex=%s lElementIndex=%s",
            policy_error,
            int(policy_status.lChainIndex),
            int(policy_status.lElementIndex),
        )
        if policy_error != 0:
            logger.error(
                "Client certificate chain rejected by OS base policy %s",
                status_hex(policy_error),
            )
            raise SchannelError(
                f"Client certificate chain validation failed: {status_hex(policy_error)}",
                winerror=policy_error,
            )
        logger.debug("Client certificate chain validated against LocalMachine trust")
    finally:
        win32.crypt32.CertFreeCertificateChain(pp_chain)
