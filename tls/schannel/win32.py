"""
Windows crypt32 / secur32 ctypes bindings for Schannel.

Call ``ensure_win32()`` before using module-level DLL handles or structures.
Other schannel modules must access symbols via this module object (e.g.
``win32.crypt32``) so values updated by ``ensure_win32`` are visible.

Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations

import sys

from tls.schannel.errors import SchannelError

# Populated by ensure_win32() on Windows.
crypt32 = secur32 = kernel32 = None  # type: ignore
CERT_CONTEXT = CredHandle = CtxtHandle = SCHANNEL_ALERT_TOKEN = None  # type: ignore
SecBuffer = SecBufferDesc = None  # type: ignore
SCH_CREDENTIALS = TLS_PARAMETERS = None  # type: ignore
SecPkgContext_StreamSizes = SecPkgContext_ConnectionInfo = None  # type: ignore
SecPkgContext_CipherInfo = None  # type: ignore
CERT_TRUST_STATUS = CERT_ENHKEY_USAGE = CERT_USAGE_MATCH = None  # type: ignore
CERT_CHAIN_PARA = CERT_CHAIN_CONTEXT = None  # type: ignore
CERT_CHAIN_POLICY_PARA = CERT_CHAIN_POLICY_STATUS = None  # type: ignore
POINTER = byref = cast = create_string_buffer = pointer = c_void_p = None  # type: ignore
c_char = DWORD = ULONG = WCHAR = LPCWSTR = LPWSTR = FILETIME = BOOL = None  # type: ignore
LONG = None  # type: ignore
# ULONG_PTR: pointer-sized unsigned integer (32/64 bit)
ULONG_PTR = c_size_t = Structure = WinDLL = create_unicode_buffer = None  # type: ignore

# MSDN: CERT_STORE_PROV_SYSTEM_W — Unicode (LPCWSTR) pvPara store name.
CERT_STORE_PROV_SYSTEM_W = 10
CERT_SYSTEM_STORE_LOCAL_MACHINE = 0x00020000
CERT_STORE_READONLY_FLAG = 0x00008000
CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000
# FriendlyName (5) before SimpleName (4) when ranking cert_name matches.
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5

# Certificate chain engine / encoding (wincrypt.h).
# HCCE_LOCAL_MACHINE is ((HCERTCHAINENGINE) 0x1) — integer cast, not a pointer.
HCCE_LOCAL_MACHINE = 0x1
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
CERT_CHAIN_ENCODING = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
# CERT_CHAIN_POLICY_BASE is ((LPCSTR) 1) — integer ID cast like store providers.
CERT_CHAIN_POLICY_BASE = 1
# CertGetCertificateChain dwFlags — revocation (wincrypt.h).
# Exclude root: root CRLs are often unavailable; check the rest of the chain.
CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT = 0x40000000
# CertVerifyCertificateChainPolicy soft-fail when revocation status is unknown
# (no CRL/OCSP or unreachable). Known-revoked certs still fail.
CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN = 0x00000100
CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN = 0x00000200
CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN = 0x00000400
CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN = 0x00000800
CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS = (
    CERT_CHAIN_POLICY_IGNORE_END_REV_UNKNOWN |
    CERT_CHAIN_POLICY_IGNORE_CTL_SIGNER_REV_UNKNOWN |
    CERT_CHAIN_POLICY_IGNORE_CA_REV_UNKNOWN |
    CERT_CHAIN_POLICY_IGNORE_ROOT_REV_UNKNOWN
)

SECPKG_CRED_INBOUND = 0x00000001
SECURITY_NATIVE_DREP = 0x10

# AcceptSecurityContext fContextReq flags (sspi.h).
# 0x00008000 is ASC_REQ_EXTENDED_ERROR; ASC_REQ_STREAM is 0x00010000.
ASC_REQ_MUTUAL_AUTH = 0x00000002
ASC_REQ_REPLAY_DETECT = 0x00000004
ASC_REQ_SEQUENCE_DETECT = 0x00000008
ASC_REQ_CONFIDENTIALITY = 0x00000010
ASC_REQ_ALLOCATE_MEMORY = 0x00000100
ASC_REQ_EXTENDED_ERROR = 0x00008000
ASC_REQ_STREAM = 0x00010000
ASC_REQ_BASE = (
    ASC_REQ_SEQUENCE_DETECT |
    ASC_REQ_REPLAY_DETECT |
    ASC_REQ_CONFIDENTIALITY |
    ASC_REQ_ALLOCATE_MEMORY |
    ASC_REQ_EXTENDED_ERROR |
    ASC_REQ_STREAM
)
# pfContextAttr bits. ASC_RET_STREAM matches the ASC_REQ_STREAM bit.
ASC_RET_STREAM = 0x00010000

SECBUFFER_VERSION = 0
SECBUFFER_EMPTY = 0
SECBUFFER_DATA = 1
SECBUFFER_TOKEN = 2
SECBUFFER_EXTRA = 5
SECBUFFER_STREAM_TRAILER = 6
SECBUFFER_STREAM_HEADER = 7

SEC_E_OK = 0x00000000
SEC_I_CONTINUE_NEEDED = 0x00090312
SEC_I_COMPLETE_NEEDED = 0x00090313
SEC_I_COMPLETE_AND_CONTINUE = 0x00090314
SEC_I_CONTEXT_EXPIRED = 0x00090317
SEC_I_RENEGOTIATE = 0x00090321
SEC_E_INCOMPLETE_MESSAGE = 0x80090318

SCH_CREDENTIALS_VERSION = 5
SCH_CRED_NO_SYSTEM_MAPPER = 0x00000002
SCH_CRED_NO_DEFAULT_CREDS = 0x00000010

SECPKG_ATTR_STREAM_SIZES = 4
SECPKG_ATTR_REMOTE_CERT_CONTEXT = 0x53
SECPKG_ATTR_CONNECTION_INFO = 0x5A
SECPKG_ATTR_CIPHER_INFO = 0x64

# SCHANNEL_ALERT_TOKEN values (schannel.h).
SCHANNEL_ALERT = 2
TLS1_ALERT_FATAL = 2
TLS1_ALERT_BAD_CERTIFICATE = 42
TLS1_ALERT_UNSUPPORTED_CERT = 43
TLS1_ALERT_CERTIFICATE_REVOKED = 44
TLS1_ALERT_CERTIFICATE_EXPIRED = 45
# RFC 8446 certificate_required (116) is not in SCHANNEL_ALERT_TOKEN dwAlertNumber
# (list ends at TLS1_ALERT_UNSUPPORTED_EXT 110):
# https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-schannel_alert_token
TLS1_ALERT_CERTIFICATE_UNKNOWN = 46
TLS1_ALERT_UNKNOWN_CA = 48

# Certificate policy HRESULTs (winerror.h), stored unsigned for DWORD comparisons.
CERT_E_EXPIRED = 0x800B0101
CERT_E_VALIDITYPERIODNESTING = 0x800B0102
CERT_E_PURPOSE = 0x800B0106
CERT_E_ISSUERCHAINING = 0x800B0107
CERT_E_MALFORMED = 0x800B0108
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_CHAINING = 0x800B010A
CERT_E_REVOKED = 0x800B010C
CERT_E_UNTRUSTEDTESTROOT = 0x800B010D
CERT_E_WRONG_USAGE = 0x800B0110
TRUST_E_CERT_SIGNATURE = 0x80096004
TRUST_E_BASIC_CONSTRAINTS = 0x80096019

SP_PROT_SSL2_SERVER = 0x00000004
SP_PROT_SSL3_SERVER = 0x00000010
SP_PROT_TLS1_SERVER = 0x00000040
SP_PROT_TLS1_1_SERVER = 0x00000100
SP_PROT_TLS1_2_SERVER = 0x00000400
SP_PROT_TLS1_3_SERVER = 0x00001000

# Negotiated protocol labels (QueryContextAttributes)
PROTOCOL_FLAG_NAMES = {
    SP_PROT_SSL2_SERVER: 'SSLv2',
    SP_PROT_SSL3_SERVER: 'SSLv3',
    SP_PROT_TLS1_SERVER: 'TLSv1',
    SP_PROT_TLS1_1_SERVER: 'TLSv1.1',
    SP_PROT_TLS1_2_SERVER: 'TLSv1.2',
    SP_PROT_TLS1_3_SERVER: 'TLSv1.3',
}

UNISP_NAME = "Microsoft Unified Security Protocol Provider"
SECPKGCONTEXT_CIPHERINFO_V1 = 1

_win32_loaded = False


def ensure_win32() -> None:
    global _win32_loaded
    global crypt32, secur32, kernel32
    global CERT_CONTEXT, CredHandle, CtxtHandle, SecBuffer, SecBufferDesc
    global SCHANNEL_ALERT_TOKEN
    global SCH_CREDENTIALS, TLS_PARAMETERS
    global SecPkgContext_StreamSizes, SecPkgContext_ConnectionInfo, SecPkgContext_CipherInfo
    global CERT_TRUST_STATUS, CERT_ENHKEY_USAGE, CERT_USAGE_MATCH
    global CERT_CHAIN_PARA, CERT_CHAIN_CONTEXT
    global CERT_CHAIN_POLICY_PARA, CERT_CHAIN_POLICY_STATUS
    global POINTER, byref, cast, create_string_buffer, pointer, c_void_p, c_char
    global DWORD, ULONG, WCHAR, LPCWSTR, LPWSTR, FILETIME, BOOL, LONG, c_size_t, ULONG_PTR
    global Structure, WinDLL, create_unicode_buffer

    if _win32_loaded:
        return
    if not sys.platform.startswith('win'):
        raise SchannelError("Schannel TLS is only available on Windows")

    from ctypes import (
        POINTER as _POINTER,
        Structure as _Structure,
        WinDLL as _WinDLL,
        byref as _byref,
        c_char as _c_char,
        c_long as _c_long,
        c_size_t as _c_size_t,
        c_void_p as _c_void_p,
        cast as _cast,
        create_string_buffer as _create_string_buffer,
        create_unicode_buffer as _create_unicode_buffer,
        pointer as _pointer,
    )
    from ctypes.wintypes import (
        BOOL as _BOOL,
        DWORD as _DWORD,
        FILETIME as _FILETIME,
        LPCWSTR as _LPCWSTR,
        LPWSTR as _LPWSTR,
        ULONG as _ULONG,
        WCHAR as _WCHAR,
    )

    POINTER, Structure, WinDLL = _POINTER, _Structure, _WinDLL
    byref, cast, create_string_buffer, pointer = _byref, _cast, _create_string_buffer, _pointer
    create_unicode_buffer = _create_unicode_buffer
    c_void_p, c_char, c_size_t = _c_void_p, _c_char, _c_size_t
    ULONG_PTR = c_size_t  # Pointer sizes varies from 32/64 bit so use c_size_t
    LONG = _c_long
    DWORD, ULONG, WCHAR, LPCWSTR, LPWSTR, FILETIME, BOOL = (
        _DWORD, _ULONG, _WCHAR, _LPCWSTR, _LPWSTR, _FILETIME, _BOOL,
    )

    class _CERT_CONTEXT(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_context
        _fields_ = [
            ("dwCertEncodingType", DWORD),
            ("pbCertEncoded", c_void_p),   # MSDN: BYTE*
            ("cbCertEncoded", DWORD),
            ("pCertInfo", c_void_p),       # MSDN: PCERT_INFO (unused currently; will use pbCertEncoded)
            ("hCertStore", c_void_p),      # MSDN: HCERTSTORE
        ]

    class _CredHandle(Structure):
        _fields_ = [("dwLower", ULONG_PTR), ("dwUpper", ULONG_PTR)]

    class _CtxtHandle(Structure):
        _fields_ = [("dwLower", ULONG_PTR), ("dwUpper", ULONG_PTR)]

    class _SecBuffer(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
        _fields_ = [
            ("cbBuffer", ULONG),
            ("BufferType", ULONG),
            ("pvBuffer", c_void_p),
        ]

    class _SecBufferDesc(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbufferdesc
        _fields_ = [("ulVersion", ULONG), ("cBuffers", ULONG), ("pBuffers", POINTER(_SecBuffer))]

    class _SCHANNEL_ALERT_TOKEN(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-schannel_alert_token
        _fields_ = [
            ("dwTokenType", DWORD),
            ("dwAlertType", DWORD),
            ("dwAlertNumber", DWORD),
        ]

    class _TLS_PARAMETERS(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-tls_parameters
        # Unused pointer fields left as c_void_p (always zero / None here).
        _fields_ = [
            ("cAlpnIds", DWORD),
            ("rgstrAlpnIds", c_void_p),          # MSDN: PUNICODE_STRING
            ("grbitDisabledProtocols", DWORD),
            ("cDisabledCrypto", DWORD),
            ("pDisabledCrypto", c_void_p),       # MSDN: PCRYPTO_SETTINGS
            ("dwFlags", DWORD),
        ]

    class _SCH_CREDENTIALS(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-sch_credentials
        _fields_ = [
            ("dwVersion", DWORD),
            ("dwCredFormat", DWORD),
            ("cCreds", DWORD),
            ("paCred", POINTER(POINTER(_CERT_CONTEXT))),  # MSDN: PCCERT_CONTEXT*
            ("hRootStore", c_void_p),            # MSDN: HCERTSTORE
            ("cMappers", DWORD),
            ("aphMappers", c_void_p),            # MSDN: HMAPPER**
            ("dwSessionLifespan", DWORD),
            ("dwFlags", DWORD),
            ("cTlsParameters", DWORD),
            ("pTlsParameters", POINTER(_TLS_PARAMETERS)),
        ]

    class _SecPkgContext_StreamSizes(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_streamsizes
        _fields_ = [
            ("cbHeader", ULONG),
            ("cbTrailer", ULONG),
            ("cbMaximumMessage", ULONG),
            ("cBuffers", ULONG),
            ("cbBlockSize", ULONG),
        ]

    class _SecPkgContext_ConnectionInfo(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/Schannel/ns-schannel-secpkgcontext_connectioninfo
        _fields_ = [
            ("dwProtocol", DWORD),
            ("aiCipher", DWORD),
            ("dwCipherStrength", DWORD),
            ("aiHash", DWORD),
            ("dwHashStrength", DWORD),
            ("aiExch", DWORD),
            ("dwExchStrength", DWORD),
        ]

    class _SecPkgContext_CipherInfo(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_cipherinfo
        _fields_ = [
            ("dwVersion", DWORD),
            ("dwProtocol", DWORD),
            ("dwCipherSuite", DWORD),
            ("dwBaseCipherSuite", DWORD),
            ("szCipherSuite", WCHAR * 64),
            ("szCipher", WCHAR * 64),
            ("dwCipherLen", DWORD),
            ("dwCipherBlockLen", DWORD),
            ("szHash", WCHAR * 64),
            ("dwHashLen", DWORD),
            ("szExchange", WCHAR * 64),
            ("dwMinExchangeLen", DWORD),
            ("dwMaxExchangeLen", DWORD),
            ("szCertificate", WCHAR * 64),
            ("dwKeyType", DWORD),
        ]

    class _CERT_TRUST_STATUS(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_trust_status
        _fields_ = [
            ("dwErrorStatus", DWORD),
            ("dwInfoStatus", DWORD),
        ]

    class _CERT_ENHKEY_USAGE(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-ctl_usage
        _fields_ = [
            ("cUsageIdentifier", DWORD),
            ("rgpszUsageIdentifier", c_void_p),  # MSDN: LPSTR*
        ]

    class _CERT_USAGE_MATCH(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_usage_match
        _fields_ = [
            ("dwType", DWORD),
            ("Usage", _CERT_ENHKEY_USAGE),
        ]

    class _CERT_CHAIN_PARA(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_para
        # Minimal form (cbSize + RequestedUsage); extended fields unused.
        _fields_ = [
            ("cbSize", DWORD),
            ("RequestedUsage", _CERT_USAGE_MATCH),
        ]

    class _CERT_CHAIN_CONTEXT(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_context
        # Only TrustStatus is read; remaining fields keep layout for Free.
        _fields_ = [
            ("cbSize", DWORD),
            ("TrustStatus", _CERT_TRUST_STATUS),
            ("cChain", DWORD),
            ("rgpChain", c_void_p),
            ("cLowerQualityChainContext", DWORD),
            ("rgpLowerQualityChainContext", c_void_p),
            ("fHasRevocationFreshnessTime", BOOL),
            ("dwRevocationFreshnessTime", DWORD),
        ]

    class _CERT_CHAIN_POLICY_PARA(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_policy_para
        _fields_ = [
            ("cbSize", DWORD),
            ("dwFlags", DWORD),
            ("pvExtraPolicyPara", c_void_p),
        ]

    class _CERT_CHAIN_POLICY_STATUS(Structure):
        # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_chain_policy_status
        _fields_ = [
            ("cbSize", DWORD),
            ("dwError", DWORD),
            ("lChainIndex", LONG),
            ("lElementIndex", LONG),
            ("pvExtraPolicyStatus", c_void_p),
        ]

    CERT_CONTEXT = _CERT_CONTEXT
    CredHandle = _CredHandle
    CtxtHandle = _CtxtHandle
    SecBuffer = _SecBuffer
    SecBufferDesc = _SecBufferDesc
    SCHANNEL_ALERT_TOKEN = _SCHANNEL_ALERT_TOKEN
    TLS_PARAMETERS = _TLS_PARAMETERS
    SCH_CREDENTIALS = _SCH_CREDENTIALS
    SecPkgContext_StreamSizes = _SecPkgContext_StreamSizes
    SecPkgContext_ConnectionInfo = _SecPkgContext_ConnectionInfo
    SecPkgContext_CipherInfo = _SecPkgContext_CipherInfo
    CERT_TRUST_STATUS = _CERT_TRUST_STATUS
    CERT_ENHKEY_USAGE = _CERT_ENHKEY_USAGE
    CERT_USAGE_MATCH = _CERT_USAGE_MATCH
    CERT_CHAIN_PARA = _CERT_CHAIN_PARA
    CERT_CHAIN_CONTEXT = _CERT_CHAIN_CONTEXT
    CERT_CHAIN_POLICY_PARA = _CERT_CHAIN_POLICY_PARA
    CERT_CHAIN_POLICY_STATUS = _CERT_CHAIN_POLICY_STATUS

    crypt32 = WinDLL("crypt32", use_last_error=True)
    secur32 = WinDLL("secur32", use_last_error=True)
    kernel32 = WinDLL("kernel32", use_last_error=True)

    # https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/
    # ctypes types that differ from MSDN are noted inline (ABI-compatible for our call sites).
    crypt32.CertOpenStore.restype = c_void_p  # MSDN: HCERTSTORE
    crypt32.CertOpenStore.argtypes = [
        # MSDN: LPCSTR — CERT_STORE_PROV_* are integer IDs cast to LPCSTR, not C strings;
        # LPCSTR would mis-handle the integer provider constant.
        c_void_p,                # lpszStoreProvider
        DWORD,                   # dwEncodingType
        c_void_p,                # hCryptProv (MSDN: HCRYPTPROV_LEGACY; always None here)
        DWORD,                   # dwFlags
        # MSDN: const void* — we only open CERT_STORE_PROV_SYSTEM_W with a Unicode name.
        LPCWSTR,                 # pvPara
    ]
    crypt32.CertEnumCertificatesInStore.restype = POINTER(CERT_CONTEXT)
    crypt32.CertEnumCertificatesInStore.argtypes = [
        c_void_p,                # hCertStore (MSDN: HCERTSTORE)
        POINTER(CERT_CONTEXT),   # pPrevCertContext
    ]
    crypt32.CertDuplicateCertificateContext.restype = POINTER(CERT_CONTEXT)
    crypt32.CertDuplicateCertificateContext.argtypes = [
        POINTER(CERT_CONTEXT),   # pCertContext
    ]
    crypt32.CertFreeCertificateContext.restype = BOOL
    crypt32.CertFreeCertificateContext.argtypes = [
        POINTER(CERT_CONTEXT),   # pCertContext
    ]
    crypt32.CertCloseStore.restype = BOOL
    crypt32.CertCloseStore.argtypes = [
        c_void_p,                # hCertStore (MSDN: HCERTSTORE)
        DWORD,                   # dwFlags
    ]
    crypt32.CertGetNameStringW.restype = DWORD
    crypt32.CertGetNameStringW.argtypes = [
        POINTER(CERT_CONTEXT),   # pCertContext
        DWORD,                   # dwType
        DWORD,                   # dwFlags
        c_void_p,                # pvTypePara
        LPWSTR,                  # pszNameString
        DWORD,                   # cchNameString
    ]
    crypt32.CertGetCertificateChain.restype = BOOL
    crypt32.CertGetCertificateChain.argtypes = [
        c_void_p,                # hChainEngine (MSDN: HCERTCHAINENGINE; HCCE_* IDs)
        POINTER(CERT_CONTEXT),   # pCertContext
        c_void_p,                # pTime (MSDN: LPFILETIME; None = now)
        c_void_p,                # hAdditionalStore (MSDN: HCERTSTORE)
        POINTER(CERT_CHAIN_PARA),  # pChainPara
        DWORD,                   # dwFlags
        c_void_p,                # pvReserved
        POINTER(POINTER(CERT_CHAIN_CONTEXT)),  # ppChainContext
    ]
    crypt32.CertVerifyCertificateChainPolicy.restype = BOOL
    crypt32.CertVerifyCertificateChainPolicy.argtypes = [
        # MSDN: LPCSTR — CERT_CHAIN_POLICY_* are integer IDs cast to LPCSTR.
        c_void_p,                # pszPolicyOID
        POINTER(CERT_CHAIN_CONTEXT),  # pChainContext
        POINTER(CERT_CHAIN_POLICY_PARA),  # pPolicyPara
        POINTER(CERT_CHAIN_POLICY_STATUS),  # pPolicyStatus
    ]
    crypt32.CertFreeCertificateChain.restype = None
    crypt32.CertFreeCertificateChain.argtypes = [
        POINTER(CERT_CHAIN_CONTEXT),  # pChainContext
    ]

    kernel32.GetLastError.restype = DWORD
    kernel32.GetLastError.argtypes = []

    # https://learn.microsoft.com/en-us/windows/win32/api/sspi/
    # Optional pointer args accept None. SECURITY_STATUS → DWORD (same width; compare as unsigned).
    secur32.AcquireCredentialsHandleW.restype = DWORD  # MSDN: SECURITY_STATUS
    secur32.AcquireCredentialsHandleW.argtypes = [
        LPCWSTR,                 # pszPrincipal
        LPCWSTR,                 # pszPackage
        ULONG,                   # fCredentialUse
        c_void_p,                # pvLogonId (optional)
        c_void_p,                # pAuthData (e.g. SCH_CREDENTIALS*)
        c_void_p,                # pGetKeyFn (optional)
        c_void_p,                # pvGetKeyArgument (optional)
        POINTER(CredHandle),     # phCredential
        POINTER(FILETIME),       # ptsExpiry (MSDN: TimeStamp; identical layout)
    ]
    secur32.FreeCredentialsHandle.restype = DWORD  # MSDN: SECURITY_STATUS
    secur32.FreeCredentialsHandle.argtypes = [POINTER(CredHandle)]
    secur32.AcceptSecurityContext.restype = DWORD  # MSDN: SECURITY_STATUS
    secur32.AcceptSecurityContext.argtypes = [
        POINTER(CredHandle),     # phCredential
        POINTER(CtxtHandle),     # phContext (NULL on first call)
        POINTER(SecBufferDesc),  # pInput
        ULONG,                   # fContextReq
        ULONG,                   # TargetDataRep
        POINTER(CtxtHandle),     # phNewContext
        POINTER(SecBufferDesc),  # pOutput
        POINTER(ULONG),          # pfContextAttr
        POINTER(FILETIME),       # ptsExpiry (MSDN: TimeStamp; identical layout)
    ]
    secur32.CompleteAuthToken.restype = DWORD  # MSDN: SECURITY_STATUS
    secur32.CompleteAuthToken.argtypes = [
        POINTER(CtxtHandle),     # phContext
        POINTER(SecBufferDesc),  # pToken
    ]
    secur32.ApplyControlToken.restype = DWORD  # MSDN: SECURITY_STATUS
    secur32.ApplyControlToken.argtypes = [
        POINTER(CtxtHandle),     # phContext
        POINTER(SecBufferDesc),  # pInput
    ]
    secur32.DeleteSecurityContext.restype = DWORD  # MSDN: SECURITY_STATUS
    secur32.DeleteSecurityContext.argtypes = [POINTER(CtxtHandle)]
    secur32.QueryContextAttributesW.restype = DWORD  # MSDN: SECURITY_STATUS
    secur32.QueryContextAttributesW.argtypes = [
        POINTER(CtxtHandle),     # phContext
        ULONG,                   # ulAttribute
        c_void_p,                # pBuffer
    ]
    secur32.EncryptMessage.restype = DWORD  # MSDN: SECURITY_STATUS
    secur32.EncryptMessage.argtypes = [
        POINTER(CtxtHandle),     # phContext
        ULONG,                   # fQOP
        POINTER(SecBufferDesc),  # pMessage
        ULONG,                   # MessageSeqNo
    ]
    secur32.DecryptMessage.restype = DWORD  # MSDN: SECURITY_STATUS
    secur32.DecryptMessage.argtypes = [
        POINTER(CtxtHandle),     # phContext
        POINTER(SecBufferDesc),  # pMessage
        ULONG,                   # MessageSeqNo
        POINTER(ULONG),          # pfQOP (optional)
    ]
    secur32.FreeContextBuffer.restype = DWORD  # MSDN: SECURITY_STATUS
    secur32.FreeContextBuffer.argtypes = [
        c_void_p,                # pvContextBuffer
    ]

    _win32_loaded = True
