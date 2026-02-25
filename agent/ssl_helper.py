"""
Infrastructure Agent: SSL helper functions
Copyright (C) 2003-2026 ITRS Group Ltd. All rights reserved
"""

from __future__ import annotations


import logging
import os
import socket
import ssl
import subprocess
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from agent.config import get_agent_root

if TYPE_CHECKING:
    from agent.config import TLSConfig

logger = logging.getLogger(__name__)

OPENSSL = '/usr/bin/openssl'
SELF_SIGNED_CERTIF_DIR = 'var'
# Exponent set based on IETF recommendations https://www.ietf.org/rfc/rfc4871.txt
KEY_PUBLIC_EXPONENT = 65537
KEY_SIZE = 2048


class AgentSSLError(Exception):
    """SSL exceptions"""

    pass


def get_ssl_context(tls_config: TLSConfig, name: str, client_mode=False) -> ssl.SSLContext:
    """Validate the TLS configuration and set up the SSL context"""
    logger.debug("%s: Using OpenSSL version '%s'", name, ssl.OPENSSL_VERSION)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT if client_mode else ssl.PROTOCOL_TLS_SERVER)
    has_supplied_ca = bool(tls_config.ca_cert or tls_config.ca_path)
    if client_mode:
        if tls_config.check_server_cert:
            logger.debug("%s: Check server certificate", name)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    else:
        if tls_config.check_client_cert:
            logger.debug("%s: Check client certificate", name)
            context.verify_mode = ssl.CERT_REQUIRED
        else:
            context.verify_mode = ssl.CERT_OPTIONAL
        if not tls_config.cert_file:
            if not tls_config.key_file and not has_supplied_ca:
                tls_config.key_file, tls_config.cert_file = create_self_signed_cert(name, SELF_SIGNED_CERTIF_DIR)
            else:
                error = f"{name}: TLS config 'cert_file' not specified"
                logger.error(error)
                raise AgentSSLError(error)

    if tls_config.log_all_messages:
        logger.debug("%s: Logging all TLS messages", name)
        context._msg_callback = ssl_debug_message_callback

    if has_supplied_ca:
        logger.debug("%s: Using configured CA Certificate(s)", name)
        # check access - load_verify_locations() does not indicate which item failed
        try:
            if tls_config.ca_cert:
                check_file_access(tls_config.ca_cert)
            if tls_config.ca_path:
                os.listdir(tls_config.ca_path)
            context.load_verify_locations(tls_config.ca_cert, tls_config.ca_path)
        except Exception as ex:
            raise AgentSSLError(f"{name}: {str(ex)}")
    else:
        logger.debug("%s: Loading system default CA certificates", name)
        context.load_default_certs(purpose=ssl.Purpose.CLIENT_AUTH)

    if tls_config.cert_file:
        logger.debug("%s: Using configured TLS cert_file%s", name, " and key_file" if tls_config.key_file else "")
        try:
            # check access - load_cert_chain() does not indicate which item failed
            check_file_access(tls_config.cert_file)
            if tls_config.key_file:
                check_file_access(tls_config.key_file)
            context.load_cert_chain(tls_config.cert_file, tls_config.key_file)
        except ssl.SSLError:
            files = f"{tls_config.cert_file} {tls_config.key_file if tls_config.key_file else ''}"
            error = f"{name}: TLS key missing or does not match the certificate: {files.strip()}"
            logger.error(error)
            raise AgentSSLError(error)
        except Exception as ex:
            raise AgentSSLError(f"{name}: {str(ex)}")

    if tls_config.cipher_suite:
        logger.debug("%s: Using configured TLS ciphers", name)
        context.set_ciphers(tls_config.cipher_suite)

    # Set custom SSL options
    for option in tls_config.context_options:
        try:
            context.options |= getattr(ssl, f'OP_{option}')
            logger.debug("%s: Setting Context property 'ssl.OP_%s'", name, option)
        except AttributeError:
            logger.error("Invalid %s tls_context_option '%s' in config.", name, option)
            raise

    return context


def verify_certificate(tls_config: TLSConfig):
    """
    Check the certificate for problems
    Only available on platforms that support "openssl verify"
    """
    command = [OPENSSL, 'verify']
    if tls_config.ca_cert:
        command += ['-CAfile', tls_config.ca_cert]
    if tls_config.ca_path:
        command += ['-CApath', tls_config.ca_path]
    command.append(tls_config.cert_file)
    verify = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if verify.returncode:
        logger.warning(verify.stdout.decode('utf-8').strip())
        for error in verify.stderr.decode('utf-8').splitlines():
            logger.warning("%s", error)


def ssl_debug_message_callback(
        _conn: ssl.SSLSocket,
        direction: str,
        version: ssl.TLSVersion,
        content_type: ssl._TLSContentType,
        msg_type: ssl._TLSMessageType,
        _data: bytes):
    """
    Called after every TLS protocol message (not application messages) this function debug logs:
      * the direction of the message (read/write)
      * the message type
      * the version of the packet
      * the content type of the packet

    Full details on args can be found in ssl.SSLContext._msg_callback
    """
    logger.debug(
        f"| tls message {direction: <5} | {version.name: <7} | {msg_type.name: <20} | {content_type.name: <20}"
    )


def check_file_access(filename):
    """Check a file can be read"""
    with open(filename):
        pass


def create_self_signed_cert(config_name: str, output_dir: str) -> tuple[str, str]:
    """Creates new self-signed private key and certificate in a specified directory.

    Returns the private-key path and the certificate path.
    """
    os.makedirs(output_dir, exist_ok=True)
    hostname = f'{socket.gethostname()}-{config_name}'
    fqdn = socket.getfqdn()
    base_path = get_agent_root() / output_dir / hostname
    private_key_path = base_path.with_suffix('.key')
    cert_path = base_path.with_suffix('.crt')
    if private_key_path.exists() and cert_path.exists():
        return private_key_path.resolve(), cert_path.resolve()

    logger.info("%s: Creating new self-signed certificate for '%s'", config_name, fqdn)
    private_key = rsa.generate_private_key(
        KEY_PUBLIC_EXPONENT,
        KEY_SIZE,
        backend=default_backend(),
    )
    # Create the private key file (only readable/writable by current user)
    with open(private_key_path, 'wb', opener=open_with_mode(0o600)) as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "GB"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "London"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "EC2"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ITRS Group Ltd"),
        x509.NameAttribute(NameOID.COMMON_NAME, fqdn),
    ])

    now = datetime.now(timezone.utc)

    # Create the certificate
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=100 * 365))  # Good for a long time
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(fqdn)]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), backend=default_backend())
    )
    with open(cert_path, 'wb', opener=open_with_mode(0o644)) as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return private_key_path.resolve(), cert_path.resolve()


def open_with_mode(mode):
    """Creates a new file opener with a specific mode"""

    def opener(path, flags):
        return os.open(path, flags, mode)

    return opener
