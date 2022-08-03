from __future__ import annotations
from dataclasses import dataclass
from functools import lru_cache
from random import randint
from pathlib import Path
from ssl import SSLContext, PROTOCOL_SSLv23
from ipaddress import IPv4Address, IPv6Address

import OpenSSL

LRU_MAX_SIZE = 1024
"""
Max size of the LRU cache used by `CertificateAuthority.new_context()` method. Defaults
to 1024.

Due to limitations of the Python's SSL module we are unable to load certificates/keys
from memory; on every request we must dump the generated cert/key to disk and pass the
paths `ssl.SSLContext.load_cert_chain()` method. For a few requests this is not an
issue, but for a large quantity of requests this is a significant performance hit.

To mitigate this issue we cache the generated SSLContext using
`lru_cache <https://docs.python.org/3/library/functools.html#functools.lru_cache>`_.
`LRU_MAX_SIZE` defines the maximum number of cached `ssl.SSLContexts` that can be stored
in memory at one time. This value can be modified by editing it _before_
`CertificateAuthority` is used elsewhere.

    .. code-block:: python

        from mitm import MITM, CertificateAuthority, middleware, protocol, crypto
        from pathlib import Path

        # Updates the maximum size of the LRU cache.
        crypto.LRU_MAX_SIZE = 2048

        # Rest of the code goes here.
"""


def make_rsa_pair(bits: int = 2048) -> OpenSSL.crypto.PKey:
    rsa = OpenSSL.crypto.PKey()
    rsa.generate_key(type=OpenSSL.crypto.TYPE_RSA, bits=bits)

    return rsa


def make_non_signed_x509_certificate(
    country_name: str = 'US',
    state_or_province_name: str = 'New York',
    locality: str = 'New York',
    organization_name: str = 'mitm',
    organization_unit_name: str = 'mitm',
    common_name: str = 'mitm',
    serial_number: int | None = None,
    time_not_before: int = 0,
    time_not_after: int = 1 * (365 * 24 * 60 * 60)
) -> OpenSSL.crypto.X509:
    """
    Generates a non-signed X509 certificate.

    :param country_name:
    :param state_or_province_name:
    :param locality:
    :param organization_name:
    :param organization_unit_name:
    :param common_name:
    :param serial_number:
    :param time_not_before:
    :param time_not_after:
    :return:
    """

    cert = OpenSSL.crypto.X509()
    cert.get_subject().C = country_name
    cert.get_subject().ST = state_or_province_name
    cert.get_subject().L = locality
    cert.get_subject().O = organization_name
    cert.get_subject().OU = organization_unit_name
    cert.get_subject().CN = common_name
    cert.set_serial_number(serial_number or randint(0, 2**64 - 1))
    cert.set_version(2)
    cert.gmtime_adj_notBefore(time_not_before)
    cert.gmtime_adj_notAfter(time_not_after)
    cert.set_issuer(cert.get_subject())

    return cert


@dataclass(unsafe_hash=True)
class CertificateAuthority:
    key: OpenSSL.crypto.PKey
    cert: OpenSSL.crypto.X509

    def __post_init__(self):
        self.cert.set_pubkey(pkey=self.key)
        self.cert.add_extensions([
            OpenSSL.crypto.X509Extension(
                type_name=b'basicConstraints',
                critical=True,
                value=b'CA:TRUE, pathlen:0'),
            OpenSSL.crypto.X509Extension(
                type_name=b'keyUsage',
                critical=True,
                value=b'keyCertSign, cRLSign'
            ),
            OpenSSL.crypto.X509Extension(
                type_name=b'subjectKeyIdentifier',
                critical=False,
                value=b'hash',
                subject=self.cert
            )
        ])
        self.cert.sign(pkey=self.key, digest='sha256')

    @classmethod
    def from_path(cls, cert_path: Path | str, key_path: Path | str) -> CertificateAuthority:
        return cls(
            key=OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, Path(key_path).read_bytes()),
            cert=OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, Path(cert_path).read_bytes())
        )

    def save(self, cert_path: Path | str, key_path: Path | str) -> tuple[int, int]:
        return (
            Path(cert_path).write_bytes(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.cert)),
            Path(key_path).write_bytes(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key))
        )

    def _new_x509(self, host: str | IPv4Address | IPv6Address) -> tuple[OpenSSL.crypto.X509, OpenSSL.crypto.PKey]:
        """

        :param host:
        :return:
        """

        # Generate a new key pair.

        key = make_rsa_pair()

        # Generates new X509Request.

        req = OpenSSL.crypto.X509Req()
        req.get_subject().CN = str(host).encode()
        req.set_pubkey(key)
        req.sign(key, 'sha256')

        # Generate a new X509 certificate.

        cert = make_non_signed_x509_certificate(common_name=str(host))
        cert.set_issuer(self.cert.get_subject())
        cert.set_pubkey(req.get_pubkey())

        # Set the certificate 'subjectAltName' extension.

        hosts = [f"DNS:{host}"]
        if isinstance(host, (IPv4Address, IPv6Address)):
            hosts += [f"IP:{host}"]
        else:
            hosts += [f"DNS:*.{host}"]

        cert.add_extensions([
            OpenSSL.crypto.X509Extension(type_name=b'subjectAltName', critical=False, value=', '.join(hosts).encode())
        ])

        # Sign the certificate with the CA's key.

        cert.sign(self.key, "sha256")

        return cert, key

    @lru_cache(maxsize=LRU_MAX_SIZE)
    def new_context(self, host: str | IPv4Address | IPv6Address) -> SSLContext:
        """
        Generates a new SSLContext with the given X509 certificate and private key.

        :param host: The host for which to create an SSL context.
        :return:
        """
        """"""

        # Generates cert/key for the host.

        cert, key = self._new_x509(host=host)

        # Store cert and key into file. Unfortunately we need to store them in disk
        # because SSLContext does not support loading from memory. This is a limitation
        # of the Python standard library, and the community: https://bugs.python.org/issue16487
        # Alternatives cannot be used for this because this context is eventually used
        # by asyncio.get_event_loop().start_tls(..., sslcontext=..., ...) parameter,
        # which only support ssl.SSLContext. To mitigate this we use lru_cache to
        # cache the SSLContext for each host. It works fairly well, but its not the
        # preferred way to do it... loading from memory would be better.

        cert_path = Path('temp_certs') / f'{host}.crt'
        key_path = Path('temp_certs') / f'{host}.key'

        cert_path.write_bytes(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert))
        key_path.write_bytes(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key))

        # Creates new SSLContext.
        context = SSLContext(protocol=PROTOCOL_SSLv23)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)

        # Remove the temporary files.
        cert_path.unlink()
        key_path.unlink()

        return context
