"""Key generation and X.509 certificate signing helpers.

Pure functions plus a small ``CAIdentity`` container. The CA key material
is persisted by the service layer (inside the SQLite ``meta`` table) so it
survives restarts and is covered by the same transactional guarantees.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_KEY_SIZE = 2048
_PUBLIC_EXPONENT = 65537


def generate_private_key_pem() -> str:
    """Generate a new RSA private key and return it as PEM."""
    key = rsa.generate_private_key(
        public_exponent=_PUBLIC_EXPONENT, key_size=_KEY_SIZE
    )
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def random_serial_number() -> int:
    """Return a random positive X.509 serial number."""
    return x509.random_serial_number()


def _load_key(pem: str):
    return serialization.load_pem_private_key(pem.encode("ascii"), password=None)


def _load_cert(pem: str) -> x509.Certificate:
    return x509.load_pem_x509_certificate(pem.encode("ascii"))


def create_ca_certificate_pem(
    ca_key_pem: str,
    common_name: str,
    not_before: datetime,
    not_after: datetime,
) -> str:
    """Create a self-signed CA certificate for the given CA key."""
    key = _load_key(ca_key_pem)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "local-ca"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def issue_certificate_pem(
    domain: str,
    subject_private_key_pem: str,
    ca_key_pem: str,
    ca_cert_pem: str,
    not_before: datetime,
    not_after: datetime,
    serial_number: int,
) -> str:
    """Sign a server certificate for ``domain`` with the local CA key."""
    subject_key = _load_key(subject_private_key_pem)
    ca_key = _load_key(ca_key_pem)
    ca_cert = _load_cert(ca_cert_pem)
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, domain),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "local-ca-issued"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(serial_number)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


@dataclass(frozen=True)
class CAIdentity:
    """The local CA's own key pair and self-signed certificate."""

    key_pem: str
    cert_pem: str

    @classmethod
    def generate(cls, common_name: str, not_before: datetime, not_after: datetime) -> "CAIdentity":
        key_pem = generate_private_key_pem()
        cert_pem = create_ca_certificate_pem(key_pem, common_name, not_before, not_after)
        return cls(key_pem=key_pem, cert_pem=cert_pem)


def verify_certificate_signature(cert_pem: str, ca_cert_pem: str) -> bool:
    """Check that ``cert_pem`` was signed by the CA in ``ca_cert_pem``."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding

    cert = _load_cert(cert_pem)
    ca_cert = _load_cert(ca_cert_pem)
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except InvalidSignature:
        return False
    return True
