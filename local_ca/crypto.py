"""Cryptographic primitives: CA key management, signing and verification.

The CA keeps its keypairs on disk under ``key_dir`` as
``ca-<generation>.key.pem`` / ``ca-<generation>.crt.pem`` plus a
``current`` pointer file. Rotation creates a new generation while old
generations stay loadable, so certificates issued before a rotation
remain verifiable. All files are written atomically (tmp + rename) so a
crash can never leave half a key or half a certificate on disk.
"""

from __future__ import annotations

import datetime
import os
import threading
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

_CA_COMMON_NAME = "Local Certificate Authority"


@dataclass(frozen=True)
class IssuedCertificate:
    """A freshly signed certificate and its private key."""

    cert_pem: str
    private_key_pem: str
    serial: str
    not_before: float
    not_after: float
    ca_generation: int


class CAKeyStore:
    """Loads or generates the CA signing keypair, supports rotation."""

    def __init__(self, key_dir: str) -> None:
        self._dir = key_dir
        self._lock = threading.RLock()
        os.makedirs(self._dir, exist_ok=True)
        self._keys: dict[int, rsa.RSAPrivateKey] = {}
        self._certs: dict[int, x509.Certificate] = {}
        current = self._read_current_generation()
        if current is None:
            self._generate_generation(1)
            self._write_current_generation(1)
            current = 1
        self._load_generation(current)
        self._current = current

    # ----------------------------------------------------------- properties
    @property
    def current_generation(self) -> int:
        with self._lock:
            return self._current

    @property
    def current_ca_cert_pem(self) -> str:
        with self._lock:
            return self._cert_pem(self._certs[self._current])

    # -------------------------------------------------------------- rotation
    def rotate(self) -> int:
        """Generate a new CA generation and make it current.

        Older generations remain loaded so previously issued certificates
        are still verifiable. Returns the new generation number.
        """
        with self._lock:
            new_generation = self._current + 1
            self._generate_generation(new_generation)
            self._write_current_generation(new_generation)
            self._load_generation(new_generation)
            self._current = new_generation
            return new_generation

    def ensure_previous_loaded(self) -> None:
        """Load every generation on disk (used after restart/recovery)."""
        with self._lock:
            for name in os.listdir(self._dir):
                if name.startswith("ca-") and name.endswith(".crt.pem"):
                    generation = int(name[len("ca-") : -len(".crt.pem")])
                    if generation not in self._certs:
                        self._load_generation(generation)

    # -------------------------------------------------------------- issuance
    def issue_certificate(
        self,
        domain: str,
        not_before: float,
        not_after: float,
    ) -> IssuedCertificate:
        """Sign a new leaf certificate for ``domain`` with the current CA."""
        with self._lock:
            ca_key = self._keys[self._current]
            ca_cert = self._certs[self._current]
            generation = self._current

        leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        serial = x509.random_serial_number()
        nb = datetime.datetime.fromtimestamp(not_before, datetime.timezone.utc)
        na = datetime.datetime.fromtimestamp(not_after, datetime.timezone.utc)
        subject = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, domain)]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(ca_cert.subject)
            .public_key(leaf_key.public_key())
            .serial_number(serial)
            .not_valid_before(nb)
            .not_valid_after(na)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain)]),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        return IssuedCertificate(
            cert_pem=self._cert_pem(cert),
            private_key_pem=leaf_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode("ascii"),
            serial=str(serial),
            not_before=not_before,
            not_after=not_after,
            ca_generation=generation,
        )

    # ----------------------------------------------------------- verification
    def verify_certificate(self, cert_pem: str, now: float) -> bool:
        """Check signature chain and validity window against any known CA."""
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
        except ValueError:
            return False
        moment = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
        if not (cert.not_valid_before_utc <= moment <= cert.not_valid_after_utc):
            return False
        with self._lock:
            candidates = list(self._certs.values())
        for ca_cert in candidates:
            if ca_cert.subject != cert.issuer:
                continue
            try:
                ca_cert.public_key().verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
                return True
            except Exception:
                continue
        return False

    # -------------------------------------------------------------- internal
    def _key_path(self, generation: int) -> str:
        return os.path.join(self._dir, f"ca-{generation}.key.pem")

    def _cert_path(self, generation: int) -> str:
        return os.path.join(self._dir, f"ca-{generation}.crt.pem")

    def _current_path(self) -> str:
        return os.path.join(self._dir, "current")

    @staticmethod
    def _cert_pem(cert: x509.Certificate) -> str:
        return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")

    @staticmethod
    def _atomic_write(path: str, data: bytes) -> None:
        tmp = f"{path}.tmp.{os.getpid()}"
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def _generate_generation(self, generation: int) -> None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _CA_COMMON_NAME)])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
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
            .sign(key, hashes.SHA256())
        )
        self._atomic_write(
            self._key_path(generation),
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        self._atomic_write(
            self._cert_path(generation),
            cert.public_bytes(serialization.Encoding.PEM),
        )

    def _load_generation(self, generation: int) -> None:
        with open(self._key_path(generation), "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
        with open(self._cert_path(generation), "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        self._keys[generation] = key
        self._certs[generation] = cert

    def _read_current_generation(self) -> int | None:
        try:
            with open(self._current_path(), "r", encoding="ascii") as fh:
                return int(fh.read().strip())
        except (OSError, ValueError):
            return None

    def _write_current_generation(self, generation: int) -> None:
        self._atomic_write(self._current_path(), str(generation).encode("ascii"))
