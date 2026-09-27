"""Business logic: account/authorization/challenge/certificate lifecycle."""

from __future__ import annotations

from .crypto import CAKeyStore
from .storage import Storage


class CertificateAuthorityService:
    """Coordinates state transitions, permissions and auditing."""

    def __init__(self, storage: Storage, ca_keys: CAKeyStore) -> None:
        raise NotImplementedError
