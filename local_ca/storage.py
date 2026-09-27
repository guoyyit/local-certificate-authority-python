"""SQLite-backed persistence with atomic state transitions."""

from __future__ import annotations

from .models import (
    Account,
    AuditEvent,
    Authorization,
    CertificateRecord,
    Challenge,
)


class Storage:
    """Durable store for accounts, authorizations, challenges and certificates."""

    def __init__(self, db_path: str) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
