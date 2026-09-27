"""SQLite-backed persistence with transactional integrity.

All multi-statement writes happen inside ``transaction()`` which uses
``BEGIN IMMEDIATE`` so concurrent writers are serialized and a crash
mid-transaction leaves no partial state behind.
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from local_ca import models
from local_ca.errors import ConflictError

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    contact    TEXT NOT NULL UNIQUE,
    token      TEXT NOT NULL,
    role       TEXT NOT NULL,
    status     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorizations (
    authorization_id TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES accounts(account_id),
    domain           TEXT NOT NULL,
    status           TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    expires_at       TEXT NOT NULL,
    UNIQUE(account_id, domain)
);
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id    TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL REFERENCES authorizations(authorization_id),
    domain          TEXT NOT NULL,
    type            TEXT NOT NULL,
    token           TEXT NOT NULL,
    expected_value  TEXT NOT NULL,
    status          TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_challenges_one_active_per_domain
    ON challenges(domain) WHERE status = 'pending';
CREATE TABLE IF NOT EXISTS certificates (
    serial           TEXT PRIMARY KEY,
    account_id       TEXT NOT NULL REFERENCES accounts(account_id),
    domain           TEXT NOT NULL,
    pem_certificate  TEXT NOT NULL,
    pem_private_key  TEXT NOT NULL,
    not_before       TEXT NOT NULL,
    not_after        TEXT NOT NULL,
    status           TEXT NOT NULL,
    revoked_at       TEXT,
    revocation_reason TEXT,
    created_at       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    event_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    actor      TEXT NOT NULL,
    action     TEXT NOT NULL,
    target     TEXT NOT NULL,
    detail     TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _dt(value: str) -> models.datetime:
    return models.datetime.fromisoformat(value)


class Storage:
    """Durable store for accounts, authorizations, challenges, certificates and audit events."""

    def __init__(self, db_path: str | Path) -> None:
        self._conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._lock = threading.RLock()
        self._in_transaction = False
        with self._write():
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    @contextmanager
    def _write(self) -> Iterator[None]:
        """Serialize a write and commit it unless an outer transaction will.

        ``with conn:`` commits on exit, which would break the atomicity of an
        enclosing ``transaction()`` block; so inside a transaction we yield
        without committing and let the outer block decide.
        """
        with self._lock:
            if self._in_transaction:
                yield
            else:
                with self._conn:
                    yield

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Run the enclosed statements in one immediate transaction."""
        with self._lock:
            assert not self._in_transaction, "nested transactions are not supported"
            self._conn.execute("BEGIN IMMEDIATE")
            self._in_transaction = True
            try:
                yield
            except BaseException:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()
            finally:
                self._in_transaction = False

    # --- accounts ---
    def create_account_if_absent(self, account: models.Account) -> models.Account:
        with self._write():
            self._conn.execute(
                "INSERT OR IGNORE INTO accounts"
                " (account_id, contact, token, role, status, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    account.account_id,
                    account.contact,
                    account.token,
                    account.role.value,
                    account.status.value,
                    account.created_at.isoformat(),
                ),
            )
        existing = self.get_account_by_contact(account.contact)
        assert existing is not None
        return existing

    def get_account(self, account_id: str) -> models.Account | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
        return self._row_to_account(row) if row else None

    def get_account_by_contact(self, contact: str) -> models.Account | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM accounts WHERE contact = ?", (contact,)
            ).fetchone()
        return self._row_to_account(row) if row else None

    def get_account_by_token(self, token: str) -> models.Account | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM accounts WHERE token = ?", (token,)
            ).fetchone()
        return self._row_to_account(row) if row else None

    def set_account_status(self, account_id: str, status: models.AccountStatus) -> None:
        with self._write():
            self._conn.execute(
                "UPDATE accounts SET status = ? WHERE account_id = ?",
                (status.value, account_id),
            )

    # --- authorizations ---
    def create_authorization_if_absent(
        self, authorization: models.Authorization
    ) -> tuple[models.Authorization, bool]:
        with self._write():
            cursor = self._conn.execute(
                "INSERT OR IGNORE INTO authorizations"
                " (authorization_id, account_id, domain, status, created_at, expires_at)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    authorization.authorization_id,
                    authorization.account_id,
                    authorization.domain,
                    authorization.status.value,
                    authorization.created_at.isoformat(),
                    authorization.expires_at.isoformat(),
                ),
            )
            created = cursor.rowcount == 1
        existing = self.get_authorization_by_account_domain(
            authorization.account_id, authorization.domain
        )
        assert existing is not None
        return existing, created

    def get_authorization(self, authorization_id: str) -> models.Authorization | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM authorizations WHERE authorization_id = ?",
                (authorization_id,),
            ).fetchone()
        return self._row_to_authorization(row) if row else None

    def get_authorization_by_account_domain(
        self, account_id: str, domain: str
    ) -> models.Authorization | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM authorizations WHERE account_id = ? AND domain = ?",
                (account_id, domain),
            ).fetchone()
        return self._row_to_authorization(row) if row else None

    def set_authorization_status(
        self, authorization_id: str, status: models.AuthorizationStatus
    ) -> None:
        with self._write():
            self._conn.execute(
                "UPDATE authorizations SET status = ? WHERE authorization_id = ?",
                (status.value, authorization_id),
            )

    def refresh_authorization(
        self,
        authorization_id: str,
        status: models.AuthorizationStatus,
        expires_at: str,
    ) -> None:
        """Move an authorization back to pending with a fresh expiry window."""
        with self._write():
            self._conn.execute(
                "UPDATE authorizations SET status = ?, expires_at = ?"
                " WHERE authorization_id = ?",
                (status.value, expires_at, authorization_id),
            )

    def expire_authorizations(self, now: str) -> int:
        with self._write():
            cursor = self._conn.execute(
                "UPDATE authorizations SET status = ? WHERE status = ? AND expires_at <= ?",
                (
                    models.AuthorizationStatus.EXPIRED.value,
                    models.AuthorizationStatus.PENDING.value,
                    now,
                ),
            )
            return cursor.rowcount

    # --- challenges ---
    def create_challenge_if_no_active(
        self, challenge: models.Challenge
    ) -> tuple[models.Challenge, bool]:
        """Insert a pending challenge; if one is already active for the domain, return it."""
        with self._write():
            try:
                self._conn.execute(
                    "INSERT INTO challenges"
                    " (challenge_id, authorization_id, domain, type, token,"
                    "  expected_value, status, created_at, expires_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        challenge.challenge_id,
                        challenge.authorization_id,
                        challenge.domain,
                        challenge.type.value,
                        challenge.token,
                        challenge.expected_value,
                        challenge.status.value,
                        challenge.created_at.isoformat(),
                        challenge.expires_at.isoformat(),
                    ),
                )
                return challenge, True
            except sqlite3.IntegrityError:
                existing = self.get_active_challenge_for_domain(challenge.domain)
                assert existing is not None
                return existing, False

    def get_challenge(self, challenge_id: str) -> models.Challenge | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)
            ).fetchone()
        return self._row_to_challenge(row) if row else None

    def get_active_challenge_for_domain(self, domain: str) -> models.Challenge | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM challenges WHERE domain = ? AND status = ?",
                (domain, models.ChallengeStatus.PENDING.value),
            ).fetchone()
        return self._row_to_challenge(row) if row else None

    def get_challenges_for_authorization(
        self, authorization_id: str
    ) -> list[models.Challenge]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM challenges WHERE authorization_id = ?"
                " ORDER BY created_at",
                (authorization_id,),
            ).fetchall()
        return [self._row_to_challenge(r) for r in rows]

    def set_challenge_status(self, challenge_id: str, status: models.ChallengeStatus) -> None:
        with self._write():
            self._conn.execute(
                "UPDATE challenges SET status = ? WHERE challenge_id = ?",
                (status.value, challenge_id),
            )

    def expire_challenges(self, now: str) -> int:
        with self._write():
            cursor = self._conn.execute(
                "UPDATE challenges SET status = ? WHERE status = ? AND expires_at <= ?",
                (
                    models.ChallengeStatus.EXPIRED.value,
                    models.ChallengeStatus.PENDING.value,
                    now,
                ),
            )
            return cursor.rowcount

    # --- certificates ---
    def insert_certificate(self, record: models.CertificateRecord) -> None:
        with self._write():
            self._conn.execute(
                "INSERT INTO certificates"
                " (serial, account_id, domain, pem_certificate, pem_private_key,"
                "  not_before, not_after, status, revoked_at, revocation_reason, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    record.serial,
                    record.account_id,
                    record.domain,
                    record.pem_certificate,
                    record.pem_private_key,
                    record.not_before.isoformat(),
                    record.not_after.isoformat(),
                    record.status.value,
                    record.revoked_at.isoformat() if record.revoked_at else None,
                    record.revocation_reason,
                    record.created_at.isoformat(),
                ),
            )

    def get_certificate(self, serial: str) -> models.CertificateRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM certificates WHERE serial = ?", (serial,)
            ).fetchone()
        return self._row_to_certificate(row) if row else None

    def list_certificates(self, domain: str | None = None) -> list[models.CertificateRecord]:
        with self._lock:
            if domain is None:
                rows = self._conn.execute(
                    "SELECT * FROM certificates ORDER BY created_at"
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM certificates WHERE domain = ? ORDER BY created_at",
                    (domain,),
                ).fetchall()
        return [self._row_to_certificate(r) for r in rows]

    def get_active_certificate_for_domain(
        self, domain: str
    ) -> models.CertificateRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM certificates WHERE domain = ? AND status = ?"
                " ORDER BY not_before DESC LIMIT 1",
                (domain, models.CertificateStatus.ACTIVE.value),
            ).fetchone()
        return self._row_to_certificate(row) if row else None

    def get_active_certificate_for_account_domain(
        self, account_id: str, domain: str
    ) -> models.CertificateRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM certificates"
                " WHERE account_id = ? AND domain = ? AND status = ?"
                " ORDER BY not_before DESC LIMIT 1",
                (account_id, domain, models.CertificateStatus.ACTIVE.value),
            ).fetchone()
        return self._row_to_certificate(row) if row else None

    def set_certificate_revoked(self, serial: str, revoked_at: str, reason: str) -> None:
        with self._write():
            self._conn.execute(
                "UPDATE certificates SET status = ?, revoked_at = ?,"
                " revocation_reason = ? WHERE serial = ?",
                (models.CertificateStatus.REVOKED.value, revoked_at, reason, serial),
            )

    # --- audit ---
    def append_audit(
        self, actor: str, action: str, target: str, detail: str, created_at: str
    ) -> None:
        with self._write():
            self._conn.execute(
                "INSERT INTO audit (actor, action, target, detail, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (actor, action, target, detail, created_at),
            )

    def list_audit(self) -> list[models.AuditEvent]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM audit ORDER BY event_id"
            ).fetchall()
        return [
            models.AuditEvent(
                event_id=r["event_id"],
                actor=r["actor"],
                action=r["action"],
                target=r["target"],
                detail=r["detail"],
                created_at=_dt(r["created_at"]),
            )
            for r in rows
        ]

    # --- meta ---
    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else None

    def set_meta_if_absent(self, key: str, value: str) -> str:
        with self._write():
            self._conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES (?, ?)", (key, value)
            )
        existing = self.get_meta(key)
        assert existing is not None
        return existing

    # --- row mapping ---
    @staticmethod
    def _row_to_account(row: sqlite3.Row) -> models.Account:
        return models.Account(
            account_id=row["account_id"],
            contact=row["contact"],
            token=row["token"],
            role=models.Role(row["role"]),
            status=models.AccountStatus(row["status"]),
            created_at=_dt(row["created_at"]),
        )

    @staticmethod
    def _row_to_authorization(row: sqlite3.Row) -> models.Authorization:
        return models.Authorization(
            authorization_id=row["authorization_id"],
            account_id=row["account_id"],
            domain=row["domain"],
            status=models.AuthorizationStatus(row["status"]),
            created_at=_dt(row["created_at"]),
            expires_at=_dt(row["expires_at"]),
        )

    @staticmethod
    def _row_to_challenge(row: sqlite3.Row) -> models.Challenge:
        return models.Challenge(
            challenge_id=row["challenge_id"],
            authorization_id=row["authorization_id"],
            domain=row["domain"],
            type=models.ChallengeType(row["type"]),
            token=row["token"],
            expected_value=row["expected_value"],
            status=models.ChallengeStatus(row["status"]),
            created_at=_dt(row["created_at"]),
            expires_at=_dt(row["expires_at"]),
        )

    @staticmethod
    def _row_to_certificate(row: sqlite3.Row) -> models.CertificateRecord:
        return models.CertificateRecord(
            serial=row["serial"],
            account_id=row["account_id"],
            domain=row["domain"],
            pem_certificate=row["pem_certificate"],
            pem_private_key=row["pem_private_key"],
            not_before=_dt(row["not_before"]),
            not_after=_dt(row["not_after"]),
            status=models.CertificateStatus(row["status"]),
            revoked_at=_dt(row["revoked_at"]) if row["revoked_at"] else None,
            revocation_reason=row["revocation_reason"],
            created_at=_dt(row["created_at"]),
        )
