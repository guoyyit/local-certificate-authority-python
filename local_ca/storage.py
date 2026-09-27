"""SQLite-backed persistence with atomic state transitions.

All writes go through a single connection guarded by a re-entrant lock.
State changes use conditional UPDATE statements (``WHERE status = ...``)
so concurrent requests cannot overwrite each other, and multi-row writes
are wrapped in transactions so a crash never leaves half-written records.
"""

from __future__ import annotations

import sqlite3
import threading

from .models import (
    Account,
    AccountStatus,
    AuditEvent,
    Authorization,
    AuthorizationStatus,
    CertificateRecord,
    CertificateStatus,
    Challenge,
    ChallengeStatus,
    Role,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    account_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS authorizations (
    authz_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_authz_domain ON authorizations(domain, status);
CREATE TABLE IF NOT EXISTS challenges (
    challenge_id TEXT PRIMARY KEY,
    authz_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    token TEXT NOT NULL,
    expected_response TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenges_domain ON challenges(domain, status);
CREATE TABLE IF NOT EXISTS certificates (
    cert_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    domain TEXT NOT NULL,
    serial TEXT NOT NULL UNIQUE,
    pem TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    status TEXT NOT NULL,
    not_before REAL NOT NULL,
    not_after REAL NOT NULL,
    issued_at REAL NOT NULL,
    revoked_at REAL,
    revocation_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_cert_domain ON certificates(domain, status);
CREATE TABLE IF NOT EXISTS audit_events (
    event_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


def _row_to_account(row: sqlite3.Row) -> Account:
    return Account(
        account_id=row["account_id"],
        name=row["name"],
        role=Role(row["role"]),
        status=AccountStatus(row["status"]),
        created_at=row["created_at"],
    )


def _row_to_authz(row: sqlite3.Row) -> Authorization:
    return Authorization(
        authz_id=row["authz_id"],
        account_id=row["account_id"],
        domain=row["domain"],
        status=AuthorizationStatus(row["status"]),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
    )


def _row_to_challenge(row: sqlite3.Row) -> Challenge:
    return Challenge(
        challenge_id=row["challenge_id"],
        authz_id=row["authz_id"],
        domain=row["domain"],
        token=row["token"],
        expected_response=row["expected_response"],
        status=ChallengeStatus(row["status"]),
        created_at=row["created_at"],
        expires_at=row["expires_at"],
    )


def _row_to_cert(row: sqlite3.Row) -> CertificateRecord:
    return CertificateRecord(
        cert_id=row["cert_id"],
        account_id=row["account_id"],
        domain=row["domain"],
        serial=row["serial"],
        pem=row["pem"],
        private_key_pem=row["private_key_pem"],
        status=CertificateStatus(row["status"]),
        not_before=row["not_before"],
        not_after=row["not_after"],
        issued_at=row["issued_at"],
        revoked_at=row["revoked_at"],
        revocation_reason=row["revocation_reason"],
    )


def _row_to_audit(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        event_id=row["event_id"],
        account_id=row["account_id"],
        action=row["action"],
        target=row["target"],
        detail=row["detail"],
        created_at=row["created_at"],
    )


class Storage:
    """Durable store for accounts, authorizations, challenges and certificates."""

    def __init__(self, db_path: str) -> None:
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        with self._lock, self._conn:
            self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ kv
    def get_kv(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM kv WHERE key = ?", (key,)
            ).fetchone()
            return row["value"] if row else None

    def set_kv(self, key: str, value: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO kv(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )

    # ------------------------------------------------------------- account
    def insert_account_if_absent(self, account: Account) -> tuple[Account, bool]:
        """Insert the account, or return the existing one with the same name.

        Returns (account, created). The UNIQUE(name) constraint makes this
        safe under concurrency: duplicates can never be created.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO accounts"
                "(account_id, name, role, status, created_at)"
                " VALUES(?, ?, ?, ?, ?)",
                (
                    account.account_id,
                    account.name,
                    account.role.value,
                    account.status.value,
                    account.created_at,
                ),
            )
            created = cur.rowcount == 1
            row = self._conn.execute(
                "SELECT * FROM accounts WHERE name = ?", (account.name,)
            ).fetchone()
            return _row_to_account(row), created

    def get_account(self, account_id: str) -> Account | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM accounts WHERE account_id = ?", (account_id,)
            ).fetchone()
            return _row_to_account(row) if row else None

    def get_account_by_name(self, name: str) -> Account | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM accounts WHERE name = ?", (name,)
            ).fetchone()
            return _row_to_account(row) if row else None

    # -------------------------------------------------------- authorization
    def insert_authorization(self, authz: Authorization) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO authorizations"
                "(authz_id, account_id, domain, status, created_at, expires_at)"
                " VALUES(?, ?, ?, ?, ?, ?)",
                (
                    authz.authz_id,
                    authz.account_id,
                    authz.domain,
                    authz.status.value,
                    authz.created_at,
                    authz.expires_at,
                ),
            )

    def get_authorization(self, authz_id: str) -> Authorization | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM authorizations WHERE authz_id = ?", (authz_id,)
            ).fetchone()
            return _row_to_authz(row) if row else None

    def find_authorization(
        self, account_id: str, domain: str, statuses: tuple[AuthorizationStatus, ...]
    ) -> Authorization | None:
        with self._lock:
            marks = ",".join("?" for _ in statuses)
            row = self._conn.execute(
                f"SELECT * FROM authorizations WHERE account_id = ? AND domain = ?"
                f" AND status IN ({marks}) ORDER BY created_at DESC LIMIT 1",
                (account_id, domain, *[s.value for s in statuses]),
            ).fetchone()
            return _row_to_authz(row) if row else None

    def transition_authorization(
        self,
        authz_id: str,
        from_statuses: tuple[AuthorizationStatus, ...],
        to_status: AuthorizationStatus,
        expires_at: float | None = None,
    ) -> bool:
        """Atomically move an authorization between states. Returns success."""
        with self._lock, self._conn:
            marks = ",".join("?" for _ in from_statuses)
            cur = self._conn.execute(
                f"UPDATE authorizations SET status = ?,"
                f" expires_at = COALESCE(?, expires_at)"
                f" WHERE authz_id = ? AND status IN ({marks})",
                (
                    to_status.value,
                    expires_at,
                    authz_id,
                    *[s.value for s in from_statuses],
                ),
            )
            return cur.rowcount == 1

    # ------------------------------------------------------------ challenge
    def insert_challenge_if_no_active(self, challenge: Challenge) -> tuple[Challenge, bool]:
        """Insert a challenge only if the domain has no active (pending) one.

        Returns (challenge, created). When a pending challenge already
        exists for the domain, that one is returned and created is False.
        """
        with self._lock, self._conn:
            row = self._conn.execute(
                "SELECT * FROM challenges WHERE domain = ? AND status = ?",
                (challenge.domain, ChallengeStatus.PENDING.value),
            ).fetchone()
            if row is not None:
                return _row_to_challenge(row), False
            self._conn.execute(
                "INSERT INTO challenges"
                "(challenge_id, authz_id, domain, token, expected_response,"
                " status, created_at, expires_at)"
                " VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    challenge.challenge_id,
                    challenge.authz_id,
                    challenge.domain,
                    challenge.token,
                    challenge.expected_response,
                    challenge.status.value,
                    challenge.created_at,
                    challenge.expires_at,
                ),
            )
            return challenge, True

    def get_challenge(self, challenge_id: str) -> Challenge | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM challenges WHERE challenge_id = ?", (challenge_id,)
            ).fetchone()
            return _row_to_challenge(row) if row else None

    def transition_challenge(
        self,
        challenge_id: str,
        from_statuses: tuple[ChallengeStatus, ...],
        to_status: ChallengeStatus,
    ) -> bool:
        with self._lock, self._conn:
            marks = ",".join("?" for _ in from_statuses)
            cur = self._conn.execute(
                f"UPDATE challenges SET status = ?"
                f" WHERE challenge_id = ? AND status IN ({marks})",
                (to_status.value, challenge_id, *[s.value for s in from_statuses]),
            )
            return cur.rowcount == 1

    def expire_challenges(self, now: float) -> int:
        """Mark every overdue pending challenge as expired. Returns count."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE challenges SET status = ? WHERE status = ? AND expires_at <= ?",
                (
                    ChallengeStatus.EXPIRED.value,
                    ChallengeStatus.PENDING.value,
                    now,
                ),
            )
            return cur.rowcount

    def expire_authorizations(self, now: float) -> int:
        """Mark every overdue pending/valid authorization as expired."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE authorizations SET status = ?"
                " WHERE status IN (?, ?) AND expires_at <= ?",
                (
                    AuthorizationStatus.EXPIRED.value,
                    AuthorizationStatus.PENDING.value,
                    AuthorizationStatus.VALID.value,
                    now,
                ),
            )
            return cur.rowcount

    # ----------------------------------------------------------- certificate
    def insert_certificate(self, cert: CertificateRecord) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO certificates"
                "(cert_id, account_id, domain, serial, pem, private_key_pem,"
                " status, not_before, not_after, issued_at, revoked_at,"
                " revocation_reason)"
                " VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    cert.cert_id,
                    cert.account_id,
                    cert.domain,
                    cert.serial,
                    cert.pem,
                    cert.private_key_pem,
                    cert.status.value,
                    cert.not_before,
                    cert.not_after,
                    cert.issued_at,
                    cert.revoked_at,
                    cert.revocation_reason,
                ),
            )

    def get_certificate(self, cert_id: str) -> CertificateRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM certificates WHERE cert_id = ?", (cert_id,)
            ).fetchone()
            return _row_to_cert(row) if row else None

    def get_certificate_by_serial(self, serial: str) -> CertificateRecord | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM certificates WHERE serial = ?", (serial,)
            ).fetchone()
            return _row_to_cert(row) if row else None

    def list_certificates(
        self, domain: str | None = None, account_id: str | None = None
    ) -> list[CertificateRecord]:
        sql = "SELECT * FROM certificates WHERE 1=1"
        params: list[str] = []
        if domain is not None:
            sql += " AND domain = ?"
            params.append(domain)
        if account_id is not None:
            sql += " AND account_id = ?"
            params.append(account_id)
        sql += " ORDER BY issued_at ASC"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [_row_to_cert(r) for r in rows]

    def transition_certificate(
        self,
        cert_id: str,
        from_statuses: tuple[CertificateStatus, ...],
        to_status: CertificateStatus,
        revoked_at: float | None = None,
        revocation_reason: str | None = None,
    ) -> bool:
        with self._lock, self._conn:
            marks = ",".join("?" for _ in from_statuses)
            cur = self._conn.execute(
                f"UPDATE certificates SET status = ?, revoked_at = ?,"
                f" revocation_reason = ?"
                f" WHERE cert_id = ? AND status IN ({marks})",
                (
                    to_status.value,
                    revoked_at,
                    revocation_reason,
                    cert_id,
                    *[s.value for s in from_statuses],
                ),
            )
            return cur.rowcount == 1

    # ---------------------------------------------------------------- audit
    def append_audit(self, event: AuditEvent) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO audit_events"
                "(event_id, account_id, action, target, detail, created_at)"
                " VALUES(?, ?, ?, ?, ?, ?)",
                (
                    event.event_id,
                    event.account_id,
                    event.action,
                    event.target,
                    event.detail,
                    event.created_at,
                ),
            )

    def list_audit_events(
        self, account_id: str | None = None, action: str | None = None
    ) -> list[AuditEvent]:
        sql = "SELECT * FROM audit_events WHERE 1=1"
        params: list[str] = []
        if account_id is not None:
            sql += " AND account_id = ?"
            params.append(account_id)
        if action is not None:
            sql += " AND action = ?"
            params.append(action)
        sql += " ORDER BY created_at ASC, event_id ASC"
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [_row_to_audit(r) for r in rows]
