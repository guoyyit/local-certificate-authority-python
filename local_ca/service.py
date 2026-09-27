"""Business logic: account/authorization/challenge/certificate lifecycle.

State machine summary
---------------------
Account:       (created) -> ACTIVE -> DEACTIVATED
Authorization: PENDING -> VALID | EXPIRED | INVALID
Challenge:     PENDING -> VALID | INVALID | EXPIRED
Certificate:   VALID -> REVOKED

Every transition is a conditional UPDATE in SQLite, so concurrent or
repeated requests can never overwrite each other or create duplicates.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
import uuid
from collections.abc import Callable

from .crypto import CAKeyStore
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
from .storage import Storage

#: How long an authorization stays usable.
AUTHZ_TTL_SECONDS = 24 * 3600.0
#: How long a challenge stays answerable.
CHALLENGE_TTL_SECONDS = 600.0
#: How long an issued certificate stays valid.
CERT_TTL_SECONDS = 90 * 24 * 3600.0


class CAError(Exception):
    """Base class for service errors."""


class NotFoundError(CAError):
    """Referenced object does not exist."""


class PermissionDeniedError(CAError):
    """The account is not allowed to perform this operation."""


class ConflictError(CAError):
    """The request conflicts with current state."""


class InvalidStateError(CAError):
    """The object is in a state that forbids the requested transition."""


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def expected_challenge_response(token: str, account_id: str) -> str:
    """Deterministic key authorization: sha256(token.account_id)."""
    return hashlib.sha256(f"{token}.{account_id}".encode("utf-8")).hexdigest()


class CertificateAuthorityService:
    """Coordinates state transitions, permissions and auditing."""

    def __init__(
        self,
        storage: Storage,
        ca_keys: CAKeyStore,
        now: Callable[[], float] = time.time,
        authz_ttl: float = AUTHZ_TTL_SECONDS,
        challenge_ttl: float = CHALLENGE_TTL_SECONDS,
        cert_ttl: float = CERT_TTL_SECONDS,
    ) -> None:
        self._storage = storage
        self._ca = ca_keys
        self._now = now
        self._authz_ttl = authz_ttl
        self._challenge_ttl = challenge_ttl
        self._cert_ttl = cert_ttl
        self._guard = threading.Lock()
        self._domain_locks: dict[str, threading.Lock] = {}
        self.recover()

    # ------------------------------------------------------------- recovery
    def recover(self) -> None:
        """Restore a retryable state after a crash.

        Confirmed results (issued certificates, revocations, audit events)
        are already durable in SQLite. Incomplete work is swept here:
        overdue pending challenges/authorizations become EXPIRED so clients
        can simply re-request them, and all CA generations are reloaded so
        previously issued certificates remain verifiable.
        """
        self._ca.ensure_previous_loaded()
        now = self._now()
        self._storage.expire_challenges(now)
        self._storage.expire_authorizations(now)

    # -------------------------------------------------------------- auditing
    def _audit(self, account_id: str, action: str, target: str, detail: str) -> None:
        self._storage.append_audit(
            AuditEvent(
                event_id=_new_id("evt"),
                account_id=account_id,
                action=action,
                target=target,
                detail=detail,
                created_at=self._now(),
            )
        )

    def list_audit_events(
        self, account_id: str | None = None, action: str | None = None
    ) -> list[AuditEvent]:
        return self._storage.list_audit_events(account_id=account_id, action=action)

    # -------------------------------------------------------------- accounts
    def register_account(self, name: str, role: Role = Role.OPERATOR) -> Account:
        """Create an account, or return the existing one with this name.

        Idempotent and concurrency-safe: the UNIQUE(name) constraint plus
        INSERT OR IGNORE guarantees no duplicate accounts ever appear.
        """
        if not name:
            raise CAError("account name must not be empty")
        account, created = self._storage.insert_account_if_absent(
            Account(
                account_id=_new_id("acct"),
                name=name,
                role=role,
                status=AccountStatus.ACTIVE,
                created_at=self._now(),
            )
        )
        if created:
            self._audit(account.account_id, "account.register", account.account_id, name)
        return account

    def get_account(self, account_id: str) -> Account:
        account = self._storage.get_account(account_id)
        if account is None:
            raise NotFoundError(f"account {account_id} not found")
        return account

    def _require_active_account(self, account_id: str) -> Account:
        account = self.get_account(account_id)
        if account.status is not AccountStatus.ACTIVE:
            raise PermissionDeniedError(f"account {account_id} is not active")
        return account

    @staticmethod
    def _require_role(account: Account, allowed: set[Role], action: str) -> None:
        if account.role not in allowed:
            raise PermissionDeniedError(
                f"account {account.account_id} with role {account.role.value} "
                f"may not perform {action}"
            )

    # --------------------------------------------------------- authorizations
    def request_authorization(self, account_id: str, domain: str) -> Authorization:
        """Create (or reuse) an authorization request for a domain."""
        account = self._require_active_account(account_id)
        self._require_role(account, {Role.ADMIN, Role.OPERATOR}, "request authorization")
        domain = self._normalize_domain(domain)
        now = self._now()
        existing = self._storage.find_authorization(
            account_id,
            domain,
            (AuthorizationStatus.PENDING, AuthorizationStatus.VALID),
        )
        if existing is not None and existing.expires_at > now:
            return existing
        authz = Authorization(
            authz_id=_new_id("authz"),
            account_id=account_id,
            domain=domain,
            status=AuthorizationStatus.PENDING,
            created_at=now,
            expires_at=now + self._authz_ttl,
        )
        self._storage.insert_authorization(authz)
        self._audit(account_id, "authorization.request", authz.authz_id, domain)
        return authz

    def get_authorization(self, authz_id: str) -> Authorization:
        authz = self._storage.get_authorization(authz_id)
        if authz is None:
            raise NotFoundError(f"authorization {authz_id} not found")
        return authz

    # ------------------------------------------------------------ challenges
    def create_challenge(self, account_id: str, authz_id: str) -> Challenge:
        """Create a domain-ownership challenge for a pending authorization.

        At most one PENDING challenge exists per domain at any moment; a
        concurrent or repeated request returns the existing one. After a
        challenge fails or expires, a new one can be created.
        """
        account = self._require_active_account(account_id)
        self._require_role(account, {Role.ADMIN, Role.OPERATOR}, "create challenge")
        authz = self.get_authorization(authz_id)
        if authz.account_id != account_id:
            raise PermissionDeniedError("authorization belongs to another account")
        now = self._now()
        self._expire_challenge_if_overdue(authz.domain, now)
        if authz.status is AuthorizationStatus.EXPIRED or authz.expires_at <= now:
            raise InvalidStateError("authorization expired; request a new one")
        if authz.status is not AuthorizationStatus.PENDING:
            raise InvalidStateError(
                f"authorization is {authz.status.value}; cannot create challenge"
            )
        token = secrets.token_urlsafe(32)
        challenge, created = self._storage.insert_challenge_if_no_active(
            Challenge(
                challenge_id=_new_id("chal"),
                authz_id=authz_id,
                domain=authz.domain,
                token=token,
                expected_response=expected_challenge_response(token, account_id),
                status=ChallengeStatus.PENDING,
                created_at=now,
                expires_at=now + self._challenge_ttl,
            )
        )
        if created:
            self._audit(account_id, "challenge.create", challenge.challenge_id, authz.domain)
        return challenge

    def respond_challenge(
        self, account_id: str, challenge_id: str, response: str
    ) -> Challenge:
        """Validate a challenge response.

        On success the challenge and its authorization become VALID. On
        failure the challenge becomes INVALID and a fresh one may be
        created. Overdue challenges become EXPIRED instead.
        """
        account = self._require_active_account(account_id)
        self._require_role(account, {Role.ADMIN, Role.OPERATOR}, "respond challenge")
        challenge = self._storage.get_challenge(challenge_id)
        if challenge is None:
            raise NotFoundError(f"challenge {challenge_id} not found")
        authz = self.get_authorization(challenge.authz_id)
        if authz.account_id != account_id:
            raise PermissionDeniedError("challenge belongs to another account")
        now = self._now()
        if challenge.status is ChallengeStatus.PENDING and challenge.expires_at <= now:
            self._storage.transition_challenge(
                challenge_id, (ChallengeStatus.PENDING,), ChallengeStatus.EXPIRED
            )
            self._audit(account_id, "challenge.expire", challenge_id, challenge.domain)
            raise InvalidStateError("challenge expired; create a new one")
        if challenge.status is not ChallengeStatus.PENDING:
            raise InvalidStateError(
                f"challenge is {challenge.status.value}; cannot respond"
            )
        if secrets.compare_digest(response, challenge.expected_response):
            won = self._storage.transition_challenge(
                challenge_id, (ChallengeStatus.PENDING,), ChallengeStatus.VALID
            )
            if not won:
                raise ConflictError("challenge state changed concurrently; retry")
            self._storage.transition_authorization(
                authz.authz_id,
                (AuthorizationStatus.PENDING,),
                AuthorizationStatus.VALID,
                expires_at=now + self._authz_ttl,
            )
            self._audit(account_id, "challenge.validate", challenge_id, challenge.domain)
        else:
            won = self._storage.transition_challenge(
                challenge_id, (ChallengeStatus.PENDING,), ChallengeStatus.INVALID
            )
            if not won:
                raise ConflictError("challenge state changed concurrently; retry")
            self._audit(account_id, "challenge.invalidate", challenge_id, challenge.domain)
            raise InvalidStateError("wrong challenge response")
        return self._storage.get_challenge(challenge_id)  # type: ignore[return-value]

    def get_challenge(self, challenge_id: str) -> Challenge:
        challenge = self._storage.get_challenge(challenge_id)
        if challenge is None:
            raise NotFoundError(f"challenge {challenge_id} not found")
        return challenge

    def _expire_challenge_if_overdue(self, domain: str, now: float) -> None:
        self._storage.expire_challenges(now)

    # ---------------------------------------------------------- certificates
    def issue_certificate(self, account_id: str, domain: str) -> CertificateRecord:
        """Issue a certificate once every required check has passed.

        Concurrent issuance for the same domain is serialized on a
        per-domain lock; the second caller observes the certificate the
        first caller just issued (backed by the same still-valid
        authorization) and returns it, so the outcome is deterministic
        and no duplicate certificates appear.
        """
        account = self._require_active_account(account_id)
        self._require_role(account, {Role.ADMIN, Role.OPERATOR}, "issue certificate")
        domain = self._normalize_domain(domain)
        with self._domain_lock(domain):
            authz = self._require_valid_authorization(account_id, domain)
            existing = self._find_reusable_certificate(account_id, domain, authz)
            if existing is not None:
                return existing
            now = self._now()
            issued = self._ca.issue_certificate(domain, now, now + self._cert_ttl)
            cert = CertificateRecord(
                cert_id=_new_id("cert"),
                account_id=account_id,
                domain=domain,
                serial=issued.serial,
                pem=issued.cert_pem,
                private_key_pem=issued.private_key_pem,
                status=CertificateStatus.VALID,
                not_before=issued.not_before,
                not_after=issued.not_after,
                issued_at=now,
            )
            self._storage.insert_certificate(cert)
            self._audit(account_id, "certificate.issue", cert.cert_id, domain)
            return cert

    def rotate_certificate(self, account_id: str, domain: str) -> CertificateRecord:
        """Issue a replacement certificate for a domain.

        The old certificate keeps its own validity window and remains
        verifiable until it expires or is revoked; the new certificate's
        later ``not_before`` makes the generations distinguishable.
        """
        account = self._require_active_account(account_id)
        self._require_role(account, {Role.ADMIN, Role.OPERATOR}, "rotate certificate")
        domain = self._normalize_domain(domain)
        with self._domain_lock(domain):
            self._require_valid_authorization(account_id, domain)
            now = self._now()
            issued = self._ca.issue_certificate(domain, now, now + self._cert_ttl)
            cert = CertificateRecord(
                cert_id=_new_id("cert"),
                account_id=account_id,
                domain=domain,
                serial=issued.serial,
                pem=issued.cert_pem,
                private_key_pem=issued.private_key_pem,
                status=CertificateStatus.VALID,
                not_before=issued.not_before,
                not_after=issued.not_after,
                issued_at=now,
            )
            self._storage.insert_certificate(cert)
            self._audit(account_id, "certificate.rotate", cert.cert_id, domain)
            return cert

    def _require_valid_authorization(self, account_id: str, domain: str) -> Authorization:
        now = self._now()
        authz = self._storage.find_authorization(
            account_id, domain, (AuthorizationStatus.VALID,)
        )
        if authz is None or authz.expires_at <= now:
            raise InvalidStateError(
                "no valid authorization; complete a challenge first"
            )
        return authz

    def _find_reusable_certificate(
        self, account_id: str, domain: str, authz: Authorization
    ) -> CertificateRecord | None:
        now = self._now()
        for cert in self._storage.list_certificates(domain=domain, account_id=account_id):
            if (
                cert.status is CertificateStatus.VALID
                and cert.issued_at >= authz.created_at
                and cert.not_after > now
            ):
                return cert
        return None

    def get_certificate(self, cert_id: str) -> CertificateRecord:
        cert = self._storage.get_certificate(cert_id)
        if cert is None:
            raise NotFoundError(f"certificate {cert_id} not found")
        return cert

    def list_certificates(
        self, domain: str | None = None, account_id: str | None = None
    ) -> list[CertificateRecord]:
        return self._storage.list_certificates(domain=domain, account_id=account_id)

    def verify_certificate(self, cert_id: str) -> bool:
        """A certificate verifies iff it is unrevoked, in its validity
        window, and signed by a known CA generation."""
        cert = self.get_certificate(cert_id)
        if cert.status is CertificateStatus.REVOKED:
            return False
        return self._ca.verify_certificate(cert.pem, self._now())

    # ------------------------------------------------------------- revocation
    def revoke_certificate(
        self, account_id: str, cert_id: str, reason: str = "unspecified"
    ) -> CertificateRecord:
        """Revoke a certificate. Idempotent: revoking twice is a no-op
        that returns the already-revoked record."""
        account = self._require_active_account(account_id)
        self._require_role(account, {Role.ADMIN, Role.OPERATOR}, "revoke certificate")
        cert = self.get_certificate(cert_id)
        if account.role is not Role.ADMIN and cert.account_id != account_id:
            raise PermissionDeniedError("only an admin may revoke others' certificates")
        if cert.status is CertificateStatus.REVOKED:
            return cert
        won = self._storage.transition_certificate(
            cert_id,
            (CertificateStatus.VALID,),
            CertificateStatus.REVOKED,
            revoked_at=self._now(),
            revocation_reason=reason,
        )
        if not won:
            # Lost a race with a concurrent revocation: it is idempotent.
            return self.get_certificate(cert_id)
        self._audit(account_id, "certificate.revoke", cert_id, reason)
        return self.get_certificate(cert_id)

    # ---------------------------------------------------------------- helpers
    def _domain_lock(self, domain: str) -> threading.Lock:
        with self._guard:
            lock = self._domain_locks.get(domain)
            if lock is None:
                lock = threading.Lock()
                self._domain_locks[domain] = lock
            return lock

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        normalized = domain.strip().lower().rstrip(".")
        if not normalized or any(ch.isspace() for ch in normalized):
            raise CAError("invalid domain name")
        return normalized
