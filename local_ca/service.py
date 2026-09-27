"""Business logic: accounts, authorizations, challenges, issuance, revocation.

Concurrency & crash-safety notes
--------------------------------
* Every mutating public method sweeps expired challenges/authorizations first,
  so timeouts take effect without a background thread.
* Multi-step writes run inside ``Storage.transaction()`` (BEGIN IMMEDIATE),
  which serializes writers and guarantees all-or-nothing commits: a crash
  mid-operation cannot leave half a certificate or half a record behind.
* Issuance is idempotent per (account, domain): a repeated or concurrent
  request returns the already-issued active certificate instead of creating
  a duplicate. ``rotate_certificate`` is the explicit way to obtain a new one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from local_ca import crypto, models
from local_ca.errors import (
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from local_ca.storage import Storage

_DEFAULT_CHALLENGE_TTL = timedelta(minutes=10)
_DEFAULT_AUTHORIZATION_TTL = timedelta(days=30)
_DEFAULT_CERTIFICATE_TTL = timedelta(days=90)
_CA_CERT_TTL = timedelta(days=3650)
_NOT_BEFORE_SKEW = timedelta(seconds=60)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex}"


class CertificateAuthorityService:
    """Coordinates the full issuance lifecycle on top of Storage."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        admin_token: str,
        now: Callable[[], datetime] | None = None,
        challenge_ttl: timedelta | None = None,
        authorization_ttl: timedelta | None = None,
        certificate_ttl: timedelta | None = None,
    ) -> None:
        if not admin_token:
            raise ValueError("admin_token must not be empty")
        self._storage = Storage(db_path)
        self._admin_token = admin_token
        self._now = now or _utcnow
        self._challenge_ttl = challenge_ttl or _DEFAULT_CHALLENGE_TTL
        self._authorization_ttl = authorization_ttl or _DEFAULT_AUTHORIZATION_TTL
        self._certificate_ttl = certificate_ttl or _DEFAULT_CERTIFICATE_TTL
        self._ca = self._load_or_create_ca_identity()

    def close(self) -> None:
        self._storage.close()

    def __enter__(self) -> "CertificateAuthorityService":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # internal helpers
    # ------------------------------------------------------------------ #
    def _load_or_create_ca_identity(self) -> crypto.CAIdentity:
        raw = self._storage.get_meta("ca_identity")
        if raw is None:
            now = self._now()
            identity = crypto.CAIdentity.generate(
                "local-ca-root", now - _NOT_BEFORE_SKEW, now + _CA_CERT_TTL
            )
            payload = json.dumps({"key_pem": identity.key_pem, "cert_pem": identity.cert_pem})
            raw = self._storage.set_meta_if_absent("ca_identity", payload)
        data = json.loads(raw)
        return crypto.CAIdentity(key_pem=data["key_pem"], cert_pem=data["cert_pem"])

    @property
    def ca_certificate_pem(self) -> str:
        return self._ca.cert_pem

    def _sweep_expired(self) -> None:
        now_iso = self._now().isoformat()
        self._storage.expire_challenges(now_iso)
        self._storage.expire_authorizations(now_iso)

    def _authenticate(self, token: str) -> models.Account:
        account = self._storage.get_account_by_token(token)
        if account is None:
            raise PermissionDeniedError("unknown account token")
        if account.status is not models.AccountStatus.ACTIVE:
            raise PermissionDeniedError(f"account {account.account_id} is not active")
        return account

    def _is_admin(self, token: str) -> bool:
        return hmac.compare_digest(token, self._admin_token)

    def is_admin(self, token: str) -> bool:
        """Public check used by the HTTP layer for admin-only endpoints."""
        return self._is_admin(token)

    def _audit(self, actor: str, action: str, target: str, detail: dict) -> None:
        self._storage.append_audit(
            actor, action, target, json.dumps(detail, sort_keys=True), self._now().isoformat()
        )

    # ------------------------------------------------------------------ #
    # accounts
    # ------------------------------------------------------------------ #
    def register_account(self, contact: str, token: str) -> models.Account:
        """Register an account; repeated registration returns the existing one."""
        contact = contact.strip().lower()
        if not contact:
            raise ValidationError("contact must not be empty")
        if not token:
            raise ValidationError("token must not be empty")
        self._sweep_expired()
        account = models.Account(
            account_id=_new_id("acct"),
            contact=contact,
            token=token,
            role=models.Role.ACCOUNT,
            status=models.AccountStatus.ACTIVE,
            created_at=self._now(),
        )
        with self._storage.transaction():
            stored = self._storage.create_account_if_absent(account)
            self._audit(
                stored.account_id,
                "account.register",
                f"account:{stored.account_id}",
                {"contact": contact},
            )
        return stored

    # ------------------------------------------------------------------ #
    # authorizations
    # ------------------------------------------------------------------ #
    def create_authorization(self, token: str, domain: str) -> models.Authorization:
        """Create (or reuse) an authorization request for ``domain``."""
        account = self._authenticate(token)
        domain = self._normalize_domain(domain)
        self._sweep_expired()
        now = self._now()
        with self._storage.transaction():
            existing = self._storage.get_authorization_by_account_domain(
                account.account_id, domain
            )
            if existing is not None:
                if existing.status is models.AuthorizationStatus.EXPIRED:
                    self._storage.refresh_authorization(
                        existing.authorization_id,
                        models.AuthorizationStatus.PENDING,
                        (now + self._authorization_ttl).isoformat(),
                    )
                    self._audit(
                        account.account_id,
                        "authorization.renew",
                        f"authorization:{existing.authorization_id}",
                        {"domain": domain},
                    )
                    return self._storage.get_authorization(existing.authorization_id)
                return existing
            authorization = models.Authorization(
                authorization_id=_new_id("authz"),
                account_id=account.account_id,
                domain=domain,
                status=models.AuthorizationStatus.PENDING,
                created_at=now,
                expires_at=now + self._authorization_ttl,
            )
            stored, _ = self._storage.create_authorization_if_absent(authorization)
            self._audit(
                account.account_id,
                "authorization.create",
                f"authorization:{stored.authorization_id}",
                {"domain": domain},
            )
            return stored

    # ------------------------------------------------------------------ #
    # challenges
    # ------------------------------------------------------------------ #
    def create_challenge(self, token: str, authorization_id: str) -> models.Challenge:
        """Create a dns-txt style challenge; one active challenge per domain."""
        account = self._authenticate(token)
        self._sweep_expired()
        authorization = self._storage.get_authorization(authorization_id)
        if authorization is None:
            raise NotFoundError(f"authorization {authorization_id} not found")
        self._require_owner(account, authorization)
        if authorization.status is models.AuthorizationStatus.VALID:
            raise ConflictError("authorization is already valid")
        if authorization.status is not models.AuthorizationStatus.PENDING:
            raise ValidationError(
                f"authorization is {authorization.status.value}; request a new one"
            )
        now = self._now()
        challenge = models.Challenge(
            challenge_id=_new_id("chal"),
            authorization_id=authorization.authorization_id,
            domain=authorization.domain,
            type=models.ChallengeType.DNS_TXT,
            token=secrets.token_urlsafe(24),
            expected_value=self._expected_challenge_value(account, authorization),
            status=models.ChallengeStatus.PENDING,
            created_at=now,
            expires_at=now + self._challenge_ttl,
        )
        with self._storage.transaction():
            stored, created = self._storage.create_challenge_if_no_active(challenge)
            if not created and stored.authorization_id != authorization.authorization_id:
                raise ConflictError(
                    f"domain {authorization.domain} already has an active challenge"
                )
            if created:
                self._audit(
                    account.account_id,
                    "challenge.create",
                    f"challenge:{stored.challenge_id}",
                    {"domain": stored.domain, "type": stored.type.value},
                )
            return stored

    def respond_challenge(self, token: str, challenge_id: str, value: str) -> models.Challenge:
        """Submit the published TXT value; on success the authorization becomes valid."""
        account = self._authenticate(token)
        self._sweep_expired()
        challenge = self._storage.get_challenge(challenge_id)
        if challenge is None:
            raise NotFoundError(f"challenge {challenge_id} not found")
        authorization = self._storage.get_authorization(challenge.authorization_id)
        assert authorization is not None
        self._require_owner(account, authorization)
        if challenge.status is models.ChallengeStatus.VALID:
            return challenge
        if challenge.status is models.ChallengeStatus.EXPIRED:
            raise ValidationError("challenge has expired; create a new one")
        if challenge.status is models.ChallengeStatus.INVALID:
            raise ValidationError("challenge already failed; create a new one")
        matched = hmac.compare_digest(value, challenge.expected_value)
        with self._storage.transaction():
            if matched:
                self._storage.set_challenge_status(
                    challenge.challenge_id, models.ChallengeStatus.VALID
                )
                self._storage.set_authorization_status(
                    authorization.authorization_id, models.AuthorizationStatus.VALID
                )
                self._audit(
                    account.account_id,
                    "challenge.valid",
                    f"challenge:{challenge.challenge_id}",
                    {"domain": challenge.domain},
                )
            else:
                # Persist the failure so the challenge leaves the active slot
                # and a fresh one can be created; raise only after commit.
                self._storage.set_challenge_status(
                    challenge.challenge_id, models.ChallengeStatus.INVALID
                )
                self._audit(
                    account.account_id,
                    "challenge.invalid",
                    f"challenge:{challenge.challenge_id}",
                    {"domain": challenge.domain},
                )
        if not matched:
            raise ValidationError("challenge verification failed")
        return self._storage.get_challenge(challenge_id)

    # ------------------------------------------------------------------ #
    # issuance
    # ------------------------------------------------------------------ #
    def issue_certificate(self, token: str, domain: str) -> models.CertificateRecord:
        """Issue a certificate once all challenges for ``domain`` are valid.

        Idempotent per (account, domain): a repeat or concurrent call returns
        the already-issued active certificate.
        """
        account = self._authenticate(token)
        domain = self._normalize_domain(domain)
        self._sweep_expired()
        with self._storage.transaction():
            existing = self._storage.get_active_certificate_for_account_domain(
                account.account_id, domain
            )
            if existing is not None:
                return existing
            authorization = self._require_valid_authorization(account, domain)
            record = self._build_certificate(account, domain)
            self._storage.insert_certificate(record)
            self._audit(
                account.account_id,
                "certificate.issue",
                f"certificate:{record.serial}",
                {"domain": domain, "authorization": authorization.authorization_id},
            )
            return record

    def rotate_certificate(self, token: str, domain: str) -> models.CertificateRecord:
        """Issue a fresh certificate for ``domain`` even if one is active.

        The previous certificate keeps its own validity window, so existing
        verifications of the old certificate are not immediately invalidated;
        old and new are distinguishable by serial and not_before.
        """
        account = self._authenticate(token)
        domain = self._normalize_domain(domain)
        self._sweep_expired()
        with self._storage.transaction():
            authorization = self._require_valid_authorization(account, domain)
            record = self._build_certificate(account, domain)
            self._storage.insert_certificate(record)
            self._audit(
                account.account_id,
                "certificate.rotate",
                f"certificate:{record.serial}",
                {"domain": domain, "authorization": authorization.authorization_id},
            )
            return record

    def get_certificate(self, serial: str) -> models.CertificateRecord:
        record = self._storage.get_certificate(serial)
        if record is None:
            raise NotFoundError(f"certificate {serial} not found")
        return record

    def list_certificates(self, domain: str | None = None) -> list[models.CertificateRecord]:
        self._sweep_expired()
        return self._storage.list_certificates(domain)

    # ------------------------------------------------------------------ #
    # revocation
    # ------------------------------------------------------------------ #
    def revoke_certificate(
        self, token: str, serial: str, reason: str = "unspecified"
    ) -> models.CertificateRecord:
        """Revoke a certificate. Repeat calls are idempotent.

        Allowed for the admin token or the account that owns the certificate.
        """
        record = self._storage.get_certificate(serial)
        if record is None:
            raise NotFoundError(f"certificate {serial} not found")
        if self._is_admin(token):
            actor = "admin"
        else:
            account = self._authenticate(token)
            if account.account_id != record.account_id:
                raise PermissionDeniedError(
                    "only the admin or the owning account may revoke a certificate"
                )
            actor = account.account_id
        with self._storage.transaction():
            current = self._storage.get_certificate(serial)
            assert current is not None
            if current.status is models.CertificateStatus.REVOKED:
                self._audit(
                    actor,
                    "certificate.revoke.duplicate",
                    f"certificate:{serial}",
                    {"reason": reason},
                )
                return current
            self._storage.set_certificate_revoked(serial, self._now().isoformat(), reason)
            self._audit(
                actor,
                "certificate.revoke",
                f"certificate:{serial}",
                {"reason": reason, "domain": current.domain},
            )
        return self._storage.get_certificate(serial)

    def revocation_status(self, serial: str) -> models.CertificateStatus:
        record = self._storage.get_certificate(serial)
        if record is None:
            raise NotFoundError(f"certificate {serial} not found")
        if (
            record.status is models.CertificateStatus.ACTIVE
            and record.not_after <= self._now()
        ):
            return models.CertificateStatus.EXPIRED
        return record.status

    # ------------------------------------------------------------------ #
    # audit
    # ------------------------------------------------------------------ #
    def audit_log(self) -> list[models.AuditEvent]:
        return self._storage.list_audit()

    # ------------------------------------------------------------------ #
    # private helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _normalize_domain(domain: str) -> str:
        normalized = domain.strip().lower().rstrip(".")
        if not normalized or any(ch.isspace() for ch in normalized):
            raise ValidationError("invalid domain")
        return normalized

    @staticmethod
    def _require_owner(account: models.Account, authorization: models.Authorization) -> None:
        if authorization.account_id != account.account_id:
            raise PermissionDeniedError("authorization belongs to a different account")

    def _require_valid_authorization(
        self, account: models.Account, domain: str
    ) -> models.Authorization:
        authorization = self._storage.get_authorization_by_account_domain(
            account.account_id, domain
        )
        if authorization is None:
            raise ValidationError(f"no authorization for domain {domain}")
        if authorization.status is not models.AuthorizationStatus.VALID:
            raise ValidationError(
                f"authorization for {domain} is {authorization.status.value}, not valid"
            )
        if authorization.expires_at <= self._now():
            raise ValidationError(f"authorization for {domain} has expired")
        challenges = self._storage.get_challenges_for_authorization(
            authorization.authorization_id
        )
        now = self._now()
        has_valid_challenge = any(
            c.status is models.ChallengeStatus.VALID and c.expires_at > now
            for c in challenges
        )
        if not has_valid_challenge:
            raise ValidationError(
                f"no unexpired valid challenge for domain {domain}"
            )
        return authorization

    def _build_certificate(
        self, account: models.Account, domain: str
    ) -> models.CertificateRecord:
        now = self._now()
        not_before = now - _NOT_BEFORE_SKEW
        not_after = now + self._certificate_ttl
        key_pem = crypto.generate_private_key_pem()
        serial = crypto.random_serial_number()
        cert_pem = crypto.issue_certificate_pem(
            domain=domain,
            subject_private_key_pem=key_pem,
            ca_key_pem=self._ca.key_pem,
            ca_cert_pem=self._ca.cert_pem,
            not_before=not_before,
            not_after=not_after,
            serial_number=serial,
        )
        return models.CertificateRecord(
            serial=str(serial),
            account_id=account.account_id,
            domain=domain,
            pem_certificate=cert_pem,
            pem_private_key=key_pem,
            not_before=not_before,
            not_after=not_after,
            status=models.CertificateStatus.ACTIVE,
            revoked_at=None,
            revocation_reason=None,
            created_at=now,
        )

    @staticmethod
    def _expected_challenge_value(
        account: models.Account, authorization: models.Authorization
    ) -> str:
        digest = hashlib.sha256(
            f"{account.token}:{authorization.authorization_id}:{authorization.domain}".encode()
        ).hexdigest()
        return f"local-ca-verify={digest}"
