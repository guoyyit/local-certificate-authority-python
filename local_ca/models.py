"""Core domain models and state enumerations for the local CA."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field


class AccountStatus(str, enum.Enum):
    """Lifecycle of an account."""

    ACTIVE = "active"
    DEACTIVATED = "deactivated"


class AuthorizationStatus(str, enum.Enum):
    """Lifecycle of an authorization request for a domain."""

    PENDING = "pending"
    VALID = "valid"
    EXPIRED = "expired"
    INVALID = "invalid"


class ChallengeStatus(str, enum.Enum):
    """Lifecycle of a domain-ownership challenge."""

    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"


class CertificateStatus(str, enum.Enum):
    """Lifecycle of an issued certificate."""

    VALID = "valid"
    REVOKED = "revoked"


class Role(str, enum.Enum):
    """Operation roles used for permission checks."""

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


@dataclass(frozen=True)
class Account:
    account_id: str
    name: str
    role: Role
    status: AccountStatus
    created_at: float


@dataclass(frozen=True)
class Authorization:
    authz_id: str
    account_id: str
    domain: str
    status: AuthorizationStatus
    created_at: float
    expires_at: float


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    authz_id: str
    domain: str
    token: str
    expected_response: str
    status: ChallengeStatus
    created_at: float
    expires_at: float


@dataclass(frozen=True)
class CertificateRecord:
    cert_id: str
    account_id: str
    domain: str
    serial: str
    pem: str
    private_key_pem: str
    status: CertificateStatus
    not_before: float
    not_after: float
    issued_at: float
    revoked_at: float | None = None
    revocation_reason: str | None = None


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    account_id: str
    action: str
    target: str
    detail: str
    created_at: float
