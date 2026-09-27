"""Domain models and state enums for the local CA."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime


class AccountStatus(str, enum.Enum):
    PENDING = "pending"
    ACTIVE = "active"
    DISABLED = "disabled"


class AuthorizationStatus(str, enum.Enum):
    PENDING = "pending"
    VALID = "valid"
    EXPIRED = "expired"
    FAILED = "failed"


class ChallengeStatus(str, enum.Enum):
    PENDING = "pending"
    VALID = "valid"
    INVALID = "invalid"
    EXPIRED = "expired"


class ChallengeType(str, enum.Enum):
    DNS_TXT = "dns-txt"


class CertificateStatus(str, enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"


class Role(str, enum.Enum):
    ADMIN = "admin"
    ACCOUNT = "account"


@dataclass(frozen=True)
class Account:
    account_id: str
    contact: str
    token: str
    role: Role
    status: AccountStatus
    created_at: datetime


@dataclass(frozen=True)
class Authorization:
    authorization_id: str
    account_id: str
    domain: str
    status: AuthorizationStatus
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    authorization_id: str
    domain: str
    type: ChallengeType
    token: str
    expected_value: str
    status: ChallengeStatus
    created_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class CertificateRecord:
    serial: str
    account_id: str
    domain: str
    pem_certificate: str
    pem_private_key: str
    not_before: datetime
    not_after: datetime
    status: CertificateStatus
    revoked_at: datetime | None
    revocation_reason: str | None
    created_at: datetime


@dataclass(frozen=True)
class AuditEvent:
    event_id: int
    actor: str
    action: str
    target: str
    detail: str
    created_at: datetime
