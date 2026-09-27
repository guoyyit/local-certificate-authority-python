from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from local_ca.service import CertificateAuthorityService

ADMIN_TOKEN = "test-admin-token"


class FakeClock:
    """Mutable UTC clock so tests control expiry."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 9, 28, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self._now

    def advance(self, delta: timedelta) -> None:
        self._now += delta


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def db_path(tmp_path):
    return tmp_path / "ca.db"


@pytest.fixture()
def service(db_path, clock):
    svc = CertificateAuthorityService(
        db_path,
        admin_token=ADMIN_TOKEN,
        now=clock,
        challenge_ttl=timedelta(minutes=5),
        authorization_ttl=timedelta(hours=1),
        certificate_ttl=timedelta(days=30),
    )
    yield svc
    svc.close()


def register(service, contact="user@example.test", token="user-token"):
    return service.register_account(contact, token)


def validate_domain(service, token, domain):
    """Drive a domain through authorization + challenge to a valid state."""
    authz = service.create_authorization(token, domain)
    challenge = service.create_challenge(token, authz.authorization_id)
    return service.respond_challenge(token, challenge.challenge_id, challenge.expected_value)


def issue(service, token, domain):
    validate_domain(service, token, domain)
    return service.issue_certificate(token, domain)
