"""Duplicate and concurrent account/authorization requests must stay idempotent."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from local_ca import models
from local_ca.errors import PermissionDeniedError, ValidationError
from tests.conftest import ADMIN_TOKEN, register


def test_register_account_is_idempotent_per_contact(service):
    first = register(service, "dup@example.test", "tok-a")
    second = register(service, "dup@example.test", "tok-a")
    assert first.account_id == second.account_id


def test_register_account_normalizes_contact(service):
    first = service.register_account("  Mixed@Example.TEST ", "tok-a")
    second = service.register_account("mixed@example.test", "tok-a")
    assert first.account_id == second.account_id


def test_register_account_rejects_empty_input(service):
    with pytest.raises(ValidationError):
        service.register_account("", "tok")
    with pytest.raises(ValidationError):
        service.register_account("a@b.test", "")


def test_concurrent_registration_creates_single_account(service):
    with ThreadPoolExecutor(max_workers=8) as pool:
        accounts = list(
            pool.map(lambda _: service.register_account("race@example.test", "tok-r"), range(16))
        )
    assert len({a.account_id for a in accounts}) == 1


def test_create_authorization_is_idempotent(service):
    register(service)
    first = service.create_authorization("user-token", "example.test")
    second = service.create_authorization("user-token", "example.test")
    assert first.authorization_id == second.authorization_id
    assert second.status is models.AuthorizationStatus.PENDING


def test_create_authorization_normalizes_domain(service):
    register(service)
    first = service.create_authorization("user-token", "Example.TEST.")
    second = service.create_authorization("user-token", "example.test")
    assert first.authorization_id == second.authorization_id
    assert first.domain == "example.test"


def test_create_authorization_requires_known_token(service):
    with pytest.raises(PermissionDeniedError):
        service.create_authorization("no-such-token", "example.test")


def test_expired_authorization_can_be_renewed(service, clock):
    register(service)
    authz = service.create_authorization("user-token", "example.test")
    clock.advance(timedelta(hours=2))  # authorization_ttl = 1h
    renewed = service.create_authorization("user-token", "example.test")
    assert renewed.authorization_id == authz.authorization_id
    assert renewed.status is models.AuthorizationStatus.PENDING
    assert renewed.expires_at > authz.expires_at


def test_concurrent_authorization_requests_do_not_duplicate(service):
    register(service)
    with ThreadPoolExecutor(max_workers=8) as pool:
        authzs = list(
            pool.map(lambda _: service.create_authorization("user-token", "race.test"), range(16))
        )
    assert len({a.authorization_id for a in authzs}) == 1


def test_audit_trail_records_account_and_authorization(service):
    account = register(service)
    service.create_authorization("user-token", "audit.test")
    actions = [e.action for e in service.audit_log()]
    assert "account.register" in actions
    assert "authorization.create" in actions
    for event in service.audit_log():
        assert event.actor == account.account_id
        assert event.created_at is not None
