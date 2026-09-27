"""Revocation semantics: state transitions, idempotency, permissions, audit."""

from __future__ import annotations

import pytest

from local_ca import models
from local_ca.errors import NotFoundError, PermissionDeniedError
from tests.conftest import ADMIN_TOKEN, issue, register


def test_revoke_by_admin(service):
    register(service)
    cert = issue(service, "user-token", "example.test")
    revoked = service.revoke_certificate(ADMIN_TOKEN, cert.serial, "keyCompromise")
    assert revoked.status is models.CertificateStatus.REVOKED
    assert revoked.revoked_at is not None
    assert revoked.revocation_reason == "keyCompromise"
    assert service.revocation_status(cert.serial) is models.CertificateStatus.REVOKED


def test_revoke_by_owning_account(service):
    register(service)
    cert = issue(service, "user-token", "example.test")
    revoked = service.revoke_certificate("user-token", cert.serial, "superseded")
    assert revoked.status is models.CertificateStatus.REVOKED


def test_revoke_by_other_account_is_denied(service):
    register(service)
    register(service, "other@example.test", "other-token")
    cert = issue(service, "user-token", "example.test")
    with pytest.raises(PermissionDeniedError):
        service.revoke_certificate("other-token", cert.serial, "malicious")
    assert service.revocation_status(cert.serial) is models.CertificateStatus.ACTIVE


def test_revoke_with_unknown_token_is_denied(service):
    register(service)
    cert = issue(service, "user-token", "example.test")
    with pytest.raises(PermissionDeniedError):
        service.revoke_certificate("no-such-token", cert.serial, "x")


def test_revoke_is_idempotent(service):
    register(service)
    cert = issue(service, "user-token", "example.test")
    first = service.revoke_certificate(ADMIN_TOKEN, cert.serial, "keyCompromise")
    second = service.revoke_certificate(ADMIN_TOKEN, cert.serial, "keyCompromise")
    assert second.status is models.CertificateStatus.REVOKED
    assert second.revoked_at == first.revoked_at


def test_revoke_unknown_serial(service):
    with pytest.raises(NotFoundError):
        service.revoke_certificate(ADMIN_TOKEN, "12345", "x")
    with pytest.raises(NotFoundError):
        service.revocation_status("12345")


def test_revoked_certificate_fails_status_check(service):
    register(service)
    cert = issue(service, "user-token", "example.test")
    assert service.revocation_status(cert.serial) is models.CertificateStatus.ACTIVE
    service.revoke_certificate(ADMIN_TOKEN, cert.serial, "cessationOfOperation")
    assert service.revocation_status(cert.serial) is models.CertificateStatus.REVOKED


def test_revocation_events_are_audited(service):
    account = register(service)
    cert = issue(service, "user-token", "example.test")
    service.revoke_certificate("user-token", cert.serial, "superseded")
    service.revoke_certificate("user-token", cert.serial, "superseded")  # duplicate
    actions = [e.action for e in service.audit_log()]
    assert "certificate.issue" in actions
    assert "certificate.revoke" in actions
    assert "certificate.revoke.duplicate" in actions
    revoke_event = next(e for e in service.audit_log() if e.action == "certificate.revoke")
    assert revoke_event.actor == account.account_id
    assert revoke_event.target == f"certificate:{cert.serial}"
