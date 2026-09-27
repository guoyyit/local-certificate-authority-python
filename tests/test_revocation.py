"""Revocation: state, idempotency, permissions, auditability."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from local_ca.models import CertificateStatus, Role
from local_ca.service import PermissionDeniedError

from .conftest import complete_challenge


def _issued(service, account_id: str, domain: str):
    complete_challenge(service, account_id, domain)
    return service.issue_certificate(account_id, domain)


def test_revoked_certificate_fails_verification(service):
    acct = service.register_account("alice")
    cert = _issued(service, acct.account_id, "revoke.test")
    assert service.verify_certificate(cert.cert_id)
    revoked = service.revoke_certificate(acct.account_id, cert.cert_id, "key-compromise")
    assert revoked.status is CertificateStatus.REVOKED
    assert revoked.revoked_at is not None
    assert revoked.revocation_reason == "key-compromise"
    assert not service.verify_certificate(cert.cert_id)


def test_revocation_is_idempotent(service, clock):
    acct = service.register_account("alice")
    cert = _issued(service, acct.account_id, "idem.test")
    first = service.revoke_certificate(acct.account_id, cert.cert_id, "superseded")
    clock.advance(100.0)
    second = service.revoke_certificate(acct.account_id, cert.cert_id, "other-reason")
    assert second.revoked_at == first.revoked_at, "first revocation wins"
    assert second.revocation_reason == "superseded"
    events = service.list_audit_events(action="certificate.revoke")
    assert len(events) == 1, "duplicate revocation must not duplicate audit"


def test_concurrent_revocation_is_idempotent(service):
    acct = service.register_account("alice")
    cert = _issued(service, acct.account_id, "race.test")
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(
            pool.map(
                lambda _: service.revoke_certificate(acct.account_id, cert.cert_id),
                range(32),
            )
        )
    assert all(r.status is CertificateStatus.REVOKED for r in results)
    assert len({r.revoked_at for r in results}) == 1
    assert len(service.list_audit_events(action="certificate.revoke")) == 1


def test_operator_cannot_revoke_others_certificate(service):
    alice = service.register_account("alice")
    mallory = service.register_account("mallory")
    cert = _issued(service, alice.account_id, "protect.test")
    with pytest.raises(PermissionDeniedError):
        service.revoke_certificate(mallory.account_id, cert.cert_id)
    assert service.verify_certificate(cert.cert_id)


def test_admin_can_revoke_any_certificate(service):
    alice = service.register_account("alice")
    admin = service.register_account("root", Role.ADMIN)
    cert = _issued(service, alice.account_id, "admin.test")
    revoked = service.revoke_certificate(admin.account_id, cert.cert_id, "policy")
    assert revoked.status is CertificateStatus.REVOKED
    assert not service.verify_certificate(cert.cert_id)


def test_viewer_cannot_revoke(service):
    alice = service.register_account("alice")
    viewer = service.register_account("watcher", Role.VIEWER)
    cert = _issued(service, alice.account_id, "viewer.test")
    with pytest.raises(PermissionDeniedError):
        service.revoke_certificate(viewer.account_id, cert.cert_id)


def test_revocation_is_audited_with_account_and_time(service):
    acct = service.register_account("alice")
    cert = _issued(service, acct.account_id, "audit.test")
    service.revoke_certificate(acct.account_id, cert.cert_id, "cessation")
    events = service.list_audit_events(action="certificate.revoke")
    assert len(events) == 1
    event = events[0]
    assert event.account_id == acct.account_id
    assert event.target == cert.cert_id
    assert "cessation" in event.detail
    assert event.created_at > 0
