"""Certificate issuance: preconditions, concurrency, rotation, persistence."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from local_ca.models import CertificateStatus, Role
from local_ca.service import InvalidStateError, PermissionDeniedError

from .conftest import complete_challenge


def test_issue_without_authorization_rejected(service):
    acct = service.register_account("alice")
    with pytest.raises(InvalidStateError, match="authorization"):
        service.issue_certificate(acct.account_id, "noauthz.test")


def test_issue_with_pending_authorization_rejected(service):
    acct = service.register_account("alice")
    service.request_authorization(acct.account_id, "pending.test")
    with pytest.raises(InvalidStateError):
        service.issue_certificate(acct.account_id, "pending.test")


def test_issue_with_expired_authorization_rejected(service, clock):
    acct = service.register_account("alice")
    complete_challenge(service, acct.account_id, "expired.test")
    clock.advance(7200.0)  # authz_ttl is 3600s in tests
    with pytest.raises(InvalidStateError):
        service.issue_certificate(acct.account_id, "expired.test")


def test_issue_persists_cert_and_key(service):
    acct = service.register_account("alice")
    complete_challenge(service, acct.account_id, "web.test")
    cert = service.issue_certificate(acct.account_id, "web.test")
    assert "BEGIN CERTIFICATE" in cert.pem
    assert "BEGIN PRIVATE KEY" in cert.private_key_pem
    fetched = service.get_certificate(cert.cert_id)
    assert fetched.pem == cert.pem
    assert fetched.private_key_pem == cert.private_key_pem
    assert fetched.status is CertificateStatus.VALID
    assert service.verify_certificate(cert.cert_id)


def test_repeat_issue_returns_same_certificate(service):
    acct = service.register_account("alice")
    complete_challenge(service, acct.account_id, "repeat.test")
    first = service.issue_certificate(acct.account_id, "repeat.test")
    second = service.issue_certificate(acct.account_id, "repeat.test")
    assert first.cert_id == second.cert_id
    certs = service.list_certificates(domain="repeat.test")
    assert len(certs) == 1


def test_concurrent_issue_is_deterministic(service):
    acct = service.register_account("alice")
    complete_challenge(service, acct.account_id, "race.test")
    with ThreadPoolExecutor(max_workers=16) as pool:
        certs = list(
            pool.map(
                lambda _: service.issue_certificate(acct.account_id, "race.test"),
                range(32),
            )
        )
    assert len({c.cert_id for c in certs}) == 1, "no duplicate issuance"
    assert len(service.list_certificates(domain="race.test")) == 1


def test_viewer_cannot_issue(service):
    viewer = service.register_account("watcher", Role.VIEWER)
    with pytest.raises(PermissionDeniedError):
        service.issue_certificate(viewer.account_id, "x.test")


def test_rotation_keeps_old_certificate_verifiable(service, clock):
    acct = service.register_account("alice")
    complete_challenge(service, acct.account_id, "rotate.test")
    old = service.issue_certificate(acct.account_id, "rotate.test")
    clock.advance(10.0)
    new = service.rotate_certificate(acct.account_id, "rotate.test")
    assert new.cert_id != old.cert_id
    assert new.serial != old.serial
    assert new.not_before > old.not_before, "generations must be distinguishable"
    # Both remain verifiable: rotation does not instantly invalidate the old one.
    assert service.verify_certificate(old.cert_id)
    assert service.verify_certificate(new.cert_id)
    certs = service.list_certificates(domain="rotate.test")
    assert {c.cert_id for c in certs} == {old.cert_id, new.cert_id}


def test_old_certificate_expires_on_its_own_schedule(service, clock):
    acct = service.register_account("alice")
    complete_challenge(service, acct.account_id, "aging.test")
    old = service.issue_certificate(acct.account_id, "aging.test")
    clock.advance(10.0)
    new = service.rotate_certificate(acct.account_id, "aging.test")
    clock.advance(7210.0)  # both certs now past their not_after
    assert not service.verify_certificate(old.cert_id)
    assert not service.verify_certificate(new.cert_id)
