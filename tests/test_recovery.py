"""Crash recovery: durable results survive, incomplete work is retryable."""

from __future__ import annotations

import pytest

from local_ca.crypto import CAKeyStore
from local_ca.models import CertificateStatus, ChallengeStatus
from local_ca.service import CertificateAuthorityService
from local_ca.storage import Storage

from .conftest import FakeClock, complete_challenge, expected_challenge_response


def _make_service(tmp_path, clock: FakeClock) -> CertificateAuthorityService:
    return CertificateAuthorityService(
        Storage(str(tmp_path / "ca.db")),
        CAKeyStore(str(tmp_path / "keys")),
        now=clock,
        authz_ttl=3600.0,
        challenge_ttl=60.0,
        cert_ttl=7200.0,
    )


def test_issued_certificates_survive_restart(tmp_path, clock):
    svc = _make_service(tmp_path, clock)
    acct = svc.register_account("alice")
    complete_challenge(svc, acct.account_id, "durable.test")
    cert = svc.issue_certificate(acct.account_id, "durable.test")

    restarted = _make_service(tmp_path, clock)
    fetched = restarted.get_certificate(cert.cert_id)
    assert fetched.pem == cert.pem
    assert fetched.private_key_pem == cert.private_key_pem
    assert restarted.verify_certificate(cert.cert_id)


def test_revocation_survives_restart(tmp_path, clock):
    svc = _make_service(tmp_path, clock)
    acct = svc.register_account("alice")
    complete_challenge(svc, acct.account_id, "gone.test")
    cert = svc.issue_certificate(acct.account_id, "gone.test")
    svc.revoke_certificate(acct.account_id, cert.cert_id, "key-compromise")

    restarted = _make_service(tmp_path, clock)
    fetched = restarted.get_certificate(cert.cert_id)
    assert fetched.status is CertificateStatus.REVOKED
    assert fetched.revocation_reason == "key-compromise"
    assert not restarted.verify_certificate(cert.cert_id)


def test_pending_challenge_expires_on_recovery_and_is_retryable(tmp_path, clock):
    svc = _make_service(tmp_path, clock)
    acct = svc.register_account("alice")
    authz = svc.request_authorization(acct.account_id, "crash.test")
    challenge = svc.create_challenge(acct.account_id, authz.authz_id)

    # "Crash" while the challenge is pending, then come back past its TTL.
    clock.advance(120.0)
    restarted = _make_service(tmp_path, clock)
    assert (
        restarted.get_challenge(challenge.challenge_id).status
        is ChallengeStatus.EXPIRED
    )
    # The flow is retryable from a clean state: new challenge, then issue.
    fresh = restarted.create_challenge(acct.account_id, authz.authz_id)
    restarted.respond_challenge(
        acct.account_id,
        fresh.challenge_id,
        expected_challenge_response(fresh.token, acct.account_id),
    )
    cert = restarted.issue_certificate(acct.account_id, "crash.test")
    assert restarted.verify_certificate(cert.cert_id)


def test_audit_log_survives_restart(tmp_path, clock):
    svc = _make_service(tmp_path, clock)
    acct = svc.register_account("alice")
    complete_challenge(svc, acct.account_id, "trail.test")
    cert = svc.issue_certificate(acct.account_id, "trail.test")
    svc.revoke_certificate(acct.account_id, cert.cert_id)

    restarted = _make_service(tmp_path, clock)
    actions = [e.action for e in restarted.list_audit_events()]
    assert "account.register" in actions
    assert "certificate.issue" in actions
    assert "certificate.revoke" in actions


def test_failed_issuance_leaves_no_partial_certificate(tmp_path, clock, monkeypatch):
    svc = _make_service(tmp_path, clock)
    acct = svc.register_account("alice")
    complete_challenge(svc, acct.account_id, "atomic.test")

    # Simulate a crash right after signing, before the record is stored.
    def boom(*args, **kwargs):
        raise RuntimeError("simulated crash")

    monkeypatch.setattr(svc._storage, "insert_certificate", boom)
    with pytest.raises(RuntimeError):
        svc.issue_certificate(acct.account_id, "atomic.test")

    # Recover: no half certificate may exist, and issuance can be retried.
    restarted = _make_service(tmp_path, clock)
    assert restarted.list_certificates(domain="atomic.test") == []
    cert = restarted.issue_certificate(acct.account_id, "atomic.test")
    assert restarted.verify_certificate(cert.cert_id)


def test_ca_rotation_history_survives_restart(tmp_path, clock):
    svc = _make_service(tmp_path, clock)
    acct = svc.register_account("alice")
    complete_challenge(svc, acct.account_id, "multi-ca.test")
    old = svc.issue_certificate(acct.account_id, "multi-ca.test")
    svc._ca.rotate()
    clock.advance(10.0)
    new = svc.rotate_certificate(acct.account_id, "multi-ca.test")

    restarted = _make_service(tmp_path, clock)
    assert restarted.verify_certificate(old.cert_id), "pre-rotation cert verifies"
    assert restarted.verify_certificate(new.cert_id)
