"""Crash recovery: committed results survive restarts, partial work rolls back."""

from __future__ import annotations

from datetime import timedelta

import pytest

from local_ca import crypto, models
from local_ca.errors import ValidationError
from local_ca.service import CertificateAuthorityService
from tests.conftest import ADMIN_TOKEN, issue, register, validate_domain


def _reopen(db_path, clock) -> CertificateAuthorityService:
    return CertificateAuthorityService(
        db_path,
        admin_token=ADMIN_TOKEN,
        now=clock,
        challenge_ttl=timedelta(minutes=5),
        authorization_ttl=timedelta(hours=1),
        certificate_ttl=timedelta(days=30),
    )


def test_issued_certificate_survives_restart(service, db_path, clock):
    register(service)
    cert = issue(service, "user-token", "example.test")
    ca_pem = service.ca_certificate_pem
    service.close()
    reopened = _reopen(db_path, clock)
    try:
        fetched = reopened.get_certificate(cert.serial)
        assert fetched.pem_certificate == cert.pem_certificate
        assert fetched.pem_private_key == cert.pem_private_key
        assert reopened.revocation_status(cert.serial) is models.CertificateStatus.ACTIVE
        assert reopened.ca_certificate_pem == ca_pem  # CA identity is stable
        assert crypto.verify_certificate_signature(
            fetched.pem_certificate, reopened.ca_certificate_pem
        )
    finally:
        reopened.close()


def test_revocation_survives_restart(service, db_path, clock):
    register(service)
    cert = issue(service, "user-token", "example.test")
    service.revoke_certificate(ADMIN_TOKEN, cert.serial, "keyCompromise")
    service.close()
    reopened = _reopen(db_path, clock)
    try:
        assert reopened.revocation_status(cert.serial) is models.CertificateStatus.REVOKED
        fetched = reopened.get_certificate(cert.serial)
        assert fetched.revocation_reason == "keyCompromise"
        assert fetched.revoked_at is not None
    finally:
        reopened.close()


def test_pending_challenge_is_retryable_after_restart(service, db_path, clock):
    register(service)
    authz = service.create_authorization("user-token", "example.test")
    challenge = service.create_challenge("user-token", authz.authorization_id)
    service.close()  # "crash" before responding
    reopened = _reopen(db_path, clock)
    try:
        done = reopened.respond_challenge(
            "user-token", challenge.challenge_id, challenge.expected_value
        )
        assert done.status is models.ChallengeStatus.VALID
        cert = reopened.issue_certificate("user-token", "example.test")
        assert cert.status is models.CertificateStatus.ACTIVE
    finally:
        reopened.close()


def test_failed_issuance_leaves_no_partial_state(service, monkeypatch):
    register(service)
    validate_domain(service, "user-token", "example.test")
    audit_before = len(service.audit_log())

    def boom(**kwargs):
        raise RuntimeError("simulated crash during signing")

    monkeypatch.setattr("local_ca.crypto.issue_certificate_pem", boom)
    with pytest.raises(RuntimeError):
        service.issue_certificate("user-token", "example.test")
    monkeypatch.undo()

    # no half certificate, no half audit record, flow is retryable
    assert service.list_certificates("example.test") == []
    assert len(service.audit_log()) == audit_before
    cert = service.issue_certificate("user-token", "example.test")
    assert cert.status is models.CertificateStatus.ACTIVE
    assert len(service.list_certificates("example.test")) == 1


def test_failed_challenge_response_leaves_no_partial_state(service, monkeypatch):
    register(service)
    authz = service.create_authorization("user-token", "example.test")
    challenge = service.create_challenge("user-token", authz.authorization_id)

    original = service._storage.set_authorization_status

    def boom(*args, **kwargs):
        raise RuntimeError("simulated crash mid-transition")

    monkeypatch.setattr(service._storage, "set_authorization_status", boom)
    with pytest.raises(RuntimeError):
        service.respond_challenge("user-token", challenge.challenge_id, challenge.expected_value)
    monkeypatch.undo()

    # transaction rolled back: challenge still pending and retryable
    pending = service._storage.get_challenge(challenge.challenge_id)
    assert pending.status is models.ChallengeStatus.PENDING
    done = service.respond_challenge("user-token", challenge.challenge_id, challenge.expected_value)
    assert done.status is models.ChallengeStatus.VALID


def test_audit_log_survives_restart(service, db_path, clock):
    account = register(service)
    cert = issue(service, "user-token", "example.test")
    service.revoke_certificate(ADMIN_TOKEN, cert.serial, "keyCompromise")
    count_before = len(service.audit_log())
    service.close()
    reopened = _reopen(db_path, clock)
    try:
        events = reopened.audit_log()
        assert len(events) == count_before
        assert any(e.action == "certificate.revoke" for e in events)
        assert any(e.actor == account.account_id for e in events)
    finally:
        reopened.close()
