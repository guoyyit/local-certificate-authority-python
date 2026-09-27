"""Issuance gating, concurrent issuance determinism and certificate rotation."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from cryptography import x509

from local_ca import crypto, models
from local_ca.errors import PermissionDeniedError, ValidationError
from tests.conftest import register, validate_domain


def test_issue_requires_valid_authorization(service):
    register(service)
    service.create_authorization("user-token", "example.test")
    with pytest.raises(ValidationError, match="pending"):
        service.issue_certificate("user-token", "example.test")


def test_issue_requires_any_authorization(service):
    register(service)
    with pytest.raises(ValidationError, match="no authorization"):
        service.issue_certificate("user-token", "missing.test")


def test_issue_after_full_validation(service):
    register(service)
    validate_domain(service, "user-token", "example.test")
    cert = service.issue_certificate("user-token", "example.test")
    assert cert.status is models.CertificateStatus.ACTIVE
    assert crypto.verify_certificate_signature(cert.pem_certificate, service.ca_certificate_pem)
    parsed = x509.load_pem_x509_certificate(cert.pem_certificate.encode())
    san = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert san.value.get_values_for_type(x509.DNSName) == ["example.test"]


def test_issue_is_idempotent_per_account_and_domain(service):
    register(service)
    validate_domain(service, "user-token", "example.test")
    first = service.issue_certificate("user-token", "example.test")
    second = service.issue_certificate("user-token", "example.test")
    assert first.serial == second.serial
    assert len(service.list_certificates("example.test")) == 1


def test_failed_challenge_blocks_issuance(service):
    register(service)
    authz = service.create_authorization("user-token", "example.test")
    challenge = service.create_challenge("user-token", authz.authorization_id)
    with pytest.raises(ValidationError):
        service.respond_challenge("user-token", challenge.challenge_id, "bogus")
    with pytest.raises(ValidationError):
        service.issue_certificate("user-token", "example.test")


def test_expired_challenge_blocks_issuance(service, clock):
    register(service)
    authz = service.create_authorization("user-token", "example.test")
    challenge = service.create_challenge("user-token", authz.authorization_id)
    service.respond_challenge("user-token", challenge.challenge_id, challenge.expected_value)
    clock.advance(timedelta(minutes=6))  # valid challenge passes its expiry
    with pytest.raises(ValidationError):
        service.issue_certificate("user-token", "example.test")


def test_expired_authorization_blocks_issuance(service, clock):
    register(service)
    validate_domain(service, "user-token", "example.test")
    clock.advance(timedelta(hours=2))  # authorization_ttl = 1h
    with pytest.raises(ValidationError):
        service.issue_certificate("user-token", "example.test")


def test_issue_requires_known_token(service):
    with pytest.raises(PermissionDeniedError):
        service.issue_certificate("no-such-token", "example.test")


def test_concurrent_issuance_is_deterministic_and_not_duplicated(service):
    register(service)
    validate_domain(service, "user-token", "race.test")
    with ThreadPoolExecutor(max_workers=8) as pool:
        certs = list(
            pool.map(lambda _: service.issue_certificate("user-token", "race.test"), range(16))
        )
    assert len({c.serial for c in certs}) == 1
    assert len(service.list_certificates("race.test")) == 1


def test_rotation_issues_new_certificate_and_keeps_old_valid(service, clock):
    register(service)
    validate_domain(service, "user-token", "example.test")
    original = service.issue_certificate("user-token", "example.test")
    clock.advance(timedelta(minutes=1))
    rotated = service.rotate_certificate("user-token", "example.test")
    assert rotated.serial != original.serial
    assert rotated.not_before > original.not_before  # validity windows distinguishable
    assert rotated.pem_private_key != original.pem_private_key
    certs = service.list_certificates("example.test")
    assert len(certs) == 2
    # old certificate remains verifiable and active until its own expiry/revocation
    assert service.get_certificate(original.serial).status is models.CertificateStatus.ACTIVE
    assert crypto.verify_certificate_signature(original.pem_certificate, service.ca_certificate_pem)
    assert service.revocation_status(original.serial) is models.CertificateStatus.ACTIVE


def test_rotation_requires_valid_authorization(service):
    register(service)
    with pytest.raises(ValidationError):
        service.rotate_certificate("user-token", "example.test")


def test_certificate_persists_key_and_is_queryable(service):
    register(service)
    validate_domain(service, "user-token", "example.test")
    issued = service.issue_certificate("user-token", "example.test")
    fetched = service.get_certificate(issued.serial)
    assert fetched.pem_private_key == issued.pem_private_key
    assert fetched.pem_certificate == issued.pem_certificate
    by_domain = service.list_certificates("example.test")
    assert [c.serial for c in by_domain] == [issued.serial]
