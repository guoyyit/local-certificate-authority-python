"""Challenge lifecycle: creation, verification, expiry, one-active-per-domain."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from local_ca import models
from local_ca.errors import ConflictError, PermissionDeniedError, ValidationError
from tests.conftest import register


def _authz(service, token, domain):
    return service.create_authorization(token, domain)


def test_challenge_creation_and_successful_response(service):
    register(service)
    authz = _authz(service, "user-token", "example.test")
    challenge = service.create_challenge("user-token", authz.authorization_id)
    assert challenge.status is models.ChallengeStatus.PENDING
    assert challenge.expected_value.startswith("local-ca-verify=")
    done = service.respond_challenge("user-token", challenge.challenge_id, challenge.expected_value)
    assert done.status is models.ChallengeStatus.VALID
    updated = service.create_authorization("user-token", "example.test")
    assert updated.status is models.AuthorizationStatus.VALID


def test_wrong_value_marks_challenge_invalid_and_allows_retry(service):
    register(service)
    authz = _authz(service, "user-token", "example.test")
    challenge = service.create_challenge("user-token", authz.authorization_id)
    with pytest.raises(ValidationError):
        service.respond_challenge("user-token", challenge.challenge_id, "bogus")
    # failed challenge is no longer active: a fresh one may be created
    fresh = service.create_challenge("user-token", authz.authorization_id)
    assert fresh.challenge_id != challenge.challenge_id
    assert fresh.status is models.ChallengeStatus.PENDING


def test_respond_to_invalid_challenge_is_rejected(service):
    register(service)
    authz = _authz(service, "user-token", "example.test")
    challenge = service.create_challenge("user-token", authz.authorization_id)
    with pytest.raises(ValidationError):
        service.respond_challenge("user-token", challenge.challenge_id, "bogus")
    with pytest.raises(ValidationError):
        service.respond_challenge("user-token", challenge.challenge_id, challenge.expected_value)


def test_respond_to_valid_challenge_is_idempotent(service):
    register(service)
    authz = _authz(service, "user-token", "example.test")
    challenge = service.create_challenge("user-token", authz.authorization_id)
    service.respond_challenge("user-token", challenge.challenge_id, challenge.expected_value)
    again = service.respond_challenge("user-token", challenge.challenge_id, challenge.expected_value)
    assert again.status is models.ChallengeStatus.VALID


def test_same_authorization_reuses_active_challenge(service):
    register(service)
    authz = _authz(service, "user-token", "example.test")
    first = service.create_challenge("user-token", authz.authorization_id)
    second = service.create_challenge("user-token", authz.authorization_id)
    assert first.challenge_id == second.challenge_id


def test_other_account_cannot_challenge_same_domain_while_active(service):
    register(service, "a@example.test", "token-a")
    register(service, "b@example.test", "token-b")
    authz_a = _authz(service, "token-a", "shared.test")
    service.create_challenge("token-a", authz_a.authorization_id)
    authz_b = _authz(service, "token-b", "shared.test")
    with pytest.raises(ConflictError):
        service.create_challenge("token-b", authz_b.authorization_id)


def test_other_account_can_challenge_after_first_fails(service):
    register(service, "a@example.test", "token-a")
    register(service, "b@example.test", "token-b")
    authz_a = _authz(service, "token-a", "shared.test")
    chal_a = service.create_challenge("token-a", authz_a.authorization_id)
    with pytest.raises(ValidationError):
        service.respond_challenge("token-a", chal_a.challenge_id, "bogus")
    authz_b = _authz(service, "token-b", "shared.test")
    chal_b = service.create_challenge("token-b", authz_b.authorization_id)
    assert chal_b.status is models.ChallengeStatus.PENDING


def test_challenge_expires_and_can_be_recreated(service, clock):
    register(service)
    authz = _authz(service, "user-token", "example.test")
    challenge = service.create_challenge("user-token", authz.authorization_id)
    clock.advance(timedelta(minutes=6))  # challenge_ttl = 5m
    with pytest.raises(ValidationError, match="expired"):
        service.respond_challenge("user-token", challenge.challenge_id, challenge.expected_value)
    fresh = service.create_challenge("user-token", authz.authorization_id)
    assert fresh.challenge_id != challenge.challenge_id
    done = service.respond_challenge("user-token", fresh.challenge_id, fresh.expected_value)
    assert done.status is models.ChallengeStatus.VALID


def test_challenge_response_requires_owning_account(service):
    register(service, "a@example.test", "token-a")
    register(service, "b@example.test", "token-b")
    authz = _authz(service, "token-a", "example.test")
    challenge = service.create_challenge("token-a", authz.authorization_id)
    with pytest.raises(PermissionDeniedError):
        service.respond_challenge("token-b", challenge.challenge_id, challenge.expected_value)


def test_challenge_on_valid_authorization_is_conflict(service):
    register(service)
    authz = _authz(service, "user-token", "example.test")
    challenge = service.create_challenge("user-token", authz.authorization_id)
    service.respond_challenge("user-token", challenge.challenge_id, challenge.expected_value)
    with pytest.raises(ConflictError):
        service.create_challenge("user-token", authz.authorization_id)


def test_concurrent_challenge_creation_yields_single_active_challenge(service):
    register(service)
    authz = _authz(service, "user-token", "race.test")
    with ThreadPoolExecutor(max_workers=8) as pool:
        challenges = list(
            pool.map(
                lambda _: service.create_challenge("user-token", authz.authorization_id),
                range(16),
            )
        )
    assert len({c.challenge_id for c in challenges}) == 1
