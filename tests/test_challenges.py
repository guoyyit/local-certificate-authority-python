"""Challenge lifecycle: uniqueness, validation, failure retry, expiry."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from local_ca.models import AuthorizationStatus, ChallengeStatus
from local_ca.service import InvalidStateError, PermissionDeniedError

from .conftest import expected_challenge_response


def _authz(service, account_id: str, domain: str):
    return service.request_authorization(account_id, domain)


def test_one_active_challenge_per_domain(service):
    acct = service.register_account("alice")
    authz = _authz(service, acct.account_id, "one.test")
    first = service.create_challenge(acct.account_id, authz.authz_id)
    second = service.create_challenge(acct.account_id, authz.authz_id)
    assert first.challenge_id == second.challenge_id
    assert first.token == second.token


def test_concurrent_challenge_creation_yields_single_challenge(service):
    acct = service.register_account("alice")
    authz = _authz(service, acct.account_id, "race.test")
    with ThreadPoolExecutor(max_workers=16) as pool:
        challenges = list(
            pool.map(
                lambda _: service.create_challenge(acct.account_id, authz.authz_id),
                range(32),
            )
        )
    assert len({c.challenge_id for c in challenges}) == 1


def test_success_challenge_marks_authorization_valid(service):
    acct = service.register_account("alice")
    authz = _authz(service, acct.account_id, "ok.test")
    challenge = service.create_challenge(acct.account_id, authz.authz_id)
    done = service.respond_challenge(
        acct.account_id,
        challenge.challenge_id,
        expected_challenge_response(challenge.token, acct.account_id),
    )
    assert done.status is ChallengeStatus.VALID
    assert service.get_authorization(authz.authz_id).status is AuthorizationStatus.VALID


def test_wrong_response_invalidates_and_allows_retry(service):
    acct = service.register_account("alice")
    authz = _authz(service, acct.account_id, "retry.test")
    challenge = service.create_challenge(acct.account_id, authz.authz_id)
    with pytest.raises(InvalidStateError, match="wrong"):
        service.respond_challenge(acct.account_id, challenge.challenge_id, "nope")
    assert service.get_challenge(challenge.challenge_id).status is ChallengeStatus.INVALID
    # A fresh challenge may be created after failure.
    fresh = service.create_challenge(acct.account_id, authz.authz_id)
    assert fresh.challenge_id != challenge.challenge_id
    done = service.respond_challenge(
        acct.account_id,
        fresh.challenge_id,
        expected_challenge_response(fresh.token, acct.account_id),
    )
    assert done.status is ChallengeStatus.VALID


def test_challenge_expires_and_allows_retry(service, clock):
    acct = service.register_account("alice")
    authz = _authz(service, acct.account_id, "slow.test")
    challenge = service.create_challenge(acct.account_id, authz.authz_id)
    clock.advance(120.0)  # challenge_ttl is 60s in tests
    with pytest.raises(InvalidStateError, match="expired"):
        service.respond_challenge(
            acct.account_id,
            challenge.challenge_id,
            expected_challenge_response(challenge.token, acct.account_id),
        )
    assert service.get_challenge(challenge.challenge_id).status is ChallengeStatus.EXPIRED
    # After expiry a new challenge can be created and completed.
    fresh = service.create_challenge(acct.account_id, authz.authz_id)
    assert fresh.challenge_id != challenge.challenge_id
    done = service.respond_challenge(
        acct.account_id,
        fresh.challenge_id,
        expected_challenge_response(fresh.token, acct.account_id),
    )
    assert done.status is ChallengeStatus.VALID


def test_respond_to_terminal_challenge_rejected(service):
    acct = service.register_account("alice")
    authz = _authz(service, acct.account_id, "done.test")
    challenge = service.create_challenge(acct.account_id, authz.authz_id)
    service.respond_challenge(
        acct.account_id,
        challenge.challenge_id,
        expected_challenge_response(challenge.token, acct.account_id),
    )
    with pytest.raises(InvalidStateError):
        service.respond_challenge(
            acct.account_id,
            challenge.challenge_id,
            expected_challenge_response(challenge.token, acct.account_id),
        )


def test_challenge_for_other_account_rejected(service):
    alice = service.register_account("alice")
    mallory = service.register_account("mallory")
    authz = _authz(service, alice.account_id, "theft.test")
    with pytest.raises(PermissionDeniedError):
        service.create_challenge(mallory.account_id, authz.authz_id)
    challenge = service.create_challenge(alice.account_id, authz.authz_id)
    with pytest.raises(PermissionDeniedError):
        service.respond_challenge(
            mallory.account_id,
            challenge.challenge_id,
            expected_challenge_response(challenge.token, alice.account_id),
        )


def test_challenge_requires_pending_authorization(service):
    acct = service.register_account("alice")
    authz = _authz(service, acct.account_id, "valid.test")
    challenge = service.create_challenge(acct.account_id, authz.authz_id)
    service.respond_challenge(
        acct.account_id,
        challenge.challenge_id,
        expected_challenge_response(challenge.token, acct.account_id),
    )
    with pytest.raises(InvalidStateError):
        service.create_challenge(acct.account_id, authz.authz_id)
