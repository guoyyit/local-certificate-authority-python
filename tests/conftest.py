"""Shared fixtures: isolated storage, controllable clock, service factory."""

from __future__ import annotations

import threading

import pytest

from local_ca.crypto import CAKeyStore
from local_ca.service import CertificateAuthorityService, expected_challenge_response
from local_ca.storage import Storage


class FakeClock:
    """A manually advanced clock, safe to share across threads."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self._t = start
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self._t

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._t += seconds


@pytest.fixture()
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture()
def service(tmp_path, clock) -> CertificateAuthorityService:
    storage = Storage(str(tmp_path / "ca.db"))
    keys = CAKeyStore(str(tmp_path / "keys"))
    return CertificateAuthorityService(
        storage,
        keys,
        now=clock,
        authz_ttl=3600.0,
        challenge_ttl=60.0,
        cert_ttl=7200.0,
    )


def complete_challenge(
    service: CertificateAuthorityService, account_id: str, domain: str
) -> None:
    """Drive an account through authorization + challenge for a domain."""
    authz = service.request_authorization(account_id, domain)
    challenge = service.create_challenge(account_id, authz.authz_id)
    service.respond_challenge(
        account_id,
        challenge.challenge_id,
        expected_challenge_response(challenge.token, account_id),
    )


__all__ = ["FakeClock", "complete_challenge", "expected_challenge_response"]
