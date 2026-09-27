"""Account registration: duplicate and concurrent requests stay unique."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from local_ca.models import AccountStatus, Role
from local_ca.service import NotFoundError, PermissionDeniedError

import pytest


def test_register_account_is_idempotent(service):
    first = service.register_account("alice")
    second = service.register_account("alice")
    assert first.account_id == second.account_id
    assert first.name == "alice"


def test_register_account_rejects_empty_name(service):
    with pytest.raises(Exception, match="empty"):
        service.register_account("")


def test_concurrent_registration_creates_single_account(service):
    with ThreadPoolExecutor(max_workers=16) as pool:
        accounts = list(pool.map(lambda _: service.register_account("team"), range(64)))
    ids = {a.account_id for a in accounts}
    assert len(ids) == 1, "concurrent registration must not duplicate accounts"
    stored = service.list_audit_events(action="account.register")
    assert len(stored) == 1, "exactly one register event may be audited"


def test_account_roles_and_status(service):
    viewer = service.register_account("watcher", Role.VIEWER)
    assert viewer.role is Role.VIEWER
    assert viewer.status is AccountStatus.ACTIVE


def test_get_missing_account_raises(service):
    with pytest.raises(NotFoundError):
        service.get_account("acct_missing")


def test_viewer_cannot_request_authorization(service):
    viewer = service.register_account("watcher", Role.VIEWER)
    with pytest.raises(PermissionDeniedError):
        service.request_authorization(viewer.account_id, "x.test")
