"""HTTP layer: routing, auth headers and error-to-status mapping."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

from local_ca.api import create_app
from tests.conftest import ADMIN_TOKEN


@pytest.fixture()
def client(service):
    with TestClient(create_app(service)) as c:
        yield c


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _issue_via_http(client, token: str, domain: str) -> dict:
    r = client.post("/accounts", json={"contact": f"{token}@example.test", "token": token})
    assert r.status_code == 201, r.text
    r = client.post("/authorizations", json={"domain": domain}, headers=_auth(token))
    assert r.status_code == 201, r.text
    authz_id = r.json()["authorization_id"]
    r = client.post("/challenges", json={"authorization_id": authz_id}, headers=_auth(token))
    assert r.status_code == 201, r.text
    challenge = r.json()
    r = client.post(
        f"/challenges/{challenge['challenge_id']}/respond",
        json={"value": challenge["expected_value"]},
        headers=_auth(token),
    )
    assert r.status_code == 200, r.text
    r = client.post("/certificates", json={"domain": domain}, headers=_auth(token))
    assert r.status_code == 201, r.text
    return r.json()


def test_full_flow_over_http(client):
    cert = _issue_via_http(client, "tok-http", "http.test")
    assert cert["status"] == "active"
    r = client.get(f"/certificates/{cert['serial']}")
    assert r.status_code == 200
    assert r.json()["pem_private_key"] == cert["pem_private_key"]
    r = client.get("/ca.pem")
    assert r.status_code == 200 and "BEGIN CERTIFICATE" in r.json()["pem"]


def test_missing_bearer_token_rejected(client):
    r = client.post("/authorizations", json={"domain": "x.test"})
    assert r.status_code == 401


def test_unknown_token_rejected(client):
    r = client.post("/authorizations", json={"domain": "x.test"}, headers=_auth("nope"))
    assert r.status_code == 403


def test_unauthorized_revoke_rejected(client):
    cert = _issue_via_http(client, "tok-owner", "owned.test")
    client.post("/accounts", json={"contact": "intruder@example.test", "token": "tok-bad"})
    r = client.post(
        f"/certificates/{cert['serial']}/revoke",
        json={"reason": "malicious"},
        headers=_auth("tok-bad"),
    )
    assert r.status_code == 403
    r = client.get(f"/certificates/{cert['serial']}/status")
    assert r.json()["status"] == "active"


def test_revoke_and_status_over_http(client):
    cert = _issue_via_http(client, "tok-owner", "owned.test")
    r = client.post(
        f"/certificates/{cert['serial']}/revoke",
        json={"reason": "keyCompromise"},
        headers=_auth(ADMIN_TOKEN),
    )
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"
    r = client.get(f"/certificates/{cert['serial']}/status")
    assert r.json() == {"serial": cert["serial"], "status": "revoked"}


def test_unknown_serial_is_404(client):
    r = client.get("/certificates/999/status")
    assert r.status_code == 404


def test_premature_issuance_is_400(client):
    client.post("/accounts", json={"contact": "early@example.test", "token": "tok-early"})
    r = client.post("/certificates", json={"domain": "early.test"}, headers=_auth("tok-early"))
    assert r.status_code == 400


def test_audit_requires_admin(client):
    r = client.get("/audit", headers=_auth("tok-owner"))
    assert r.status_code == 403
    _issue_via_http(client, "tok-owner", "audit.test")
    r = client.get("/audit", headers=_auth(ADMIN_TOKEN))
    assert r.status_code == 200
    actions = [e["action"] for e in r.json()]
    assert "certificate.issue" in actions
