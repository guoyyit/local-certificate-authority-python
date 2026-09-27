"""HTTP API end-to-end flow and error mapping."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from local_ca.api import create_app
from local_ca.service import expected_challenge_response


@pytest.fixture()
def client(tmp_path):
    app = create_app(
        db_path=str(tmp_path / "ca.db"), key_dir=str(tmp_path / "keys")
    )
    return TestClient(app)


def _full_flow(client: TestClient, name: str, domain: str) -> dict:
    acct = client.post("/accounts", json={"name": name}).json()
    authz = client.post(
        "/authorizations", json={"account_id": acct["account_id"], "domain": domain}
    ).json()
    chal = client.post(
        "/challenges",
        json={"account_id": acct["account_id"], "authz_id": authz["authz_id"]},
    ).json()
    resp = expected_challenge_response(chal["token"], acct["account_id"])
    r = client.post(
        f"/challenges/{chal['challenge_id']}/respond",
        json={"account_id": acct["account_id"], "response": resp},
    )
    assert r.status_code == 200 and r.json()["status"] == "valid"
    return acct


def test_full_flow_over_http(client):
    acct = _full_flow(client, "alice", "http.test")
    r = client.post(
        "/certificates", json={"account_id": acct["account_id"], "domain": "http.test"}
    )
    assert r.status_code == 201
    cert = r.json()
    assert cert["status"] == "valid"

    r = client.get(f"/certificates/{cert['cert_id']}/verify")
    assert r.json() == {"cert_id": cert["cert_id"], "valid": True}

    r = client.post(
        f"/certificates/{cert['cert_id']}/revoke",
        json={"account_id": acct["account_id"], "reason": "done"},
    )
    assert r.json()["status"] == "revoked"
    r = client.get(f"/certificates/{cert['cert_id']}/verify")
    assert r.json()["valid"] is False

    r = client.get("/audit", params={"account_id": acct["account_id"]})
    actions = [e["action"] for e in r.json()]
    assert "certificate.issue" in actions and "certificate.revoke" in actions


def test_error_mapping(client):
    assert client.get("/accounts/acct_missing").status_code == 404
    viewer = client.post("/accounts", json={"name": "v", "role": "viewer"}).json()
    r = client.post(
        "/authorizations",
        json={"account_id": viewer["account_id"], "domain": "x.test"},
    )
    assert r.status_code == 403
    r = client.post(
        "/certificates",
        json={"account_id": viewer["account_id"], "domain": "x.test"},
    )
    assert r.status_code in (403, 422)


def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}
