"""FastAPI application exposing the local CA over HTTP."""

from __future__ import annotations

import dataclasses
import enum
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .crypto import CAKeyStore
from .models import Role
from .service import (
    CAError,
    CertificateAuthorityService,
    ConflictError,
    InvalidStateError,
    NotFoundError,
    PermissionDeniedError,
)
from .storage import Storage

_STATUS_BY_ERROR = {
    NotFoundError: 404,
    PermissionDeniedError: 403,
    ConflictError: 409,
    InvalidStateError: 422,
    CAError: 400,
}


def _to_jsonable(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {k: _to_jsonable(v) for k, v in dataclasses.asdict(value).items()}
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, (list, tuple)):
        return [_to_jsonable(v) for v in value]
    return value


class RegisterAccountRequest(BaseModel):
    name: str
    role: Role = Role.OPERATOR


class AuthorizationRequest(BaseModel):
    account_id: str
    domain: str


class CreateChallengeRequest(BaseModel):
    account_id: str
    authz_id: str


class RespondChallengeRequest(BaseModel):
    account_id: str
    response: str


class IssueCertificateRequest(BaseModel):
    account_id: str
    domain: str


class RevokeCertificateRequest(BaseModel):
    account_id: str
    reason: str = Field(default="unspecified", max_length=256)


def create_app(db_path: str = "local_ca.db", key_dir: str = "ca_keys") -> FastAPI:
    """Build the FastAPI application."""
    storage = Storage(db_path)
    ca_keys = CAKeyStore(key_dir)
    service = CertificateAuthorityService(storage, ca_keys)

    app = FastAPI(title="Local Certificate Authority")
    app.state.service = service

    @app.exception_handler(CAError)
    def _handle_ca_error(request: Request, exc: CAError) -> JSONResponse:
        status = next(
            (code for cls, code in _STATUS_BY_ERROR.items() if isinstance(exc, cls)),
            400,
        )
        return JSONResponse(status_code=status, content={"detail": str(exc)})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # ------------------------------------------------------------- accounts
    @app.post("/accounts", status_code=201)
    def register_account(body: RegisterAccountRequest) -> Any:
        return _to_jsonable(service.register_account(body.name, body.role))

    @app.get("/accounts/{account_id}")
    def get_account(account_id: str) -> Any:
        return _to_jsonable(service.get_account(account_id))

    # ------------------------------------------------------- authorizations
    @app.post("/authorizations", status_code=201)
    def request_authorization(body: AuthorizationRequest) -> Any:
        return _to_jsonable(service.request_authorization(body.account_id, body.domain))

    @app.get("/authorizations/{authz_id}")
    def get_authorization(authz_id: str) -> Any:
        return _to_jsonable(service.get_authorization(authz_id))

    # ----------------------------------------------------------- challenges
    @app.post("/challenges", status_code=201)
    def create_challenge(body: CreateChallengeRequest) -> Any:
        return _to_jsonable(service.create_challenge(body.account_id, body.authz_id))

    @app.get("/challenges/{challenge_id}")
    def get_challenge(challenge_id: str) -> Any:
        return _to_jsonable(service.get_challenge(challenge_id))

    @app.post("/challenges/{challenge_id}/respond")
    def respond_challenge(challenge_id: str, body: RespondChallengeRequest) -> Any:
        return _to_jsonable(
            service.respond_challenge(body.account_id, challenge_id, body.response)
        )

    # ---------------------------------------------------------- certificates
    @app.post("/certificates", status_code=201)
    def issue_certificate(body: IssueCertificateRequest) -> Any:
        return _to_jsonable(service.issue_certificate(body.account_id, body.domain))

    @app.post("/certificates/rotate", status_code=201)
    def rotate_certificate(body: IssueCertificateRequest) -> Any:
        return _to_jsonable(service.rotate_certificate(body.account_id, body.domain))

    @app.get("/certificates")
    def list_certificates(
        domain: str | None = None, account_id: str | None = None
    ) -> Any:
        return _to_jsonable(
            service.list_certificates(domain=domain, account_id=account_id)
        )

    @app.get("/certificates/{cert_id}")
    def get_certificate(cert_id: str) -> Any:
        return _to_jsonable(service.get_certificate(cert_id))

    @app.get("/certificates/{cert_id}/verify")
    def verify_certificate(cert_id: str) -> Any:
        return {"cert_id": cert_id, "valid": service.verify_certificate(cert_id)}

    @app.post("/certificates/{cert_id}/revoke")
    def revoke_certificate(cert_id: str, body: RevokeCertificateRequest) -> Any:
        return _to_jsonable(
            service.revoke_certificate(body.account_id, cert_id, body.reason)
        )

    # ---------------------------------------------------------------- audit
    @app.get("/audit")
    def list_audit(account_id: str | None = None, action: str | None = None) -> Any:
        return _to_jsonable(
            service.list_audit_events(account_id=account_id, action=action)
        )

    return app
