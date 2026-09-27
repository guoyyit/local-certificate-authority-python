"""FastAPI application exposing the CA service over HTTP.

Authentication: clients pass their account token (or the admin token) in
the ``Authorization: Bearer <token>`` header.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from local_ca import models
from local_ca.errors import (
    CAError,
    ConflictError,
    NotFoundError,
    PermissionDeniedError,
    ValidationError,
)
from local_ca.service import CertificateAuthorityService


class RegisterAccountRequest(BaseModel):
    contact: str
    token: str


class CreateAuthorizationRequest(BaseModel):
    domain: str


class CreateChallengeRequest(BaseModel):
    authorization_id: str


class RespondChallengeRequest(BaseModel):
    value: str


class IssueCertificateRequest(BaseModel):
    domain: str


class RevokeCertificateRequest(BaseModel):
    reason: str = "unspecified"


class AccountResponse(BaseModel):
    account_id: str
    contact: str
    status: str
    created_at: datetime


class AuthorizationResponse(BaseModel):
    authorization_id: str
    domain: str
    status: str
    expires_at: datetime


class ChallengeResponse(BaseModel):
    challenge_id: str
    authorization_id: str
    domain: str
    type: str
    token: str
    expected_value: str
    status: str
    expires_at: datetime


class CertificateResponse(BaseModel):
    serial: str
    domain: str
    pem_certificate: str
    pem_private_key: str
    not_before: datetime
    not_after: datetime
    status: str
    revoked_at: datetime | None
    revocation_reason: str | None


class StatusResponse(BaseModel):
    serial: str
    status: str


class AuditResponse(BaseModel):
    event_id: int
    actor: str
    action: str
    target: str
    detail: str
    created_at: datetime


def _account_response(account: models.Account) -> AccountResponse:
    return AccountResponse(
        account_id=account.account_id,
        contact=account.contact,
        status=account.status.value,
        created_at=account.created_at,
    )


def _authorization_response(authz: models.Authorization) -> AuthorizationResponse:
    return AuthorizationResponse(
        authorization_id=authz.authorization_id,
        domain=authz.domain,
        status=authz.status.value,
        expires_at=authz.expires_at,
    )


def _challenge_response(challenge: models.Challenge) -> ChallengeResponse:
    return ChallengeResponse(
        challenge_id=challenge.challenge_id,
        authorization_id=challenge.authorization_id,
        domain=challenge.domain,
        type=challenge.type.value,
        token=challenge.token,
        expected_value=challenge.expected_value,
        status=challenge.status.value,
        expires_at=challenge.expires_at,
    )


def _certificate_response(record: models.CertificateRecord) -> CertificateResponse:
    return CertificateResponse(
        serial=record.serial,
        domain=record.domain,
        pem_certificate=record.pem_certificate,
        pem_private_key=record.pem_private_key,
        not_before=record.not_before,
        not_after=record.not_after,
        status=record.status.value,
        revoked_at=record.revoked_at,
        revocation_reason=record.revocation_reason,
    )


_ERROR_STATUS = (
    (NotFoundError, 404),
    (ConflictError, 409),
    (PermissionDeniedError, 403),
    (ValidationError, 400),
)


def create_app(service: CertificateAuthorityService) -> FastAPI:
    """Build the HTTP API around an existing service instance."""
    app = FastAPI(title="local-certificate-authority")

    @app.exception_handler(CAError)
    async def _ca_error_handler(_request, exc: CAError) -> JSONResponse:  # type: ignore[no-untyped-def]
        status = next(
            (code for cls, code in _ERROR_STATUS if isinstance(exc, cls)), 500
        )
        return JSONResponse(status_code=status, content={"detail": str(exc)})

    def bearer_token(authorization: str = Header(default="")) -> str:
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            raise HTTPException(status_code=401, detail="missing bearer token")
        return authorization[len(prefix):]

    @app.post("/accounts", response_model=AccountResponse, status_code=201)
    def register_account(body: RegisterAccountRequest) -> AccountResponse:
        return _account_response(service.register_account(body.contact, body.token))

    @app.post("/authorizations", response_model=AuthorizationResponse, status_code=201)
    def create_authorization(
        body: CreateAuthorizationRequest, token: str = Depends(bearer_token)
    ) -> AuthorizationResponse:
        return _authorization_response(service.create_authorization(token, body.domain))

    @app.post("/challenges", response_model=ChallengeResponse, status_code=201)
    def create_challenge(
        body: CreateChallengeRequest, token: str = Depends(bearer_token)
    ) -> ChallengeResponse:
        return _challenge_response(service.create_challenge(token, body.authorization_id))

    @app.post("/challenges/{challenge_id}/respond", response_model=ChallengeResponse)
    def respond_challenge(
        challenge_id: str,
        body: RespondChallengeRequest,
        token: str = Depends(bearer_token),
    ) -> ChallengeResponse:
        return _challenge_response(service.respond_challenge(token, challenge_id, body.value))

    @app.post("/certificates", response_model=CertificateResponse, status_code=201)
    def issue_certificate(
        body: IssueCertificateRequest, token: str = Depends(bearer_token)
    ) -> CertificateResponse:
        return _certificate_response(service.issue_certificate(token, body.domain))

    @app.post("/certificates/rotate", response_model=CertificateResponse, status_code=201)
    def rotate_certificate(
        body: IssueCertificateRequest, token: str = Depends(bearer_token)
    ) -> CertificateResponse:
        return _certificate_response(service.rotate_certificate(token, body.domain))

    @app.get("/certificates", response_model=list[CertificateResponse])
    def list_certificates(domain: str | None = None) -> list[CertificateResponse]:
        return [_certificate_response(r) for r in service.list_certificates(domain)]

    @app.get("/certificates/{serial}", response_model=CertificateResponse)
    def get_certificate(serial: str) -> CertificateResponse:
        return _certificate_response(service.get_certificate(serial))

    @app.post("/certificates/{serial}/revoke", response_model=CertificateResponse)
    def revoke_certificate(
        serial: str,
        body: RevokeCertificateRequest,
        token: str = Depends(bearer_token),
    ) -> CertificateResponse:
        return _certificate_response(service.revoke_certificate(token, serial, body.reason))

    @app.get("/certificates/{serial}/status", response_model=StatusResponse)
    def revocation_status(serial: str) -> StatusResponse:
        return StatusResponse(serial=serial, status=service.revocation_status(serial).value)

    @app.get("/audit", response_model=list[AuditResponse])
    def audit_log(token: str = Depends(bearer_token)) -> list[AuditResponse]:
        if not service.is_admin(token):
            raise HTTPException(status_code=403, detail="admin token required")
        return [
            AuditResponse(
                event_id=e.event_id,
                actor=e.actor,
                action=e.action,
                target=e.target,
                detail=e.detail,
                created_at=e.created_at,
            )
            for e in service.audit_log()
        ]

    @app.get("/ca.pem")
    def ca_pem() -> dict[str, str]:
        return {"pem": service.ca_certificate_pem}

    return app
