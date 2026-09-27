"""Entry point: run the local CA HTTP server.

Configuration via environment variables:
  LOCAL_CA_DB           SQLite database path (default: ./local-ca.db)
  LOCAL_CA_ADMIN_TOKEN  admin bearer token (default: dev-admin-token)
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from local_ca.api import create_app
from local_ca.service import CertificateAuthorityService

service = CertificateAuthorityService(
    os.environ.get("LOCAL_CA_DB", "local-ca.db"),
    admin_token=os.environ.get("LOCAL_CA_ADMIN_TOKEN", "dev-admin-token"),
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    yield
    service.close()


app = create_app(service)
app.router.lifespan_context = lifespan
