"""FastAPI application exposing the local CA over HTTP."""

from __future__ import annotations

from fastapi import FastAPI


def create_app(db_path: str = "local_ca.db", key_dir: str = "ca_keys") -> FastAPI:
    """Build the FastAPI application."""
    raise NotImplementedError
