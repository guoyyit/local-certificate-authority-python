"""Cryptographic primitives: CA key management, signing and verification."""

from __future__ import annotations


class CAKeyStore:
    """Loads or generates the CA signing keypair, supports rotation."""

    def __init__(self, key_dir: str) -> None:
        raise NotImplementedError
