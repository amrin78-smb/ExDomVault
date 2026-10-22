"""Worker identity: the Ed25519 private key used to sign every API request."""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.config import ConfigError

_MAX_KEY_FILE_BYTES = 16 * 1024


def load_private_key(path: str) -> Ed25519PrivateKey:
    """Loads an unencrypted PEM (PKCS#8) Ed25519 private key, e.g. from
    ``openssl genpkey -algorithm ed25519``. Raises ConfigError without echoing key material."""
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise ConfigError("EXDV_PRIVATE_KEY_FILE cannot be read") from exc
    if len(data) > _MAX_KEY_FILE_BYTES:
        raise ConfigError("EXDV_PRIVATE_KEY_FILE is too large to be a PEM private key")
    try:
        key = serialization.load_pem_private_key(data, password=None)
    except (ValueError, TypeError) as exc:
        raise ConfigError(
            "EXDV_PRIVATE_KEY_FILE is not an unencrypted PEM (PKCS#8) private key"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ConfigError("EXDV_PRIVATE_KEY_FILE must hold an Ed25519 key")
    return key


def public_key_b64(key: Ed25519PrivateKey) -> str:
    """Standard base64 of the raw 32-byte public key (the form pasted into Settings → Workers)."""
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw).decode("ascii")
