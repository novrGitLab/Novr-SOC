"""Password hashing and opaque credentials.

* Passwords: bcrypt (cost 12). The legacy platform used bcrypt too, so imported hashes stay verifiable.
* Session and CSRF tokens: 32 random bytes, stored only as SHA-256.
* Machine credentials: "nsk_<identity-uuid-hex>.<secret>". Only SHA-256(secret) is stored; secrets under
  32 bytes are refused; comparison is constant-time (port of legacy lib/machineToken.ts).
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import uuid

import bcrypt

MIN_MACHINE_SECRET_BYTES = 32
_BCRYPT_ROUNDS = 12
_DUMMY_HASH = bcrypt.hashpw(b"novrsoc-timing-equaliser", bcrypt.gensalt(_BCRYPT_ROUNDS)).decode()
_MACHINE = re.compile(r"^nsk_([0-9a-f]{32})\.([A-Za-z0-9_-]{43,})$")


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(_BCRYPT_ROUNDS)).decode()


def verify_password(password: str, password_hash: str | None) -> bool:
    """Constant work whether or not the account exists (a dummy hash is checked when there is none)."""
    target = password_hash or _DUMMY_HASH
    try:
        ok = bcrypt.checkpw(password.encode(), target.encode())
    except ValueError:
        ok = False
    return ok and password_hash is not None


def sha256(value: str | bytes) -> bytes:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).digest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


def digests_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def new_machine_credential(identity_id: uuid.UUID) -> tuple[str, bytes]:
    secret = secrets.token_urlsafe(MIN_MACHINE_SECRET_BYTES)
    return f"nsk_{identity_id.hex}.{secret}", sha256(secret)


def parse_machine_credential(token: str) -> tuple[uuid.UUID, bytes] | None:
    """(identity id, sha256 of the presented secret) or None when malformed or too short."""
    m = _MACHINE.match(token.strip())
    if not m:
        return None
    return uuid.UUID(hex=m.group(1)), sha256(m.group(2))
