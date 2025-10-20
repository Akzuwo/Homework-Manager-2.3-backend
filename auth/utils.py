"""Utility helpers for password hashing and token management."""

from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import hmac
import secrets
from typing import Optional

try:  # pragma: no cover - optional dependency
    from argon2 import PasswordHasher, exceptions as argon2_exceptions
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    PasswordHasher = None
    argon2_exceptions = None


class _PBKDF2Hasher:
    def __init__(self, iterations: int = 480_000) -> None:
        self.iterations = iterations

    def hash(self, password: str) -> str:
        if not password:
            raise ValueError("Password must not be empty")
        salt = secrets.token_bytes(16)
        derived = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self.iterations)
        encoded = "pbkdf2$%d$%s$%s" % (
            self.iterations,
            base64.b64encode(salt).decode('ascii'),
            base64.b64encode(derived).decode('ascii'),
        )
        return encoded

    def verify(self, encoded: str, password: str) -> bool:
        try:
            scheme, iter_str, salt_b64, hash_b64 = encoded.split('$', 3)
        except ValueError as exc:
            raise ValueError("Invalid hash format") from exc
        if scheme != 'pbkdf2':
            raise ValueError("Unsupported hash scheme")
        iterations = int(iter_str)
        salt = base64.b64decode(salt_b64.encode('ascii'))
        expected = base64.b64decode(hash_b64.encode('ascii'))
        derived = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations)
        if not hmac.compare_digest(expected, derived):
            raise ValueError("Hash mismatch")
        return True


if PasswordHasher is not None:  # pragma: no cover - exercised in production
    _password_hasher = PasswordHasher()
    _VERIFY_EXCEPTIONS = (
        argon2_exceptions.VerifyMismatchError,
        argon2_exceptions.VerificationError,
        argon2_exceptions.InvalidHash,
        ValueError,
    )
else:  # pragma: no cover - executed in tests
    _password_hasher = _PBKDF2Hasher()
    _VERIFY_EXCEPTIONS = (ValueError,)


def hash_password(password: str) -> str:
    """Hash *password* using Argon2 and return the encoded hash."""
    if not password:
        raise ValueError("Password must not be empty")
    return _password_hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Return ``True`` if *password* matches *password_hash*."""
    if not password_hash or password is None:
        return False
    try:
        return _password_hasher.verify(password_hash, password)
    except _VERIFY_EXCEPTIONS:
        return False


def generate_token(length: int = 32) -> str:
    """Generate a URL-safe random token."""
    if length <= 0:
        raise ValueError("length must be positive")
    return secrets.token_urlsafe(length)


def calculate_token_expiry(seconds: int, *, now: Optional[_dt.datetime] = None) -> _dt.datetime:
    """Return an absolute expiry timestamp seconds from *now*."""
    if seconds <= 0:
        raise ValueError("seconds must be positive")
    reference = now or _dt.datetime.now(_dt.timezone.utc)
    if reference.tzinfo is not None:
        reference = reference.astimezone(_dt.timezone.utc).replace(tzinfo=None)
    return reference + _dt.timedelta(seconds=seconds)


__all__ = [
    "hash_password",
    "verify_password",
    "generate_token",
    "calculate_token_expiry",
]
