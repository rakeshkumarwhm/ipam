"""Password hashing, JWT handling and login throttling."""
import re
import threading
import time
from datetime import datetime, timedelta, timezone

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from .config import get_settings

_ph = PasswordHasher()  # Argon2id with library defaults
_ALGO = "HS256"
# Hash of a random string, verified against when the user does not exist so that
# response time does not reveal valid usernames.
_DUMMY_HASH = _ph.hash("not-a-real-password")


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password: str, hashed: str | None) -> bool:
    try:
        return _ph.verify(hashed or _DUMMY_HASH, password) and hashed is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def validate_password_strength(password: str) -> None:
    if len(password) < 12 or len(password) > 128:
        raise ValueError("Password must be 12-128 characters")
    if not (re.search(r"[a-z]", password) and re.search(r"[A-Z]", password)
            and re.search(r"\d", password)):
        raise ValueError("Password needs upper case, lower case and a digit")


def create_access_token(user_id: int, token_version: int) -> str:
    s = get_settings()
    now = datetime.now(timezone.utc)
    payload = {"sub": str(user_id), "ver": token_version, "iat": now,
               "exp": now + timedelta(minutes=s.access_token_minutes)}
    return jwt.encode(payload, s.secret_key, algorithm=_ALGO)


def decode_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, get_settings().secret_key, algorithms=[_ALGO],
                          options={"require": ["exp", "sub", "ver"]})
    except jwt.PyJWTError:
        return None


class LoginThrottle:
    """In-memory lockout per username and client IP (single-process; use a shared
    store such as Redis if you run several workers)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._fails: dict[str, list[float]] = {}

    def _prune(self, key: str, window: float) -> list[float]:
        now = time.monotonic()
        hits = [t for t in self._fails.get(key, []) if now - t < window]
        self._fails[key] = hits
        return hits

    def blocked(self, *keys: str) -> bool:
        s = get_settings()
        window = s.lockout_minutes * 60
        with self._lock:
            return any(len(self._prune(k, window)) >= s.max_failed_logins for k in keys)

    def fail(self, *keys: str) -> None:
        with self._lock:
            for k in keys:
                self._fails.setdefault(k, []).append(time.monotonic())

    def reset(self, *keys: str) -> None:
        with self._lock:
            for k in keys:
                self._fails.pop(k, None)


throttle = LoginThrottle()
