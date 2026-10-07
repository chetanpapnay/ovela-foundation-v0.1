"""
Trusted session service.

This is the only application module permitted to obtain trusted
AuthorizationContext objects, and it does so only from a verified,
live, server-side session.

Security rules:
- The browser holds an opaque token; the server owns all session state.
- Only a SHA-256 hash of the secret is stored.
- The secret is verified (constant time) before revocation status is revealed.
- Idle and absolute timeouts are enforced server-side; rotation never
  extends the absolute lifetime.
- A context is issued at AUTHENTICATED only. Step-up is a later milestone
  and can never be produced by plain authentication.
- Any store or clock failure fails closed (SessionStoreError).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable
from uuid import UUID, uuid4

from .authorization_context import (
    AuthorizationContext,
    AuthorizationState,
    _issue_internal_authorization_context,
)
from .session_store import (
    SessionError,
    SessionRecord,
    SessionStore,
    SessionStoreError,
    session_store_from_environment,
)
from .temporal_context import from_server_clock


class SessionInvalid(SessionError):
    """The session token is not valid. Maps to HTTP 401."""


class SessionExpired(SessionInvalid):
    """The session passed its idle or absolute timeout."""


class SessionRevoked(SessionInvalid):
    """The session was revoked."""


_SECRET_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
_MAX_TOKEN_LENGTH = 100
_INVALID_MESSAGE = "session is not valid"


@dataclass(frozen=True, slots=True)
class IssuedSession:
    """A newly issued session. The token is shown to the browser once."""

    token: str = field(repr=False)
    session_id: UUID
    expires_at: datetime


def _hash_secret(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("ascii")).digest()


def _ms(value: datetime) -> datetime:
    """Truncate to milliseconds so memory and SQL Server agree exactly."""
    return value.replace(microsecond=(value.microsecond // 1000) * 1000)


def _parse_token(token: object) -> tuple[UUID, str]:
    if not isinstance(token, str) or not token or len(token) > _MAX_TOKEN_LENGTH:
        raise SessionInvalid(_INVALID_MESSAGE)

    session_text, separator, secret = token.partition(".")

    if not separator or not _SECRET_PATTERN.fullmatch(secret):
        raise SessionInvalid(_INVALID_MESSAGE)

    try:
        session_id = UUID(session_text)
    except ValueError:
        raise SessionInvalid(_INVALID_MESSAGE) from None

    if str(session_id) != session_text:
        raise SessionInvalid(_INVALID_MESSAGE)

    return session_id, secret


def _server_clock() -> datetime:
    return from_server_clock("UTC").timestamp_utc


class SessionService:
    def __init__(
        self,
        store: SessionStore,
        *,
        idle_timeout: timedelta = timedelta(minutes=15),
        absolute_timeout: timedelta = timedelta(hours=8),
        context_ttl: timedelta = timedelta(minutes=5),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not isinstance(store, SessionStore):
            raise TypeError("store must be a SessionStore")

        for name, value in (
            ("idle_timeout", idle_timeout),
            ("absolute_timeout", absolute_timeout),
            ("context_ttl", context_ttl),
        ):
            if not isinstance(value, timedelta):
                raise TypeError(f"{name} must be a timedelta")

            if value <= timedelta(0):
                raise ValueError(f"{name} must be positive")

        if clock is not None and not callable(clock):
            raise TypeError("clock must be callable or None")

        self._store = store
        self._idle_timeout = idle_timeout
        self._absolute_timeout = absolute_timeout
        self._context_ttl = context_ttl
        self._clock = clock if clock is not None else _server_clock

    @classmethod
    def from_environment(cls, **kwargs: Any) -> "SessionService":
        """
        Build a service on the shared SQL Server store. Fails closed when
        OVELA_SESSION_DB_CONNECTION is not set: production sessions never
        fall back to process-local memory.
        """
        store = session_store_from_environment()

        if store is None:
            raise SessionStoreError("session store is not configured")

        return cls(store, **kwargs)

    # -- internals ---------------------------------------------------

    def _now(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise SessionStoreError("trusted clock unavailable") from exc

        if not isinstance(value, datetime) or value.tzinfo is None:
            raise SessionStoreError("trusted clock returned an invalid time")

        return _ms(value.astimezone(timezone.utc))

    @staticmethod
    def _call(function: Callable[..., Any], *args: Any) -> Any:
        try:
            return function(*args)
        except SessionError:
            raise
        except Exception as exc:
            raise SessionStoreError("session store failure") from exc

    def _validate(self, token: object) -> tuple[SessionRecord, datetime]:
        session_id, secret = _parse_token(token)
        now = self._now()

        record = self._call(self._store.get, session_id)

        if record is None:
            raise SessionInvalid(_INVALID_MESSAGE)

        if not hmac.compare_digest(record.secret_hash, _hash_secret(secret)):
            raise SessionInvalid(_INVALID_MESSAGE)

        if record.revoked_at is not None:
            raise SessionRevoked("session was revoked")

        if now >= record.expires_at or now >= record.idle_expires_at:
            raise SessionExpired("session expired")

        idle_expires_at = min(now + self._idle_timeout, record.expires_at)

        if not self._call(self._store.touch, session_id, now, idle_expires_at):
            raise SessionRevoked("session was revoked")

        refreshed = SessionRecord(
            session_id=record.session_id,
            subject_id=record.subject_id,
            secret_hash=record.secret_hash,
            issued_at=record.issued_at,
            expires_at=record.expires_at,
            idle_expires_at=idle_expires_at,
            last_seen_at=now,
            revoked_at=None,
        )

        return refreshed, now

    # -- public API --------------------------------------------------

    def create_authenticated_session(self, subject_id: UUID) -> IssuedSession:
        """
        Create a session for a subject whose authentication has ALREADY been
        verified by the caller. This method does not authenticate anyone;
        only the authentication layer may call it.
        """
        if not isinstance(subject_id, UUID):
            raise TypeError("subject_id must be a UUID")

        now = self._now()
        secret = secrets.token_urlsafe(32)
        expires_at = now + self._absolute_timeout

        record = SessionRecord(
            session_id=uuid4(),
            subject_id=subject_id,
            secret_hash=_hash_secret(secret),
            issued_at=now,
            expires_at=expires_at,
            idle_expires_at=min(now + self._idle_timeout, expires_at),
            last_seen_at=now,
        )

        self._call(self._store.insert, record)

        return IssuedSession(
            token=f"{record.session_id}.{secret}",
            session_id=record.session_id,
            expires_at=record.expires_at,
        )

    def resolve_context(self, token: object) -> AuthorizationContext:
        """Return a trusted AUTHENTICATED context for a live session."""
        record, now = self._validate(token)

        expires_at = min(now + self._context_ttl, record.expires_at)

        return _issue_internal_authorization_context(
            session_id=record.session_id,
            subject_id=record.subject_id,
            state=AuthorizationState.AUTHENTICATED,
            issued_at=now,
            expires_at=expires_at,
        )

    def rotate(self, token: object) -> IssuedSession:
        """
        Replace a live session with a new identifier and secret. The old
        token stops working. The absolute lifetime is NOT extended.
        """
        record, now = self._validate(token)
        secret = secrets.token_urlsafe(32)

        new_record = SessionRecord(
            session_id=uuid4(),
            subject_id=record.subject_id,
            secret_hash=_hash_secret(secret),
            issued_at=record.issued_at,
            expires_at=record.expires_at,
            idle_expires_at=min(now + self._idle_timeout, record.expires_at),
            last_seen_at=now,
        )

        if not self._call(
            self._store.rotate,
            record.session_id,
            new_record,
            now,
        ):
            raise SessionRevoked("session was revoked")

        return IssuedSession(
            token=f"{new_record.session_id}.{secret}",
            session_id=new_record.session_id,
            expires_at=new_record.expires_at,
        )

    def revoke(self, token: object) -> bool:
        """
        Revoke a session (logout). The caller must hold the valid token.
        Idempotent: returns False when nothing was revoked.
        """
        try:
            session_id, secret = _parse_token(token)
        except SessionInvalid:
            return False

        record = self._call(self._store.get, session_id)

        if record is None:
            return False

        if not hmac.compare_digest(record.secret_hash, _hash_secret(secret)):
            return False

        return bool(self._call(self._store.revoke, session_id, self._now()))