"""
OVELA / JURIX Session Management Engine.

Security principle:
    - Raw bearer tokens are never stored; only SHA-256 digests are persisted.
    - Sessions strictly bind to subject_id and device_id.
    - Refresh rotation is atomic: old refresh token is immediately revoked.
    - Concurrent replay produces at most one winner.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import hmac
import secrets
import threading
from uuid import UUID, uuid4

from .device_binding import DeviceBindingValidator, DeviceProof


class SessionState(StrEnum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    SUSPICIOUS = "SUSPICIOUS"


class AuthenticationLevel(StrEnum):
    NONE = "NONE"
    RECOGNIZED = "RECOGNIZED"
    AUTHENTICATED = "AUTHENTICATED"
    OWNER_VERIFIED = "OWNER_VERIFIED"
    STEP_UP_VERIFIED = "STEP_UP_VERIFIED"


class TokenKind(StrEnum):
    SESSION = "SESSION"
    REFRESH = "REFRESH"
    STEP_UP = "STEP_UP"


class SessionError(Exception):
    """Base error for session boundary violations."""


class SessionInvalid(SessionError):
    """Raised when session data or token fails validation."""


class SessionExpired(SessionError):
    """Raised when a session has expired."""


class SessionRevoked(SessionError):
    """Raised when an operation targets a revoked session."""


class SessionReplay(SessionError):
    """Raised when an already rotated or consumed token is replayed."""


class SessionRotationRequired(SessionError):
    """Raised when session rotation is required."""


@dataclass(frozen=True, slots=True)
class SessionRecord:
    session_id: UUID
    subject_id: UUID
    device_id: UUID
    state: SessionState
    authentication_level: AuthenticationLevel
    issued_at: datetime
    expires_at: datetime
    last_seen_at: datetime
    rotation_counter: int
    token_version: int

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")
        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        if not isinstance(self.device_id, UUID):
            raise TypeError("device_id must be a UUID")
        if not isinstance(self.state, SessionState):
            raise TypeError("state must be a SessionState")
        if not isinstance(self.authentication_level, AuthenticationLevel):
            raise TypeError("authentication_level must be an AuthenticationLevel")
        if not isinstance(self.issued_at, datetime) or self.issued_at.tzinfo is None:
            raise SessionInvalid("issued_at must be timezone-aware")
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None:
            raise SessionInvalid("expires_at must be timezone-aware")
        if not isinstance(self.last_seen_at, datetime) or self.last_seen_at.tzinfo is None:
            raise SessionInvalid("last_seen_at must be timezone-aware")
        if self.expires_at.astimezone(timezone.utc) <= self.issued_at.astimezone(timezone.utc):
            raise SessionInvalid("expires_at must be strictly later than issued_at")
        if self.last_seen_at.astimezone(timezone.utc) < self.issued_at.astimezone(timezone.utc):
            raise SessionInvalid("last_seen_at cannot be earlier than issued_at")
        if not isinstance(self.rotation_counter, int) or self.rotation_counter < 0:
            raise SessionInvalid("rotation_counter must be non-negative")
        if not isinstance(self.token_version, int) or self.token_version < 0:
            raise SessionInvalid("token_version must be non-negative")


@dataclass(frozen=True, slots=True)
class TokenRecord:
    token_id: UUID
    session_id: UUID
    kind: TokenKind
    token_hash: str
    issued_at: datetime
    expires_at: datetime
    rotation_counter: int
    revoked: bool

    def __post_init__(self) -> None:
        if not isinstance(self.token_id, UUID):
            raise TypeError("token_id must be a UUID")
        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")
        if not isinstance(self.kind, TokenKind):
            raise TypeError("kind must be a TokenKind")
        if not isinstance(self.token_hash, str) or not self.token_hash.strip():
            raise SessionInvalid("token_hash must be non-empty")
        if not isinstance(self.issued_at, datetime) or self.issued_at.tzinfo is None:
            raise SessionInvalid("issued_at must be timezone-aware")
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None:
            raise SessionInvalid("expires_at must be timezone-aware")
        if not isinstance(self.rotation_counter, int) or self.rotation_counter < 0:
            raise SessionInvalid("rotation_counter must be non-negative")
        if not isinstance(self.revoked, bool):
            raise TypeError("revoked must be a bool")


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


class SessionService:
    """Thread-safe session issuance, validation, rotation, and revocation service."""

    def __init__(self, device_validator: DeviceBindingValidator | None = None) -> None:
        self._lock = threading.RLock()
        self._device_validator = device_validator
        self._sessions: dict[UUID, SessionRecord] = {}
        # token_hash -> TokenRecord
        self._tokens: dict[str, TokenRecord] = {}

    def issue(
        self,
        *,
        subject_id: UUID,
        device_id: UUID,
        authentication_level: AuthenticationLevel,
        now: datetime,
        lifetime_seconds: int = 3600,
    ) -> tuple[SessionRecord, str]:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise SessionInvalid("now must be timezone-aware")
        if lifetime_seconds <= 0:
            raise SessionInvalid("lifetime_seconds must be positive")

        session_id = uuid4()
        now_utc = now.astimezone(timezone.utc)
        expires_at = now_utc + timedelta(seconds=lifetime_seconds)

        session = SessionRecord(
            session_id=session_id,
            subject_id=subject_id,
            device_id=device_id,
            state=SessionState.ACTIVE,
            authentication_level=authentication_level,
            issued_at=now_utc,
            expires_at=expires_at,
            last_seen_at=now_utc,
            rotation_counter=0,
            token_version=1,
        )

        raw_token = secrets.token_urlsafe(32)
        token_hash = _hash_token(raw_token)

        token_record = TokenRecord(
            token_id=uuid4(),
            session_id=session_id,
            kind=TokenKind.SESSION,
            token_hash=token_hash,
            issued_at=now_utc,
            expires_at=expires_at,
            rotation_counter=0,
            revoked=False,
        )

        with self._lock:
            self._sessions[session_id] = session
            self._tokens[token_hash] = token_record

        return session, raw_token

    def issue_refresh_token(
        self,
        *,
        session_id: UUID,
        now: datetime,
        lifetime_seconds: int = 86400,
    ) -> str:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise SessionInvalid("now must be timezone-aware")

        now_utc = now.astimezone(timezone.utc)
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None or session.state != SessionState.ACTIVE:
                raise SessionInvalid("Cannot issue refresh token for inactive session")

            raw_refresh = secrets.token_urlsafe(32)
            token_hash = _hash_token(raw_refresh)

            token_rec = TokenRecord(
                token_id=uuid4(),
                session_id=session_id,
                kind=TokenKind.REFRESH,
                token_hash=token_hash,
                issued_at=now_utc,
                expires_at=now_utc + timedelta(seconds=lifetime_seconds),
                rotation_counter=session.rotation_counter,
                revoked=False,
            )
            self._tokens[token_hash] = token_rec
            return raw_refresh

    def validate(
        self,
        *,
        raw_token: str,
        device_proof: DeviceProof,
        now: datetime,
    ) -> SessionRecord:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise SessionInvalid("now must be timezone-aware")
        if not isinstance(raw_token, str) or not raw_token.strip():
            raise SessionInvalid("raw_token must be non-empty")

        now_utc = now.astimezone(timezone.utc)
        token_hash = _hash_token(raw_token)

        with self._lock:
            token_rec = self._tokens.get(token_hash)
            if token_rec is None or token_rec.kind != TokenKind.SESSION:
                raise SessionInvalid("Invalid session token")

            if token_rec.revoked:
                raise SessionRevoked("Session token has been revoked")

            if now_utc >= token_rec.expires_at.astimezone(timezone.utc):
                raise SessionExpired("Session token has expired")

            session = self._sessions.get(token_rec.session_id)
            if session is None:
                raise SessionInvalid("Associated session does not exist")

            if session.state == SessionState.REVOKED:
                raise SessionRevoked("Session is revoked")
            if session.state == SessionState.EXPIRED or now_utc >= session.expires_at.astimezone(timezone.utc):
                raise SessionExpired("Session has expired")
            if session.state != SessionState.ACTIVE:
                raise SessionInvalid(f"Session is not active: {session.state}")

            # Verify device proof
            if self._device_validator is not None:
                dev_res = self._device_validator.validate(
                    proof=device_proof,
                    expected_subject_id=session.subject_id,
                    now=now,
                )
                if not dev_res.valid or dev_res.device_id != session.device_id:
                    raise SessionInvalid(f"Device validation failed: {dev_res.reason_code}")

            # Update last_seen_at
            updated_session = SessionRecord(
                session_id=session.session_id,
                subject_id=session.subject_id,
                device_id=session.device_id,
                state=session.state,
                authentication_level=session.authentication_level,
                issued_at=session.issued_at,
                expires_at=session.expires_at,
                last_seen_at=now_utc,
                rotation_counter=session.rotation_counter,
                token_version=session.token_version,
            )
            self._sessions[session.session_id] = updated_session
            return updated_session

    def rotate(
        self,
        *,
        session_id: UUID,
        raw_refresh_token: str,
        device_proof: DeviceProof,
        now: datetime,
    ) -> tuple[SessionRecord, str]:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise SessionInvalid("now must be timezone-aware")
        if not isinstance(raw_refresh_token, str) or not raw_refresh_token.strip():
            raise SessionInvalid("raw_refresh_token must be non-empty")

        now_utc = now.astimezone(timezone.utc)
        refresh_hash = _hash_token(raw_refresh_token)

        with self._lock:
            token_rec = self._tokens.get(refresh_hash)
            if token_rec is None or token_rec.kind != TokenKind.REFRESH:
                raise SessionInvalid("Invalid refresh token")

            if token_rec.session_id != session_id:
                raise SessionInvalid("Refresh token session mismatch")

            if token_rec.revoked:
                # Concurrent reuse or replay of old refresh token detected
                raise SessionReplay("Refresh token was already used or revoked")

            if now_utc >= token_rec.expires_at.astimezone(timezone.utc):
                raise SessionExpired("Refresh token has expired")

            session = self._sessions.get(session_id)
            if session is None or session.state != SessionState.ACTIVE:
                raise SessionInvalid("Target session is inactive or revoked")

            # Invalidate the old refresh token immediately (atomic single-use)
            revoked_refresh = TokenRecord(
                token_id=token_rec.token_id,
                session_id=token_rec.session_id,
                kind=token_rec.kind,
                token_hash=token_rec.token_hash,
                issued_at=token_rec.issued_at,
                expires_at=token_rec.expires_at,
                rotation_counter=token_rec.rotation_counter,
                revoked=True,
            )
            self._tokens[refresh_hash] = revoked_refresh

            # Verify device proof
            if self._device_validator is not None:
                dev_res = self._device_validator.validate(
                    proof=device_proof,
                    expected_subject_id=session.subject_id,
                    now=now,
                )
                if not dev_res.valid or dev_res.device_id != session.device_id:
                    raise SessionInvalid("Device proof validation failed during rotation")

            new_counter = session.rotation_counter + 1
            new_version = session.token_version + 1

            new_session = SessionRecord(
                session_id=session.session_id,
                subject_id=session.subject_id,
                device_id=session.device_id,
                state=SessionState.ACTIVE,
                authentication_level=session.authentication_level,
                issued_at=session.issued_at,
                expires_at=now_utc + timedelta(hours=1),
                last_seen_at=now_utc,
                rotation_counter=new_counter,
                token_version=new_version,
            )
            self._sessions[session_id] = new_session

            # Issue new session bearer token
            raw_new_token = secrets.token_urlsafe(32)
            new_token_hash = _hash_token(raw_new_token)
            new_token_rec = TokenRecord(
                token_id=uuid4(),
                session_id=session_id,
                kind=TokenKind.SESSION,
                token_hash=new_token_hash,
                issued_at=now_utc,
                expires_at=new_session.expires_at,
                rotation_counter=new_counter,
                revoked=False,
            )
            self._tokens[new_token_hash] = new_token_rec

            return new_session, raw_new_token

    def revoke(
        self,
        *,
        session_id: UUID,
        reason: str,
        now: datetime,
    ) -> None:
        if not isinstance(session_id, UUID):
            raise TypeError("session_id must be a UUID")
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return  # Idempotent

            revoked_session = SessionRecord(
                session_id=session.session_id,
                subject_id=session.subject_id,
                device_id=session.device_id,
                state=SessionState.REVOKED,
                authentication_level=session.authentication_level,
                issued_at=session.issued_at,
                expires_at=session.expires_at,
                last_seen_at=now if now.tzinfo is not None else session.last_seen_at,
                rotation_counter=session.rotation_counter,
                token_version=session.token_version,
            )
            self._sessions[session_id] = revoked_session

            # Revoke all tokens for this session
            for h, tok in list(self._tokens.items()):
                if tok.session_id == session_id and not tok.revoked:
                    self._tokens[h] = TokenRecord(
                        token_id=tok.token_id,
                        session_id=tok.session_id,
                        kind=tok.kind,
                        token_hash=tok.token_hash,
                        issued_at=tok.issued_at,
                        expires_at=tok.expires_at,
                        rotation_counter=tok.rotation_counter,
                        revoked=True,
                    )

    def revoke_all_for_subject(
        self,
        *,
        subject_id: UUID,
        reason: str,
        now: datetime,
    ) -> int:
        if not isinstance(subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        count = 0
        with self._lock:
            for s_id, sess in list(self._sessions.items()):
                if sess.subject_id == subject_id and sess.state != SessionState.REVOKED:
                    self.revoke(session_id=s_id, reason=reason, now=now)
                    count += 1
        return count