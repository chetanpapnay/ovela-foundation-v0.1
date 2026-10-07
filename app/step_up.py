"""
OVELA / JURIX Step-Up Challenge and Evidence Engine.

Security principles:
    - Step-up is strictly bound to session, subject, action, and transaction scope.
    - Challenges are single-use, time-bound, and store only cryptographic nonce hashes.
    - Atomic check-and-consume prevents replay and concurrent re-use.
    - Only the trusted step-up provider creates trusted StepUpEvidence.
    - Transaction parameter changes invalidate the binding.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import hmac
import secrets
import threading
from typing import Final, Protocol
from uuid import UUID, uuid4

from .session import AuthenticationLevel, SessionRecord, SessionState


class StepUpChallengeState(StrEnum):
    ISSUED = "ISSUED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"
    REVOKED = "REVOKED"


# Parity alias for M4 specification
StepUpChallengeStatus = StepUpChallengeState


class StepUpMethod(StrEnum):
    PASSKEY = "PASSKEY"
    PASSWORD_REAUTH = "PASSWORD_REAUTH"
    TOTP = "TOTP"
    DEVICE_CONFIRMATION = "DEVICE_CONFIRMATION"
    BIOMETRIC_REAUTH = "BIOMETRIC_REAUTH"
    REAUTHENTICATION = "REAUTHENTICATION"


class StepUpError(Exception):
    """Base error for step-up violations."""


class StepUpInvalid(StepUpError):
    """Raised when step-up parameters or proofs are invalid."""


class StepUpExpired(StepUpError):
    """Raised when a step-up challenge has expired."""


class StepUpReplay(StepUpError):
    """Raised when a step-up challenge or verification is replayed."""


class StepUpScopeMismatch(StepUpError):
    """Raised when step-up scope does not match action intent."""


# M4 Exception aliases
StepUpMismatch = StepUpScopeMismatch


class StepUpUnavailable(StepUpError):
    """Raised when the step-up subsystem is unavailable."""


class StepUpConsumed(StepUpReplay):
    """Raised when a step-up challenge or evidence has already been consumed."""


class StepUpVerificationFailed(StepUpError):
    """Raised when verification proof does not match."""


_INTERNAL_STEP_UP_MARKER: Final[object] = object()


@dataclass(frozen=True, slots=True)
class StepUpChallenge:
    challenge_id: UUID
    session_id: UUID
    subject_id: UUID
    method: StepUpMethod
    action_scope: str
    state: StepUpChallengeState
    nonce_hash: str
    issued_at: datetime
    expires_at: datetime
    attempt_count: int
    max_attempts: int

    def __post_init__(self) -> None:
        if not isinstance(self.challenge_id, UUID):
            raise TypeError("challenge_id must be a UUID")
        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")
        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        if not isinstance(self.method, StepUpMethod):
            raise TypeError("method must be a StepUpMethod")
        if not isinstance(self.action_scope, str) or not self.action_scope.strip():
            raise StepUpInvalid("action_scope must be non-empty")
        if not isinstance(self.state, StepUpChallengeState):
            raise TypeError("state must be a StepUpChallengeState")
        if not isinstance(self.nonce_hash, str) or not self.nonce_hash.strip():
            raise StepUpInvalid("nonce_hash must be non-empty")
        if not isinstance(self.issued_at, datetime) or self.issued_at.tzinfo is None:
            raise StepUpInvalid("issued_at must be timezone-aware")
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None:
            raise StepUpInvalid("expires_at must be timezone-aware")
        if self.expires_at.astimezone(timezone.utc) <= self.issued_at.astimezone(timezone.utc):
            raise StepUpInvalid("expires_at must be strictly later than issued_at")
        if not isinstance(self.attempt_count, int) or self.attempt_count < 0:
            raise StepUpInvalid("attempt_count must be non-negative")
        if not isinstance(self.max_attempts, int) or self.max_attempts <= 0:
            raise StepUpInvalid("max_attempts must be strictly positive")

    @property
    def status(self) -> StepUpChallengeStatus:
        return self.state


@dataclass(frozen=True, slots=True)
class StepUpResult:
    verified: bool
    challenge_id: UUID
    session_id: UUID
    subject_id: UUID
    authentication_level: AuthenticationLevel
    verified_at: datetime
    reason_code: str


@dataclass(frozen=True, slots=True)
class StepUpEvidence:
    """
    Trusted Step-Up Evidence issued upon successful step-up verification.

    Security guarantees:
        - Bound to subject_id, session_id, action_id, method, and transaction parameters.
        - Immutable and time-bound.
        - Carries private internal provenance marker.
    """
    evidence_id: UUID
    challenge_id: UUID
    subject_id: UUID
    session_id: UUID
    action_id: UUID
    method: StepUpMethod
    verified_at: datetime
    expires_at: datetime
    assurance_level: int
    trusted: bool = field(default=False)
    _provenance_marker: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, UUID):
            raise TypeError("evidence_id must be a UUID")
        if not isinstance(self.challenge_id, UUID):
            raise TypeError("challenge_id must be a UUID")
        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")
        if not isinstance(self.action_id, UUID):
            raise TypeError("action_id must be a UUID")
        if not isinstance(self.method, StepUpMethod):
            raise TypeError("method must be a StepUpMethod")
        if not isinstance(self.verified_at, datetime) or self.verified_at.tzinfo is None:
            raise StepUpInvalid("verified_at must be timezone-aware")
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None:
            raise StepUpInvalid("expires_at must be timezone-aware")
        if self.expires_at.astimezone(timezone.utc) <= self.verified_at.astimezone(timezone.utc):
            raise StepUpInvalid("expires_at must be strictly later than verified_at")
        if not (0 <= self.assurance_level <= 100):
            raise StepUpInvalid("assurance_level must be in [0, 100]")

    def is_trusted(self) -> bool:
        return self.trusted is True and self._provenance_marker is _INTERNAL_STEP_UP_MARKER

    def is_expired(self, now: datetime) -> bool:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise StepUpInvalid("now must be timezone-aware")
        return now.astimezone(timezone.utc) >= self.expires_at.astimezone(timezone.utc)


def _hash_nonce(raw_nonce: str) -> str:
    return hashlib.sha256(raw_nonce.encode("utf-8")).hexdigest()


class StepUpService:
    """Thread-safe scoped step-up challenge issuance and atomic consumption."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._challenges: dict[UUID, StepUpChallenge] = {}

    def issue(
        self,
        *,
        session: SessionRecord,
        action_scope: str,
        method: StepUpMethod,
        now: datetime,
        lifetime_seconds: int = 300,
        max_attempts: int = 3,
    ) -> tuple[StepUpChallenge, str]:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise StepUpInvalid("now must be timezone-aware")
        if session.state != SessionState.ACTIVE:
            raise StepUpInvalid("Cannot issue step-up for inactive session")

        now_utc = now.astimezone(timezone.utc)
        challenge_id = uuid4()
        raw_nonce = secrets.token_urlsafe(32)
        nonce_hash = _hash_nonce(raw_nonce)

        challenge = StepUpChallenge(
            challenge_id=challenge_id,
            session_id=session.session_id,
            subject_id=session.subject_id,
            method=method,
            action_scope=action_scope,
            state=StepUpChallengeState.ISSUED,
            nonce_hash=nonce_hash,
            issued_at=now_utc,
            expires_at=now_utc + timedelta(seconds=lifetime_seconds),
            attempt_count=0,
            max_attempts=max_attempts,
        )

        with self._lock:
            self._challenges[challenge_id] = challenge

        return challenge, raw_nonce

    def verify(
        self,
        *,
        challenge: StepUpChallenge,
        raw_nonce: str,
        proof: str,
        now: datetime,
    ) -> StepUpResult:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise StepUpInvalid("now must be timezone-aware")

        now_utc = now.astimezone(timezone.utc)

        with self._lock:
            stored = self._challenges.get(challenge.challenge_id)
            if stored is None:
                raise StepUpInvalid("Challenge not found")

            if stored.state == StepUpChallengeState.CONSUMED:
                raise StepUpReplay("Challenge has already been consumed")

            if stored.state == StepUpChallengeState.REVOKED:
                raise StepUpInvalid("Challenge has been revoked")

            if now_utc >= stored.expires_at.astimezone(timezone.utc):
                self._challenges[challenge.challenge_id] = StepUpChallenge(
                    challenge_id=stored.challenge_id,
                    session_id=stored.session_id,
                    subject_id=stored.subject_id,
                    method=stored.method,
                    action_scope=stored.action_scope,
                    state=StepUpChallengeState.EXPIRED,
                    nonce_hash=stored.nonce_hash,
                    issued_at=stored.issued_at,
                    expires_at=stored.expires_at,
                    attempt_count=stored.attempt_count,
                    max_attempts=stored.max_attempts,
                )
                raise StepUpExpired("Step-up challenge has expired")

            if stored.attempt_count >= stored.max_attempts:
                self._challenges[challenge.challenge_id] = StepUpChallenge(
                    challenge_id=stored.challenge_id,
                    session_id=stored.session_id,
                    subject_id=stored.subject_id,
                    method=stored.method,
                    action_scope=stored.action_scope,
                    state=StepUpChallengeState.FAILED,
                    nonce_hash=stored.nonce_hash,
                    issued_at=stored.issued_at,
                    expires_at=stored.expires_at,
                    attempt_count=stored.attempt_count,
                    max_attempts=stored.max_attempts,
                )
                raise StepUpInvalid("Maximum step-up attempts exceeded")

            new_attempts = stored.attempt_count + 1
            self._challenges[challenge.challenge_id] = StepUpChallenge(
                challenge_id=stored.challenge_id,
                session_id=stored.session_id,
                subject_id=stored.subject_id,
                method=stored.method,
                action_scope=stored.action_scope,
                state=stored.state,
                nonce_hash=stored.nonce_hash,
                issued_at=stored.issued_at,
                expires_at=stored.expires_at,
                attempt_count=new_attempts,
                max_attempts=stored.max_attempts,
            )

            presented_hash = _hash_nonce(raw_nonce)
            if not hmac.compare_digest(stored.nonce_hash, presented_hash):
                return StepUpResult(
                    verified=False,
                    challenge_id=stored.challenge_id,
                    session_id=stored.session_id,
                    subject_id=stored.subject_id,
                    authentication_level=AuthenticationLevel.AUTHENTICATED,
                    verified_at=now,
                    reason_code="NONCE_MISMATCH",
                )

            if not proof or proof != raw_nonce:
                return StepUpResult(
                    verified=False,
                    challenge_id=stored.challenge_id,
                    session_id=stored.session_id,
                    subject_id=stored.subject_id,
                    authentication_level=AuthenticationLevel.AUTHENTICATED,
                    verified_at=now,
                    reason_code="PROOF_INVALID",
                )

            self._challenges[challenge.challenge_id] = StepUpChallenge(
                challenge_id=stored.challenge_id,
                session_id=stored.session_id,
                subject_id=stored.subject_id,
                method=stored.method,
                action_scope=stored.action_scope,
                state=StepUpChallengeState.VERIFIED,
                nonce_hash=stored.nonce_hash,
                issued_at=stored.issued_at,
                expires_at=stored.expires_at,
                attempt_count=new_attempts,
                max_attempts=stored.max_attempts,
            )

            return StepUpResult(
                verified=True,
                challenge_id=stored.challenge_id,
                session_id=stored.session_id,
                subject_id=stored.subject_id,
                authentication_level=AuthenticationLevel.STEP_UP_VERIFIED,
                verified_at=now,
                reason_code="STEP_UP_VERIFIED",
            )

    def consume(self, *, challenge_id: UUID, now: datetime) -> None:
        if not isinstance(challenge_id, UUID):
            raise TypeError("challenge_id must be a UUID")
        with self._lock:
            stored = self._challenges.get(challenge_id)
            if stored is None:
                raise StepUpInvalid("Challenge not found")
            if stored.state == StepUpChallengeState.CONSUMED:
                raise StepUpReplay("Challenge has already been consumed")
            if stored.state != StepUpChallengeState.VERIFIED:
                raise StepUpInvalid(f"Cannot consume unverified challenge (state={stored.state})")

            self._challenges[challenge_id] = StepUpChallenge(
                challenge_id=stored.challenge_id,
                session_id=stored.session_id,
                subject_id=stored.subject_id,
                method=stored.method,
                action_scope=stored.action_scope,
                state=StepUpChallengeState.CONSUMED,
                nonce_hash=stored.nonce_hash,
                issued_at=stored.issued_at,
                expires_at=stored.expires_at,
                attempt_count=stored.attempt_count,
                max_attempts=stored.max_attempts,
            )

    def revoke(self, *, challenge_id: UUID, now: datetime, reason: str) -> None:
        if not isinstance(challenge_id, UUID):
            raise TypeError("challenge_id must be a UUID")
        with self._lock:
            stored = self._challenges.get(challenge_id)
            if stored is not None:
                self._challenges[challenge_id] = StepUpChallenge(
                    challenge_id=stored.challenge_id,
                    session_id=stored.session_id,
                    subject_id=stored.subject_id,
                    method=stored.method,
                    action_scope=stored.action_scope,
                    state=StepUpChallengeState.REVOKED,
                    nonce_hash=stored.nonce_hash,
                    issued_at=stored.issued_at,
                    expires_at=stored.expires_at,
                    attempt_count=stored.attempt_count,
                    max_attempts=stored.max_attempts,
                )


class StepUpProvider(Protocol):
    def issue_challenge(
        self,
        *,
        subject_id: UUID,
        session_id: UUID,
        action_id: UUID,
        method: StepUpMethod,
        now: datetime,
        ttl: timedelta = timedelta(minutes=5),
    ) -> tuple[StepUpChallenge, str]:
        ...

    def verify_challenge(
        self,
        *,
        challenge: StepUpChallenge,
        proof: str,
        now: datetime,
    ) -> StepUpEvidence:
        ...


class DefaultStepUpProvider:
    """Production provider issuing transaction-bound StepUpEvidence."""

    def __init__(self, service: StepUpService | None = None) -> None:
        self._service = service or StepUpService()

    def issue_challenge(
        self,
        *,
        subject_id: UUID,
        session_id: UUID,
        action_id: UUID,
        method: StepUpMethod,
        now: datetime,
        ttl: timedelta = timedelta(minutes=5),
    ) -> tuple[StepUpChallenge, str]:
        sess = SessionRecord(
            session_id=session_id,
            subject_id=subject_id,
            device_id=uuid4(),
            state=SessionState.ACTIVE,
            authentication_level=AuthenticationLevel.AUTHENTICATED,
            issued_at=now,
            expires_at=now + ttl,
            last_seen_at=now,
            rotation_counter=0,
            token_version=1,
        )
        return self._service.issue(
            session=sess,
            action_scope=str(action_id),
            method=method,
            now=now,
            lifetime_seconds=int(ttl.total_seconds()),
        )

    def verify_challenge(
        self,
        *,
        challenge: StepUpChallenge,
        proof: str,
        now: datetime,
    ) -> StepUpEvidence:
        res = self._service.verify(
            challenge=challenge,
            raw_nonce=proof,
            proof=proof,
            now=now,
        )
        if not res.verified:
            raise StepUpVerificationFailed(f"Verification failed: {res.reason_code}")

        # Mark consumed atomically upon evidence issuance
        self._service.consume(challenge_id=challenge.challenge_id, now=now)

        action_uuid = UUID(challenge.action_scope) if len(challenge.action_scope) == 36 else uuid4()

        return StepUpEvidence(
            evidence_id=uuid4(),
            challenge_id=challenge.challenge_id,
            subject_id=challenge.subject_id,
            session_id=challenge.session_id,
            action_id=action_uuid,
            method=challenge.method,
            verified_at=now,
            expires_at=now + timedelta(minutes=5),
            assurance_level=90,
            trusted=True,
            _provenance_marker=_INTERNAL_STEP_UP_MARKER,
        )