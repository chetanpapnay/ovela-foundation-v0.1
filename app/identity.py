"""
OVELA / JURIX Real Identity Core.

Security principle:
    Recognition is not authentication.
    Identity claims are untrusted evidence until verified by the trusted core.
    Missing, malformed, expired, replayed, or suspicious evidence fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Protocol
from uuid import UUID


class IdentityState(StrEnum):
    UNKNOWN = "UNKNOWN"
    UNVERIFIED = "UNVERIFIED"
    RECOGNIZED = "RECOGNIZED"
    AUTHENTICATED = "AUTHENTICATED"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    OWNER_VERIFIED = "OWNER_VERIFIED"
    SESSION_EXPIRED = "SESSION_EXPIRED"
    SUSPICIOUS = "SUSPICIOUS"


class IdentityEvidenceKind(StrEnum):
    DEVICE_ASSOCIATION = "DEVICE_ASSOCIATION"
    FACE_RECOGNITION = "FACE_RECOGNITION"
    VOICE_RECOGNITION = "VOICE_RECOGNITION"
    DOCUMENT_REFERENCE = "DOCUMENT_REFERENCE"
    AUTHENTICATOR_ASSERTION = "AUTHENTICATOR_ASSERTION"
    PASSKEY_ASSERTION = "PASSKEY_ASSERTION"
    PASSWORD_VERIFICATION = "PASSWORD_VERIFICATION"
    STEP_UP_ASSERTION = "STEP_UP_ASSERTION"


class IdentityError(Exception):
    """Base error for identity boundary violations."""


class IdentityInvalid(IdentityError):
    """Raised when identity evidence violates data invariants."""


class IdentityNotFound(IdentityError):
    """Raised when a referenced subject cannot be resolved."""


class IdentitySuspicious(IdentityError):
    """Raised when identity evaluation detects tampering or anomaly."""


@dataclass(frozen=True, slots=True)
class IdentitySubject:
    subject_id: UUID
    display_name: str
    state: IdentityState
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        if not isinstance(self.display_name, str) or not self.display_name.strip():
            raise IdentityInvalid("display_name must be a non-empty string")
        if not isinstance(self.state, IdentityState):
            raise TypeError("state must be an IdentityState")
        if not isinstance(self.created_at, datetime) or self.created_at.tzinfo is None:
            raise IdentityInvalid("created_at must be a timezone-aware datetime")
        if not isinstance(self.updated_at, datetime) or self.updated_at.tzinfo is None:
            raise IdentityInvalid("updated_at must be a timezone-aware datetime")
        if self.updated_at.astimezone(timezone.utc) < self.created_at.astimezone(timezone.utc):
            raise IdentityInvalid("updated_at cannot be earlier than created_at")


@dataclass(frozen=True, slots=True)
class IdentityEvidence:
    evidence_id: UUID
    subject_id: UUID
    kind: IdentityEvidenceKind
    confidence: float
    observed_at: datetime
    expires_at: datetime | None
    trusted: bool

    def __post_init__(self) -> None:
        if not isinstance(self.evidence_id, UUID):
            raise TypeError("evidence_id must be a UUID")
        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        if not isinstance(self.kind, IdentityEvidenceKind):
            raise TypeError("kind must be an IdentityEvidenceKind")
        if not isinstance(self.confidence, (int, float)):
            raise TypeError("confidence must be a float")
        if not (0.0 <= float(self.confidence) <= 1.0):
            raise IdentityInvalid("confidence must be between 0.0 and 1.0")
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None:
            raise IdentityInvalid("observed_at must be a timezone-aware datetime")
        if self.expires_at is not None:
            if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None:
                raise IdentityInvalid("expires_at must be a timezone-aware datetime")
            if self.expires_at.astimezone(timezone.utc) <= self.observed_at.astimezone(timezone.utc):
                raise IdentityInvalid("expires_at must be strictly later than observed_at")
        if not isinstance(self.trusted, bool):
            raise TypeError("trusted must be a bool")


@dataclass(frozen=True, slots=True)
class IdentityEvaluation:
    subject_id: UUID | None
    state: IdentityState
    evidence_ids: tuple[UUID, ...]
    evaluated_at: datetime
    reason_code: str


class IdentityEvaluator(Protocol):
    def evaluate(
        self,
        *,
        evidence: tuple[IdentityEvidence, ...],
        now: datetime,
    ) -> IdentityEvaluation:
        ...


class DefaultIdentityEvaluator:
    """
    Fail-closed evaluator of identity evidence.

    Non-negotiable rule:
    Biometrics or recognition evidence (voice, face, device association)
    can at most establish RECOGNIZED. They can never independently mint
    AUTHENTICATED, OWNER_VERIFIED, or STEP_UP_VERIFIED.
    """

    __slots__ = ()

    def evaluate(
        self,
        *,
        evidence: tuple[IdentityEvidence, ...],
        now: datetime,
    ) -> IdentityEvaluation:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise IdentityInvalid("now must be a timezone-aware datetime")

        now_utc = now.astimezone(timezone.utc)

        if not evidence:
            return IdentityEvaluation(
                subject_id=None,
                state=IdentityState.UNKNOWN,
                evidence_ids=(),
                evaluated_at=now,
                reason_code="NO_IDENTITY",
            )

        # Filter out expired or untrusted evidence
        valid_evidences: list[IdentityEvidence] = []
        subject_ids: set[UUID] = set()

        for ev in evidence:
            if not isinstance(ev, IdentityEvidence):
                return IdentityEvaluation(
                    subject_id=None,
                    state=IdentityState.UNKNOWN,
                    evidence_ids=(),
                    evaluated_at=now,
                    reason_code="INVALID_EVIDENCE",
                )

            # Fail closed on future-dated anomaly
            if ev.observed_at.astimezone(timezone.utc) > now_utc:
                return IdentityEvaluation(
                    subject_id=None,
                    state=IdentityState.SUSPICIOUS,
                    evidence_ids=(ev.evidence_id,),
                    evaluated_at=now,
                    reason_code="SUSPICIOUS_EVIDENCE",
                )

            # Check expiry
            if ev.expires_at is not None and now_utc >= ev.expires_at.astimezone(timezone.utc):
                continue

            # Untrusted evidence cannot establish identity
            if not ev.trusted:
                continue

            valid_evidences.append(ev)
            subject_ids.add(ev.subject_id)

        if not valid_evidences:
            return IdentityEvaluation(
                subject_id=None,
                state=IdentityState.UNKNOWN,
                evidence_ids=(),
                evaluated_at=now,
                reason_code="NO_IDENTITY",
            )

        # Ambiguous identity evidence across multiple subjects fails closed as SUSPICIOUS
        if len(subject_ids) > 1:
            return IdentityEvaluation(
                subject_id=None,
                state=IdentityState.SUSPICIOUS,
                evidence_ids=tuple(e.evidence_id for e in valid_evidences),
                evaluated_at=now,
                reason_code="SUSPICIOUS_EVIDENCE",
            )

        target_subject_id = next(iter(subject_ids))
        kinds = {e.kind for e in valid_evidences}
        valid_ids = tuple(e.evidence_id for e in valid_evidences)

        # Recognition kinds (face, voice, device association) never grant AUTHENTICATED
        recognition_only = kinds.issubset({
            IdentityEvidenceKind.DEVICE_ASSOCIATION,
            IdentityEvidenceKind.FACE_RECOGNITION,
            IdentityEvidenceKind.VOICE_RECOGNITION,
            IdentityEvidenceKind.DOCUMENT_REFERENCE,
        })

        if recognition_only:
            return IdentityEvaluation(
                subject_id=target_subject_id,
                state=IdentityState.RECOGNIZED,
                evidence_ids=valid_ids,
                evaluated_at=now,
                reason_code="RECOGNIZED_ONLY",
            )

        # Authentication assertion evidence
        if IdentityEvidenceKind.PASSWORD_VERIFICATION in kinds or IdentityEvidenceKind.PASSKEY_ASSERTION in kinds:
            return IdentityEvaluation(
                subject_id=target_subject_id,
                state=IdentityState.AUTHENTICATED,
                evidence_ids=valid_ids,
                evaluated_at=now,
                reason_code="AUTHENTICATED_SESSION",
            )

        return IdentityEvaluation(
            subject_id=target_subject_id,
            state=IdentityState.UNVERIFIED,
            evidence_ids=valid_ids,
            evaluated_at=now,
            reason_code="AUTHENTICATION_REQUIRED",
        )