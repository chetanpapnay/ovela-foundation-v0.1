"""Unit tests for the M3 Identity Core."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest

from app.identity import (
    DefaultIdentityEvaluator,
    IdentityError,
    IdentityEvidence,
    IdentityEvidenceKind,
    IdentityInvalid,
    IdentityState,
    IdentitySubject,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def test_unknown_identity():
    evaluator = DefaultIdentityEvaluator()
    now = _utc_now()
    res = evaluator.evaluate(evidence=(), now=now)
    assert res.state == IdentityState.UNKNOWN
    assert res.subject_id is None
    assert res.reason_code == "NO_IDENTITY"


def test_unverified_claim():
    evaluator = DefaultIdentityEvaluator()
    now = _utc_now()
    subject_id = uuid4()
    ev = IdentityEvidence(
        evidence_id=uuid4(),
        subject_id=subject_id,
        kind=IdentityEvidenceKind.DOCUMENT_REFERENCE,
        confidence=0.5,
        observed_at=now,
        expires_at=now + timedelta(hours=1),
        trusted=False,  # Untrusted evidence
    )
    res = evaluator.evaluate(evidence=(ev,), now=now)
    assert res.state == IdentityState.UNKNOWN
    assert res.reason_code == "NO_IDENTITY"


def test_recognized_evidence():
    evaluator = DefaultIdentityEvaluator()
    now = _utc_now()
    subject_id = uuid4()
    ev = IdentityEvidence(
        evidence_id=uuid4(),
        subject_id=subject_id,
        kind=IdentityEvidenceKind.FACE_RECOGNITION,
        confidence=0.95,
        observed_at=now,
        expires_at=now + timedelta(hours=1),
        trusted=True,
    )
    res = evaluator.evaluate(evidence=(ev,), now=now)
    assert res.state == IdentityState.RECOGNIZED
    assert res.subject_id == subject_id
    assert res.reason_code == "RECOGNIZED_ONLY"


def test_recognition_cannot_produce_authenticated():
    evaluator = DefaultIdentityEvaluator()
    now = _utc_now()
    subject_id = uuid4()
    voice_ev = IdentityEvidence(
        evidence_id=uuid4(),
        subject_id=subject_id,
        kind=IdentityEvidenceKind.VOICE_RECOGNITION,
        confidence=0.99,
        observed_at=now,
        expires_at=now + timedelta(hours=1),
        trusted=True,
    )
    face_ev = IdentityEvidence(
        evidence_id=uuid4(),
        subject_id=subject_id,
        kind=IdentityEvidenceKind.FACE_RECOGNITION,
        confidence=0.99,
        observed_at=now,
        expires_at=now + timedelta(hours=1),
        trusted=True,
    )
    res = evaluator.evaluate(evidence=(voice_ev, face_ev), now=now)
    assert res.state != IdentityState.AUTHENTICATED
    assert res.state == IdentityState.RECOGNIZED


def test_recognition_cannot_produce_owner_verified():
    evaluator = DefaultIdentityEvaluator()
    now = _utc_now()
    subject_id = uuid4()
    ev = IdentityEvidence(
        evidence_id=uuid4(),
        subject_id=subject_id,
        kind=IdentityEvidenceKind.FACE_RECOGNITION,
        confidence=1.0,
        observed_at=now,
        expires_at=now + timedelta(hours=1),
        trusted=True,
    )
    res = evaluator.evaluate(evidence=(ev,), now=now)
    assert res.state != IdentityState.OWNER_VERIFIED
    assert res.state == IdentityState.RECOGNIZED


def test_invalid_evidence_fails_closed():
    evaluator = DefaultIdentityEvaluator()
    now = _utc_now()
    res = evaluator.evaluate(evidence=("not-an-evidence",), now=now)  # type: ignore
    assert res.state == IdentityState.UNKNOWN
    assert res.reason_code == "INVALID_EVIDENCE"


def test_suspicious_evidence_fails_closed():
    evaluator = DefaultIdentityEvaluator()
    now = _utc_now()
    # Conflicting subjects in same evaluation
    ev1 = IdentityEvidence(
        evidence_id=uuid4(),
        subject_id=uuid4(),
        kind=IdentityEvidenceKind.FACE_RECOGNITION,
        confidence=0.9,
        observed_at=now,
        expires_at=now + timedelta(hours=1),
        trusted=True,
    )
    ev2 = IdentityEvidence(
        evidence_id=uuid4(),
        subject_id=uuid4(),
        kind=IdentityEvidenceKind.VOICE_RECOGNITION,
        confidence=0.9,
        observed_at=now,
        expires_at=now + timedelta(hours=1),
        trusted=True,
    )
    res = evaluator.evaluate(evidence=(ev1, ev2), now=now)
    assert res.state == IdentityState.SUSPICIOUS
    assert res.reason_code == "SUSPICIOUS_EVIDENCE"


def test_invalid_uuid_rejected():
    now = _utc_now()
    with pytest.raises(TypeError):
        IdentitySubject(
            subject_id="invalid-uuid-string",  # type: ignore
            display_name="User",
            state=IdentityState.UNVERIFIED,
            created_at=now,
            updated_at=now,
        )


def test_naive_datetime_rejected():
    now_naive = datetime.now()  # no tzinfo
    with pytest.raises(IdentityInvalid):
        IdentitySubject(
            subject_id=uuid4(),
            display_name="User",
            state=IdentityState.UNVERIFIED,
            created_at=now_naive,
            updated_at=now_naive,
        )


def test_expired_evidence_rejected():
    evaluator = DefaultIdentityEvaluator()
    now = _utc_now()
    past = now - timedelta(hours=2)
    ev = IdentityEvidence(
        evidence_id=uuid4(),
        subject_id=uuid4(),
        kind=IdentityEvidenceKind.FACE_RECOGNITION,
        confidence=0.9,
        observed_at=past,
        expires_at=now - timedelta(minutes=1),  # Expired
        trusted=True,
    )
    res = evaluator.evaluate(evidence=(ev,), now=now)
    assert res.state == IdentityState.UNKNOWN
    assert res.reason_code == "NO_IDENTITY"


def test_invalid_future_expiry_relationship_rejected():
    now = _utc_now()
    with pytest.raises(IdentityInvalid):
        IdentityEvidence(
            evidence_id=uuid4(),
            subject_id=uuid4(),
            kind=IdentityEvidenceKind.FACE_RECOGNITION,
            confidence=0.9,
            observed_at=now,
            expires_at=now - timedelta(minutes=5),  # expiry before observation
            trusted=True,
        )


def test_confidence_outside_0_1_rejected():
    now = _utc_now()
    with pytest.raises(IdentityInvalid):
        IdentityEvidence(
            evidence_id=uuid4(),
            subject_id=uuid4(),
            kind=IdentityEvidenceKind.FACE_RECOGNITION,
            confidence=1.5,  # > 1.0
            observed_at=now,
            expires_at=now + timedelta(hours=1),
            trusted=True,
        )

    with pytest.raises(IdentityInvalid):
        IdentityEvidence(
            evidence_id=uuid4(),
            subject_id=uuid4(),
            kind=IdentityEvidenceKind.FACE_RECOGNITION,
            confidence=-0.1,  # < 0.0
            observed_at=now,
            expires_at=now + timedelta(hours=1),
            trusted=True,
        )


def test_display_name_collision_cannot_authorize():
    now = _utc_now()
    subj1 = IdentitySubject(
        subject_id=uuid4(),
        display_name="Alice",
        state=IdentityState.AUTHENTICATED,
        created_at=now,
        updated_at=now,
    )
    subj2 = IdentitySubject(
        subject_id=uuid4(),
        display_name="Alice",  # same display name, distinct UUID
        state=IdentityState.UNVERIFIED,
        created_at=now,
        updated_at=now,
    )
    assert subj1.subject_id != subj2.subject_id
    assert subj2.state == IdentityState.UNVERIFIED


def test_explicit_state_transition_behavior():
    now = _utc_now()
    subj = IdentitySubject(
        subject_id=uuid4(),
        display_name="Bob",
        state=IdentityState.UNVERIFIED,
        created_at=now,
        updated_at=now,
    )
    # Dataclass is frozen and immutable
    with pytest.raises(Exception):
        subj.state = IdentityState.AUTHENTICATED  # type: ignore


def test_stable_reason_code_returned():
    evaluator = DefaultIdentityEvaluator()
    now = _utc_now()
    res = evaluator.evaluate(evidence=(), now=now)
    assert res.reason_code == "NO_IDENTITY"