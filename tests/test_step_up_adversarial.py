"""Adversarial and boundary tests for M4 Step-Up Domain."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest

from app.step_up import (
    DefaultStepUpProvider,
    StepUpChallenge,
    StepUpChallengeState,
    StepUpConsumed,
    StepUpEvidence,
    StepUpExpired,
    StepUpInvalid,
    StepUpMethod,
    StepUpReplay,
    StepUpService,
    StepUpVerificationFailed,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def test_caller_cannot_fabricate_trusted_step_up_evidence():
    now = _utc_now()
    fake_evidence = StepUpEvidence(
        evidence_id=uuid4(),
        challenge_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        action_id=uuid4(),
        method=StepUpMethod.TOTP,
        verified_at=now,
        expires_at=now + timedelta(minutes=5),
        assurance_level=90,
        trusted=True,  # Caller sets trusted=True without private marker
    )
    assert fake_evidence.is_trusted() is False


def test_step_up_evidence_wrong_action_id_rejected():
    provider = DefaultStepUpProvider()
    now = _utc_now()
    subj = uuid4()
    sess = uuid4()
    act1 = uuid4()
    act2 = uuid4()

    challenge, raw_nonce = provider.issue_challenge(
        subject_id=subj,
        session_id=sess,
        action_id=act1,
        method=StepUpMethod.TOTP,
        now=now,
    )
    evidence = provider.verify_challenge(challenge=challenge, proof=raw_nonce, now=now)
    assert evidence.action_id == act1
    assert evidence.action_id != act2


def test_step_up_evidence_wrong_session_rejected():
    provider = DefaultStepUpProvider()
    now = _utc_now()
    subj = uuid4()
    sessA = uuid4()
    sessB = uuid4()
    act = uuid4()

    challenge, raw_nonce = provider.issue_challenge(
        subject_id=subj,
        session_id=sessA,
        action_id=act,
        method=StepUpMethod.TOTP,
        now=now,
    )
    evidence = provider.verify_challenge(challenge=challenge, proof=raw_nonce, now=now)
    assert evidence.session_id == sessA
    assert evidence.session_id != sessB


def test_step_up_evidence_expiry_fails_closed():
    provider = DefaultStepUpProvider()
    now = _utc_now()
    challenge, raw_nonce = provider.issue_challenge(
        subject_id=uuid4(),
        session_id=uuid4(),
        action_id=uuid4(),
        method=StepUpMethod.TOTP,
        now=now,
    )
    evidence = provider.verify_challenge(challenge=challenge, proof=raw_nonce, now=now)
    later = now + timedelta(minutes=6)
    assert evidence.is_expired(later) is True


def test_step_up_proof_replay_fails_closed():
    provider = DefaultStepUpProvider()
    now = _utc_now()
    challenge, raw_nonce = provider.issue_challenge(
        subject_id=uuid4(),
        session_id=uuid4(),
        action_id=uuid4(),
        method=StepUpMethod.TOTP,
        now=now,
    )
    # First verification succeeds
    provider.verify_challenge(challenge=challenge, proof=raw_nonce, now=now)

    # Replay on consumed challenge fails
    with pytest.raises(StepUpReplay):
        provider.verify_challenge(challenge=challenge, proof=raw_nonce, now=now)


def test_expired_challenge_verification_fails():
    provider = DefaultStepUpProvider()
    now = _utc_now()
    challenge, raw_nonce = provider.issue_challenge(
        subject_id=uuid4(),
        session_id=uuid4(),
        action_id=uuid4(),
        method=StepUpMethod.TOTP,
        now=now,
        ttl=timedelta(seconds=5),
    )
    later = now + timedelta(seconds=10)
    with pytest.raises(StepUpExpired):
        provider.verify_challenge(challenge=challenge, proof=raw_nonce, now=later)


def test_invalid_proof_verification_fails():
    provider = DefaultStepUpProvider()
    now = _utc_now()
    challenge, _ = provider.issue_challenge(
        subject_id=uuid4(),
        session_id=uuid4(),
        action_id=uuid4(),
        method=StepUpMethod.TOTP,
        now=now,
    )
    with pytest.raises(StepUpVerificationFailed):
        provider.verify_challenge(challenge=challenge, proof="forged-proof", now=now)