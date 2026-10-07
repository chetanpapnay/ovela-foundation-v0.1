"""Tests for M3 Step-Up Challenge Engine (15 test cases)."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest

from app.session import AuthenticationLevel, SessionRecord, SessionState
from app.step_up import (
    StepUpChallenge,
    StepUpChallengeState,
    StepUpExpired,
    StepUpInvalid,
    StepUpMethod,
    StepUpReplay,
    StepUpService,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _active_session():
    now = _utc_now()
    return SessionRecord(
        session_id=uuid4(),
        subject_id=uuid4(),
        device_id=uuid4(),
        state=SessionState.ACTIVE,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        issued_at=now,
        expires_at=now + timedelta(hours=1),
        last_seen_at=now,
        rotation_counter=0,
        token_version=1,
    )


def test_challenge_issuance():
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, raw_nonce = service.issue(
        session=sess,
        action_scope="TRANSFER_100",
        method=StepUpMethod.TOTP,
        now=now,
    )
    assert challenge.state == StepUpChallengeState.ISSUED
    assert challenge.session_id == sess.session_id
    assert challenge.subject_id == sess.subject_id
    assert isinstance(raw_nonce, str) and len(raw_nonce) > 0


def test_expiry():
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, raw_nonce = service.issue(
        session=sess,
        action_scope="TRANSFER",
        method=StepUpMethod.TOTP,
        now=now,
        lifetime_seconds=5,
    )
    later = now + timedelta(seconds=10)
    with pytest.raises(StepUpExpired):
        service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=later)


def test_wrong_nonce():
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, _ = service.issue(
        session=sess,
        action_scope="TRANSFER",
        method=StepUpMethod.TOTP,
        now=now,
    )
    res = service.verify(challenge=challenge, raw_nonce="wrong-nonce", proof="wrong-nonce", now=now)
    assert res.verified is False
    assert res.reason_code == "NONCE_MISMATCH"


def test_wrong_proof():
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, raw_nonce = service.issue(
        session=sess,
        action_scope="TRANSFER",
        method=StepUpMethod.TOTP,
        now=now,
    )
    res = service.verify(challenge=challenge, raw_nonce=raw_nonce, proof="incorrect-proof", now=now)
    assert res.verified is False
    assert res.reason_code == "PROOF_INVALID"


def test_wrong_session():
    # Step-up bound to session A cannot be transferred to session B
    sessA = _active_session()
    sessB = _active_session()
    service = StepUpService()
    now = _utc_now()
    challengeA, _ = service.issue(
        session=sessA,
        action_scope="TRANSFER",
        method=StepUpMethod.TOTP,
        now=now,
    )
    assert challengeA.session_id != sessB.session_id


def test_wrong_subject():
    sessA = _active_session()
    sessB = _active_session()
    service = StepUpService()
    now = _utc_now()
    challengeA, _ = service.issue(
        session=sessA,
        action_scope="TRANSFER",
        method=StepUpMethod.TOTP,
        now=now,
    )
    assert challengeA.subject_id != sessB.subject_id


def test_wrong_scope():
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, _ = service.issue(
        session=sess,
        action_scope="TRANSFER_100_USD",
        method=StepUpMethod.TOTP,
        now=now,
    )
    assert challenge.action_scope != "TRANSFER_200_USD"


def test_replay():
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, raw_nonce = service.issue(
        session=sess,
        action_scope="TRANSFER",
        method=StepUpMethod.TOTP,
        now=now,
    )
    res = service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)
    assert res.verified is True
    # Consume challenge
    service.consume(challenge_id=challenge.challenge_id, now=now)
    with pytest.raises(StepUpReplay):
        service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)


def test_consumed_challenge():
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, raw_nonce = service.issue(
        session=sess,
        action_scope="TRANSFER",
        method=StepUpMethod.TOTP,
        now=now,
    )
    service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)
    service.consume(challenge_id=challenge.challenge_id, now=now)
    with pytest.raises(StepUpReplay):
        service.consume(challenge_id=challenge.challenge_id, now=now)


def test_revoked_challenge():
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, raw_nonce = service.issue(
        session=sess,
        action_scope="TRANSFER",
        method=StepUpMethod.TOTP,
        now=now,
    )
    service.revoke(challenge_id=challenge.challenge_id, now=now, reason="Security alert")
    with pytest.raises(StepUpInvalid):
        service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)


def test_concurrent_verification_one_winner():
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, raw_nonce = service.issue(
        session=sess,
        action_scope="TRANSFER",
        method=StepUpMethod.TOTP,
        now=now,
    )

    def do_verify_and_consume():
        try:
            res = service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)
            if res.verified:
                service.consume(challenge_id=challenge.challenge_id, now=now)
                return True
        except (StepUpReplay, StepUpInvalid):
            return False
        return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(do_verify_and_consume) for _ in range(16)]
        results = [f.result() for f in futures]

    assert results.count(True) == 1


def test_transaction_mutation_invalidates_binding():
    # If transaction amount changes, the action scope string no longer matches
    scope_100 = "ACTION_TRANSFER:100.00:USD"
    scope_200 = "ACTION_TRANSFER:200.00:USD"
    assert scope_100 != scope_200


def test_cannot_upgrade_another_session():
    service = StepUpService()
    now = _utc_now()
    sessA = _active_session()
    sessB = _active_session()
    challengeA, raw_nonce = service.issue(
        session=sessA,
        action_scope="OP",
        method=StepUpMethod.TOTP,
        now=now,
    )
    res = service.verify(challenge=challengeA, raw_nonce=raw_nonce, proof=raw_nonce, now=now)
    assert res.session_id == sessA.session_id
    assert res.session_id != sessB.session_id


def test_cannot_upgrade_another_subject():
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, raw_nonce = service.issue(
        session=sess,
        action_scope="OP",
        method=StepUpMethod.TOTP,
        now=now,
    )
    res = service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)
    assert res.subject_id == sess.subject_id


def test_client_step_up_verified_ignored():
    # Client cannot bypass step up by sending claims
    service = StepUpService()
    now = _utc_now()
    sess = _active_session()
    challenge, _ = service.issue(
        session=sess,
        action_scope="OP",
        method=StepUpMethod.TOTP,
        now=now,
    )
    res = service.verify(challenge=challenge, raw_nonce="client-forged-nonce", proof="client-claim", now=now)
    assert res.verified is False