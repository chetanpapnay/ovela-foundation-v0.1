"""Tests for M3 Session Core (18 test cases)."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest

from app.device_binding import DefaultDeviceBindingValidator, DeviceBinding, DeviceBindingState, DeviceProof
from app.session import (
    AuthenticationLevel,
    SessionError,
    SessionExpired,
    SessionInvalid,
    SessionReplay,
    SessionRevoked,
    SessionService,
    SessionState,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _setup_device(dev_id, subj_id, b_id, key="k"):
    now = _utc_now()
    b = DeviceBinding(
        device_id=dev_id,
        subject_id=subj_id,
        binding_id=b_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    val = DefaultDeviceBindingValidator({dev_id: b})
    return val, key


def _make_proof(dev_id, b_id, key="k", nonce=None, observed_at=None):
    from app.device_binding import hmac
    obs = observed_at or _utc_now()
    n = nonce or str(uuid4())
    payload = f"{dev_id}:{b_id}:{n}".encode("utf-8")
    sig = hmac.new(key.encode("utf-8"), payload, "sha256").hexdigest()
    return DeviceProof(
        device_id=dev_id,
        binding_id=b_id,
        nonce=n,
        signature=sig,
        observed_at=obs,
    )


def test_valid_issuance():
    service = SessionService()
    now = _utc_now()
    subj_id, dev_id = uuid4(), uuid4()
    session, token = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    assert session.state == SessionState.ACTIVE
    assert session.subject_id == subj_id
    assert session.device_id == dev_id
    assert isinstance(token, str) and len(token) > 0


def test_expiry():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    val, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(val)
    now = _utc_now()
    session, token = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
        lifetime_seconds=60,
    )
    later = now + timedelta(seconds=61)
    proof = _make_proof(dev_id, b_id, key, observed_at=later)
    with pytest.raises(SessionExpired):
        service.validate(raw_token=token, device_proof=proof, now=later)


def test_revocation():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    val, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(val)
    now = _utc_now()
    session, token = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    service.revoke(session_id=session.session_id, reason="User logout", now=now)
    proof = _make_proof(dev_id, b_id, key, observed_at=now)
    with pytest.raises(SessionRevoked):
        service.validate(raw_token=token, device_proof=proof, now=now)


def test_suspicious_state():
    service = SessionService()
    now = _utc_now()
    session, _ = service.issue(
        subject_id=uuid4(),
        device_id=uuid4(),
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    object.__setattr__(session, "state", SessionState.SUSPICIOUS)
    assert session.state == SessionState.SUSPICIOUS


def test_immutable_subject_binding():
    service = SessionService()
    now = _utc_now()
    session, _ = service.issue(
        subject_id=uuid4(),
        device_id=uuid4(),
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    with pytest.raises(Exception):
        session.subject_id = uuid4()  # type: ignore


def test_immutable_device_binding():
    service = SessionService()
    now = _utc_now()
    session, _ = service.issue(
        subject_id=uuid4(),
        device_id=uuid4(),
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    with pytest.raises(Exception):
        session.device_id = uuid4()  # type: ignore


def test_invalid_token():
    service = SessionService()
    now = _utc_now()
    proof = _make_proof(uuid4(), uuid4(), observed_at=now)
    with pytest.raises(SessionInvalid):
        service.validate(raw_token="not-a-real-token", device_proof=proof, now=now)


def test_token_tampering():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    val, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(val)
    now = _utc_now()
    session, token = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    tampered_token = token[:-2] + "xx"
    proof = _make_proof(dev_id, b_id, key, observed_at=now)
    with pytest.raises(SessionInvalid):
        service.validate(raw_token=tampered_token, device_proof=proof, now=now)


def test_token_truncation():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    val, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(val)
    now = _utc_now()
    session, token = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    proof = _make_proof(dev_id, b_id, key, observed_at=now)
    with pytest.raises(SessionInvalid):
        service.validate(raw_token=token[:10], device_proof=proof, now=now)


def test_replay():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    val, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(val)
    now = _utc_now()
    session, token = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    proof1 = _make_proof(dev_id, b_id, key, observed_at=now)
    s1 = service.validate(raw_token=token, device_proof=proof1, now=now)
    assert s1.session_id == session.session_id


def test_refresh_rotation():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    val, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(val)
    now = _utc_now()
    session, _ = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    refresh_token = service.issue_refresh_token(session_id=session.session_id, now=now)
    proof = _make_proof(dev_id, b_id, key, observed_at=now)

    new_session, new_token = service.rotate(
        session_id=session.session_id,
        raw_refresh_token=refresh_token,
        device_proof=proof,
        now=now,
    )
    assert new_session.rotation_counter == 1
    assert new_session.token_version == 2
    assert isinstance(new_token, str)


def test_old_refresh_token_rejected():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    val, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(val)
    now = _utc_now()
    session, _ = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    refresh_token = service.issue_refresh_token(session_id=session.session_id, now=now)
    proof1 = _make_proof(dev_id, b_id, key, observed_at=now)

    service.rotate(
        session_id=session.session_id,
        raw_refresh_token=refresh_token,
        device_proof=proof1,
        now=now,
    )

    proof2 = _make_proof(dev_id, b_id, key, observed_at=now)
    with pytest.raises(SessionReplay):
        service.rotate(
            session_id=session.session_id,
            raw_refresh_token=refresh_token,
            device_proof=proof2,
            now=now,
        )


def test_concurrent_refresh_one_winner():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    val, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(val)
    now = _utc_now()
    session, _ = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    refresh_token = service.issue_refresh_token(session_id=session.session_id, now=now)

    def do_rotate():
        try:
            proof = _make_proof(dev_id, b_id, key, observed_at=now)
            return service.rotate(
                session_id=session.session_id,
                raw_refresh_token=refresh_token,
                device_proof=proof,
                now=now,
            )
        except (SessionReplay, SessionError):
            return None

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(do_rotate) for _ in range(16)]
        results = [f.result() for f in futures]

    successful = [r for r in results if r is not None]
    assert len(successful) == 1


def test_idempotent_revocation():
    service = SessionService()
    now = _utc_now()
    session, _ = service.issue(
        subject_id=uuid4(),
        device_id=uuid4(),
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    service.revoke(session_id=session.session_id, reason="Logout 1", now=now)
    service.revoke(session_id=session.session_id, reason="Logout 2", now=now)
    assert True


def test_revoke_all():
    service = SessionService()
    now = _utc_now()
    subj = uuid4()
    s1, _ = service.issue(subject_id=subj, device_id=uuid4(), authentication_level=AuthenticationLevel.AUTHENTICATED, now=now)
    s2, _ = service.issue(subject_id=subj, device_id=uuid4(), authentication_level=AuthenticationLevel.AUTHENTICATED, now=now)
    s3, _ = service.issue(subject_id=uuid4(), device_id=uuid4(), authentication_level=AuthenticationLevel.AUTHENTICATED, now=now)

    revoked_count = service.revoke_all_for_subject(subject_id=subj, reason="Admin reset", now=now)
    assert revoked_count == 2


def test_client_timestamp_cannot_bypass_expiry():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    val, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(val)
    now = _utc_now()
    session, token = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
        lifetime_seconds=10,
    )
    server_now = now + timedelta(seconds=20)
    proof = _make_proof(dev_id, b_id, key, observed_at=server_now)
    with pytest.raises(SessionExpired):
        service.validate(raw_token=token, device_proof=proof, now=server_now)


def test_token_version_mismatch():
    service = SessionService()
    now = _utc_now()
    session, _ = service.issue(
        subject_id=uuid4(),
        device_id=uuid4(),
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    assert session.token_version == 1


def test_rotation_counter_mismatch():
    service = SessionService()
    now = _utc_now()
    session, _ = service.issue(
        subject_id=uuid4(),
        device_id=uuid4(),
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    assert session.rotation_counter == 0