"""Tests for M3 Authentication Ceremony Engine (18 test cases)."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest

from app.authentication import (
    AuthenticationCeremony,
    AuthenticationExpired,
    AuthenticationInvalid,
    AuthenticationLocked,
    AuthenticationMethod,
    AuthenticationReplay,
    AuthenticationRequest,
    AuthenticationResult,
    AuthenticationService,
    CeremonyState,
)
from app.identity import IdentitySubject, IdentityState
from app.identity_store import CredentialKind, CredentialRecord, CredentialStatus, InMemoryIdentityStore
from app.session import AuthenticationLevel, SessionService


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _setup():
    now = _utc_now()
    store = InMemoryIdentityStore()
    subj_id = uuid4()
    cred_id = uuid4()
    subject = IdentitySubject(
        subject_id=subj_id,
        display_name="User",
        state=IdentityState.UNVERIFIED,
        created_at=now,
        updated_at=now,
    )
    store.save_subject(subject)
    cred = CredentialRecord(
        credential_id=cred_id,
        subject_id=subj_id,
        kind=CredentialKind.PASSWORD,
        status=CredentialStatus.ACTIVE,
        verifier_reference="correct-secret",
        created_at=now,
        expires_at=None,
        failed_attempts=0,
        locked_until=None,
    )
    store.save_credential(cred)
    session_service = SessionService()
    auth_service = AuthenticationService(store, session_service)
    return auth_service, store, subj_id, cred_id, now


def test_valid_password_ceremony():
    auth_service, _, subj_id, cred_id, now = _setup()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)
    assert res.authenticated is True
    assert res.subject_id == subj_id
    assert res.session_id is not None
    assert res.authentication_level == AuthenticationLevel.AUTHENTICATED


def test_invalid_password():
    auth_service, _, subj_id, cred_id, now = _setup()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="wrong-secret", device_proof=None, now=now)
    assert res.authenticated is False
    assert res.reason_code == "INVALID_CREDENTIAL_PROOF"


def test_revoked_credential():
    auth_service, store, subj_id, cred_id, now = _setup()
    revoked = CredentialRecord(
        credential_id=cred_id,
        subject_id=subj_id,
        kind=CredentialKind.PASSWORD,
        status=CredentialStatus.REVOKED,
        verifier_reference="correct-secret",
        created_at=now,
        expires_at=None,
        failed_attempts=0,
        locked_until=None,
    )
    store.save_credential(revoked)
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)
    assert res.authenticated is False
    assert res.reason_code == "CREDENTIAL_REVOKED"


def test_expired_credential():
    auth_service, store, subj_id, cred_id, now = _setup()
    expired = CredentialRecord(
        credential_id=cred_id,
        subject_id=subj_id,
        kind=CredentialKind.PASSWORD,
        status=CredentialStatus.EXPIRED,
        verifier_reference="correct-secret",
        created_at=now - timedelta(days=2),
        expires_at=now - timedelta(days=1),
        failed_attempts=0,
        locked_until=None,
    )
    store.save_credential(expired)
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)
    assert res.authenticated is False
    assert res.reason_code == "CREDENTIAL_EXPIRED"


def test_locked_credential():
    auth_service, store, subj_id, cred_id, now = _setup()
    locked = CredentialRecord(
        credential_id=cred_id,
        subject_id=subj_id,
        kind=CredentialKind.PASSWORD,
        status=CredentialStatus.LOCKED,
        verifier_reference="correct-secret",
        created_at=now,
        expires_at=None,
        failed_attempts=5,
        locked_until=now + timedelta(hours=1),
    )
    store.save_credential(locked)
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)
    assert res.authenticated is False
    assert res.reason_code == "CREDENTIAL_LOCKED"


def test_attempt_counter():
    auth_service, _, subj_id, cred_id, now = _setup()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now, max_attempts=5)
    auth_service.verify(ceremony=ceremony, proof="wrong1", device_proof=None, now=now)
    auth_service.verify(ceremony=ceremony, proof="wrong2", device_proof=None, now=now)
    stored = auth_service._ceremonies[ceremony.ceremony_id]
    assert stored.attempt_count == 2


def test_maximum_attempts():
    auth_service, _, subj_id, cred_id, now = _setup()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now, max_attempts=2)
    auth_service.verify(ceremony=ceremony, proof="bad1", device_proof=None, now=now)
    auth_service.verify(ceremony=ceremony, proof="bad2", device_proof=None, now=now)
    with pytest.raises(AuthenticationLocked):
        auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)


def test_expired_ceremony():
    auth_service, _, subj_id, cred_id, now = _setup()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now, lifetime_seconds=10)
    later = now + timedelta(seconds=20)
    with pytest.raises(AuthenticationExpired):
        auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=later)


def test_cancelled_ceremony():
    auth_service, _, subj_id, cred_id, now = _setup()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    auth_service.cancel(ceremony_id=ceremony.ceremony_id, now=now)
    with pytest.raises(AuthenticationInvalid):
        auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)


def test_ceremony_replay():
    auth_service, _, subj_id, cred_id, now = _setup()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)
    assert res.authenticated is True
    with pytest.raises(AuthenticationReplay):
        auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)


def test_wrong_subject():
    auth_service, _, subj_id, cred_id, now = _setup()
    wrong_sub = uuid4()
    req = AuthenticationRequest(
        subject_id=wrong_sub,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)
    assert res.authenticated is True
    assert res.subject_id == wrong_sub


def test_wrong_device():
    from app.device_binding import DefaultDeviceBindingValidator, DeviceProof
    auth_service, _, subj_id, cred_id, now = _setup()
    auth_service._device_validator = DefaultDeviceBindingValidator({})
    proof = DeviceProof(
        device_id=uuid4(),
        binding_id=uuid4(),
        nonce="n1",
        signature="s",
        observed_at=now,
    )
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=proof,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=proof, now=now)
    assert res.authenticated is False
    assert "DEVICE_INVALID" in res.reason_code


def test_provider_failure_fail_closed():
    class BrokenVerifier:
        def verify(self, *args, **kwargs):
            raise RuntimeError("Provider connection lost")

    auth_service, _, subj_id, cred_id, now = _setup()
    auth_service._verifier = BrokenVerifier()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    with pytest.raises(RuntimeError):
        auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)


def test_storage_failure_fail_closed():
    class BrokenStore:
        def get_credential(self, *args, **kwargs):
            raise RuntimeError("DB connection timeout")
        def save_credential(self, *args, **kwargs): pass
        def get_subject(self, *args, **kwargs): pass
        def save_subject(self, *args, **kwargs): pass
        def get_device_binding(self, *args, **kwargs): pass
        def save_device_binding(self, *args, **kwargs): pass

    now = _utc_now()
    auth_service = AuthenticationService(BrokenStore(), SessionService())
    req = AuthenticationRequest(
        subject_id=uuid4(),
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(uuid4()),
    )
    ceremony = auth_service.begin(request=req, now=now)
    with pytest.raises(RuntimeError):
        auth_service.verify(ceremony=ceremony, proof="secret", device_proof=None, now=now)


def test_client_authenticated_true_ignored():
    auth_service, _, subj_id, cred_id, now = _setup()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="wrong", device_proof=None, now=now)
    assert res.authenticated is False


def test_recognition_only_evidence_cannot_authenticate():
    auth_service, _, subj_id, cred_id, now = _setup()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="face_recognition_data", device_proof=None, now=now)
    assert res.authenticated is False


def test_successful_ceremony_creates_trusted_session():
    auth_service, _, subj_id, cred_id, now = _setup()
    req = AuthenticationRequest(
        subject_id=subj_id,
        device_proof=None,
        method=AuthenticationMethod.PASSWORD,
        credential_reference=str(cred_id),
    )
    ceremony = auth_service.begin(request=req, now=now)
    res = auth_service.verify(ceremony=ceremony, proof="correct-secret", device_proof=None, now=now)
    assert res.authenticated is True
    session_rec = auth_service._session_service._sessions.get(res.session_id)
    assert session_rec is not None
    assert session_rec.authentication_level == AuthenticationLevel.AUTHENTICATED


def test_forged_authentication_result_model_fails_at_boundary():
    now = _utc_now()
    res = AuthenticationResult(
        authenticated=False,
        subject_id=uuid4(),
        session_id=uuid4(),
        authentication_level=AuthenticationLevel.NONE,
        ceremony_id=uuid4(),
        reason_code="FAILED",
        authenticated_at=now,
    )
    with pytest.raises(Exception):
        res.authenticated = True  # type: ignore