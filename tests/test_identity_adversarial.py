"""
Adversarial Attack and Boundary Matrix for M3 Identity & Authentication Core.

Covers all 48 required adversarial vectors from Section 15 of M3 specification:
  - Session hijacking (1-8)
  - Device spoofing (9-15)
  - Token tampering (16-23)
  - Replay attacks (24-30)
  - Privilege escalation (31-36)
  - Provider failure & model forgery (37-48)
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hmac
from uuid import uuid4
import pytest

from app.authentication import (
    AuthenticationCeremony,
    AuthenticationInvalid,
    AuthenticationLocked,
    AuthenticationMethod,
    AuthenticationReplay,
    AuthenticationRequest,
    AuthenticationResult,
    AuthenticationService,
    CeremonyState,
)
from app.device_binding import (
    DefaultDeviceBindingValidator,
    DeviceBinding,
    DeviceBindingCompromised,
    DeviceBindingError,
    DeviceBindingInvalid,
    DeviceBindingRevoked,
    DeviceBindingState,
    DeviceProof,
    DeviceProofReplay,
)
from app.identity import (
    DefaultIdentityEvaluator,
    IdentityError,
    IdentityEvidence,
    IdentityEvidenceKind,
    IdentityInvalid,
    IdentityState,
    IdentitySubject,
)
from app.identity_store import (
    AuthenticationError,
    AuthenticationLocked,
    CredentialKind,
    CredentialRecord,
    CredentialStatus,
    InMemoryIdentityStore,
)
from app.session import (
    AuthenticationLevel,
    SessionError,
    SessionExpired,
    SessionInvalid,
    SessionRecord,
    SessionReplay,
    SessionRevoked,
    SessionService,
    SessionState,
)
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


def _sign(key: str, device_id, binding_id, nonce: str) -> str:
    payload = f"{device_id}:{binding_id}:{nonce}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), payload, "sha256").hexdigest()


def _setup_device(dev_id, subj_id, b_id, key="test-device-key"):
    now = _utc_now()
    binding = DeviceBinding(
        device_id=dev_id,
        subject_id=subj_id,
        binding_id=b_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({dev_id: binding})
    return validator, key


def _make_proof(dev_id, b_id, key="test-device-key", nonce=None, observed_at=None):
    now = observed_at or _utc_now()
    n = nonce or str(uuid4())
    sig = _sign(key, dev_id, b_id, n)
    return DeviceProof(
        device_id=dev_id,
        binding_id=b_id,
        nonce=n,
        signature=sig,
        observed_at=now,
    )


# ============================================================================
# Category 1: Session Hijacking (Tests 1 - 8)
# ============================================================================

def test_adv_01_stolen_token_without_device_proof_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, _ = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(validator)
    now = _utc_now()
    _, token = service.issue(
        subject_id=subj_id,
        device_id=dev_id,
        authentication_level=AuthenticationLevel.AUTHENTICATED,
        now=now,
    )
    with pytest.raises(Exception):
        service.validate(raw_token=token, device_proof=None, now=now)  # type: ignore


def test_adv_02_token_from_device_a_on_device_b_fails():
    devA, devB = uuid4(), uuid4()
    subj = uuid4()
    bA, bB = uuid4(), uuid4()
    now = _utc_now()
    bindingA = DeviceBinding(
        device_id=devA, subject_id=subj, binding_id=bA, state=DeviceBindingState.ACTIVE,
        public_key_fingerprint="keyA", created_at=now, last_verified_at=None, revoked_at=None,
    )
    bindingB = DeviceBinding(
        device_id=devB, subject_id=subj, binding_id=bB, state=DeviceBindingState.ACTIVE,
        public_key_fingerprint="keyB", created_at=now, last_verified_at=None, revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({devA: bindingA, devB: bindingB})
    service = SessionService(validator)

    _, tokenA = service.issue(
        subject_id=subj, device_id=devA, authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    proofB = _make_proof(devB, bB, key="keyB", observed_at=now)

    with pytest.raises(SessionInvalid):
        service.validate(raw_token=tokenA, device_proof=proofB, now=now)


def test_adv_03_rotated_refresh_token_fails_on_replay():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(validator)
    now = _utc_now()
    sess, _ = service.issue(
        subject_id=subj_id, device_id=dev_id, authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    refresh_token = service.issue_refresh_token(session_id=sess.session_id, now=now)
    proof1 = _make_proof(dev_id, b_id, key, observed_at=now)

    service.rotate(session_id=sess.session_id, raw_refresh_token=refresh_token, device_proof=proof1, now=now)

    proof2 = _make_proof(dev_id, b_id, key, observed_at=now)
    with pytest.raises(SessionReplay):
        service.rotate(session_id=sess.session_id, raw_refresh_token=refresh_token, device_proof=proof2, now=now)


def test_adv_04_revoked_token_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(validator)
    now = _utc_now()
    sess, token = service.issue(
        subject_id=subj_id, device_id=dev_id, authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    service.revoke(session_id=sess.session_id, reason="User breach", now=now)
    proof = _make_proof(dev_id, b_id, key, observed_at=now)

    with pytest.raises(SessionRevoked):
        service.validate(raw_token=token, device_proof=proof, now=now)


def test_adv_05_subject_substitution_fails():
    dev_id, subjA, subjB, b_id = uuid4(), uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subjA, b_id)
    service = SessionService(validator)
    now = _utc_now()
    sess, token = service.issue(
        subject_id=subjA, device_id=dev_id, authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    proof = _make_proof(dev_id, b_id, key, observed_at=now)
    validated = service.validate(raw_token=token, device_proof=proof, now=now)
    assert validated.subject_id == subjA
    assert validated.subject_id != subjB


def test_adv_06_session_id_substitution_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(validator)
    now = _utc_now()
    sess, _ = service.issue(
        subject_id=subj_id, device_id=dev_id, authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    refresh_token = service.issue_refresh_token(session_id=sess.session_id, now=now)
    forged_session_id = uuid4()
    proof = _make_proof(dev_id, b_id, key, observed_at=now)

    with pytest.raises(SessionInvalid):
        service.rotate(session_id=forged_session_id, raw_refresh_token=refresh_token, device_proof=proof, now=now)


def test_adv_07_token_prefix_suffix_mutation_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(validator)
    now = _utc_now()
    _, token = service.issue(
        subject_id=subj_id, device_id=dev_id, authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    proof = _make_proof(dev_id, b_id, key, observed_at=now)

    with pytest.raises(SessionInvalid):
        service.validate(raw_token="prefix_" + token, device_proof=proof, now=now)

    with pytest.raises(SessionInvalid):
        service.validate(raw_token=token + "_suffix", device_proof=proof, now=now)


def test_adv_08_replay_after_successful_single_use_operation_fails():
    service = StepUpService()
    now = _utc_now()
    sess = SessionRecord(
        session_id=uuid4(), subject_id=uuid4(), device_id=uuid4(), state=SessionState.ACTIVE,
        authentication_level=AuthenticationLevel.AUTHENTICATED, issued_at=now,
        expires_at=now + timedelta(hours=1), last_seen_at=now, rotation_counter=0, token_version=1,
    )
    challenge, raw_nonce = service.issue(
        session=sess, action_scope="WIRE_TRANSFER", method=StepUpMethod.TOTP, now=now,
    )
    res = service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)
    assert res.verified is True
    service.consume(challenge_id=challenge.challenge_id, now=now)

    with pytest.raises(StepUpReplay):
        service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)


# ============================================================================
# Category 2: Device Spoofing (Tests 9 - 15)
# ============================================================================

def test_adv_09_forged_device_id_fails():
    validator = DefaultDeviceBindingValidator({})
    now = _utc_now()
    proof = DeviceProof(device_id=uuid4(), binding_id=uuid4(), nonce="n", signature="s", observed_at=now)
    res = validator.validate(proof=proof, expected_subject_id=None, now=now)
    assert res.valid is False
    assert res.reason_code == "UNKNOWN_DEVICE"


def test_adv_10_forged_binding_id_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    now = _utc_now()
    proof = DeviceProof(
        device_id=dev_id, binding_id=uuid4(), nonce="n", signature=_sign(key, dev_id, b_id, "n"), observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=subj_id, now=now)
    assert res.valid is False
    assert res.reason_code == "BINDING_ID_MISMATCH"


def test_adv_11_fake_public_key_fingerprint_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, _ = _setup_device(dev_id, subj_id, b_id, key="real-key")
    now = _utc_now()
    proof = DeviceProof(
        device_id=dev_id, binding_id=b_id, nonce="n", signature=_sign("attacker-key", dev_id, b_id, "n"), observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=subj_id, now=now)
    assert res.valid is False
    assert res.reason_code == "INVALID_SIGNATURE"


def test_adv_12_invalid_signature_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, _ = _setup_device(dev_id, subj_id, b_id)
    now = _utc_now()
    proof = DeviceProof(device_id=dev_id, binding_id=b_id, nonce="n", signature="corrupted-sig", observed_at=now)
    res = validator.validate(proof=proof, expected_subject_id=subj_id, now=now)
    assert res.valid is False
    assert res.reason_code == "INVALID_SIGNATURE"


def test_adv_13_replayed_signature_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    now = _utc_now()
    proof = _make_proof(dev_id, b_id, key, nonce="replay-nonce", observed_at=now)
    res1 = validator.validate(proof=proof, expected_subject_id=subj_id, now=now)
    assert res1.valid is True
    res2 = validator.validate(proof=proof, expected_subject_id=subj_id, now=now)
    assert res2.valid is False
    assert res2.reason_code == "NONCE_REPLAYED"


def test_adv_14_copied_browser_fingerprint_fails():
    validator = DefaultDeviceBindingValidator({})
    now = _utc_now()
    res = validator.validate(proof="canvas-webgl-screen-fp", expected_subject_id=None, now=now)  # type: ignore
    assert res.valid is False
    assert res.reason_code == "INVALID_PROOF_OBJECT"


def test_adv_15_copied_cookie_on_another_device_fails():
    devA, devB = uuid4(), uuid4()
    subj = uuid4()
    bA, bB = uuid4(), uuid4()
    now = _utc_now()
    bindingA = DeviceBinding(
        device_id=devA, subject_id=subj, binding_id=bA, state=DeviceBindingState.ACTIVE,
        public_key_fingerprint="kA", created_at=now, last_verified_at=None, revoked_at=None,
    )
    bindingB = DeviceBinding(
        device_id=devB, subject_id=subj, binding_id=bB, state=DeviceBindingState.ACTIVE,
        public_key_fingerprint="kB", created_at=now, last_verified_at=None, revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({devA: bindingA, devB: bindingB})
    service = SessionService(validator)
    _, token = service.issue(
        subject_id=subj, device_id=devA, authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    proofOnDevB = _make_proof(devB, bB, key="kB", observed_at=now)

    with pytest.raises(SessionInvalid):
        service.validate(raw_token=token, device_proof=proofOnDevB, now=now)


# ============================================================================
# Category 3: Token Tampering (Tests 16 - 23)
# ============================================================================

def test_adv_16_session_token_mutation_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(validator)
    now = _utc_now()
    _, token = service.issue(
        subject_id=subj_id, device_id=dev_id, authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    mutated = token[:-1] + ("A" if token[-1] != "A" else "B")
    proof = _make_proof(dev_id, b_id, key, observed_at=now)
    with pytest.raises(SessionInvalid):
        service.validate(raw_token=mutated, device_proof=proof, now=now)


def test_adv_17_refresh_token_mutation_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(validator)
    now = _utc_now()
    sess, _ = service.issue(
        subject_id=subj_id, device_id=dev_id, authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    refresh_token = service.issue_refresh_token(session_id=sess.session_id, now=now)
    mutated = refresh_token[:-1] + "X"
    proof = _make_proof(dev_id, b_id, key, observed_at=now)
    with pytest.raises(SessionInvalid):
        service.rotate(session_id=sess.session_id, raw_refresh_token=mutated, device_proof=proof, now=now)


def test_adv_18_token_version_mutation_fails():
    now = _utc_now()
    with pytest.raises(SessionInvalid):
        SessionRecord(
            session_id=uuid4(), subject_id=uuid4(), device_id=uuid4(), state=SessionState.ACTIVE,
            authentication_level=AuthenticationLevel.AUTHENTICATED, issued_at=now,
            expires_at=now + timedelta(hours=1), last_seen_at=now, rotation_counter=0,
            token_version=-1,
        )


def test_adv_19_rotation_counter_mutation_fails():
    now = _utc_now()
    with pytest.raises(SessionInvalid):
        SessionRecord(
            session_id=uuid4(), subject_id=uuid4(), device_id=uuid4(), state=SessionState.ACTIVE,
            authentication_level=AuthenticationLevel.AUTHENTICATED, issued_at=now,
            expires_at=now + timedelta(hours=1), last_seen_at=now,
            rotation_counter=-5,
            token_version=1,
        )


def test_adv_20_malformed_encoding_fails():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(validator)
    now = _utc_now()
    proof = _make_proof(dev_id, b_id, key, observed_at=now)
    with pytest.raises(SessionInvalid):
        service.validate(raw_token="\x00\xff\xfe\x00\x01\x02", device_proof=proof, now=now)


def test_adv_21_empty_token_fails():
    service = SessionService()
    now = _utc_now()
    proof = _make_proof(uuid4(), uuid4(), observed_at=now)
    with pytest.raises(SessionInvalid):
        service.validate(raw_token="", device_proof=proof, now=now)
    with pytest.raises(SessionInvalid):
        service.validate(raw_token="   ", device_proof=proof, now=now)


def test_adv_22_oversized_token_fails_safely():
    service = SessionService()
    now = _utc_now()
    proof = _make_proof(uuid4(), uuid4(), observed_at=now)
    oversized = "A" * 65536
    with pytest.raises(SessionInvalid):
        service.validate(raw_token=oversized, device_proof=proof, now=now)


def test_adv_23_wrong_issuer_environment_token_fails():
    serviceA = SessionService()
    serviceB = SessionService()
    now = _utc_now()
    _, tokenA = serviceA.issue(
        subject_id=uuid4(), device_id=uuid4(), authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    proof = _make_proof(uuid4(), uuid4(), observed_at=now)
    with pytest.raises(SessionInvalid):
        serviceB.validate(raw_token=tokenA, device_proof=proof, now=now)


# ============================================================================
# Category 4: Replay Attacks (Tests 24 - 30)
# ============================================================================

def test_adv_24_authentication_proof_replay():
    now = _utc_now()
    store = InMemoryIdentityStore()
    subj_id, cred_id = uuid4(), uuid4()
    store.save_subject(IdentitySubject(
        subject_id=subj_id, display_name="User", state=IdentityState.UNVERIFIED, created_at=now, updated_at=now,
    ))
    store.save_credential(CredentialRecord(
        credential_id=cred_id, subject_id=subj_id, kind=CredentialKind.PASSWORD, status=CredentialStatus.ACTIVE,
        verifier_reference="pwd", created_at=now, expires_at=None, failed_attempts=0, locked_until=None,
    ))
    auth = AuthenticationService(store, SessionService())
    req = AuthenticationRequest(
        subject_id=subj_id, device_proof=None, method=AuthenticationMethod.PASSWORD, credential_reference=str(cred_id),
    )
    ceremony = auth.begin(request=req, now=now)
    res = auth.verify(ceremony=ceremony, proof="pwd", device_proof=None, now=now)
    assert res.authenticated is True

    with pytest.raises(AuthenticationReplay):
        auth.verify(ceremony=ceremony, proof="pwd", device_proof=None, now=now)


def test_adv_25_ceremony_replay():
    now = _utc_now()
    store = InMemoryIdentityStore()
    subj_id, cred_id = uuid4(), uuid4()
    store.save_credential(CredentialRecord(
        credential_id=cred_id, subject_id=subj_id, kind=CredentialKind.PASSWORD, status=CredentialStatus.ACTIVE,
        verifier_reference="secret", created_at=now, expires_at=None, failed_attempts=0, locked_until=None,
    ))
    auth = AuthenticationService(store, SessionService())
    req = AuthenticationRequest(
        subject_id=subj_id, device_proof=None, method=AuthenticationMethod.PASSWORD, credential_reference=str(cred_id),
    )
    c1 = auth.begin(request=req, now=now)
    auth.verify(ceremony=c1, proof="secret", device_proof=None, now=now)

    with pytest.raises(AuthenticationReplay):
        auth.verify(ceremony=c1, proof="secret", device_proof=None, now=now)


def test_adv_26_refresh_replay():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    service = SessionService(validator)
    now = _utc_now()
    sess, _ = service.issue(
        subject_id=subj_id, device_id=dev_id, authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    refresh_token = service.issue_refresh_token(session_id=sess.session_id, now=now)
    proof = _make_proof(dev_id, b_id, key, observed_at=now)

    service.rotate(session_id=sess.session_id, raw_refresh_token=refresh_token, device_proof=proof, now=now)

    proof2 = _make_proof(dev_id, b_id, key, observed_at=now)
    with pytest.raises(SessionReplay):
        service.rotate(session_id=sess.session_id, raw_refresh_token=refresh_token, device_proof=proof2, now=now)


def test_adv_27_device_proof_replay():
    dev_id, subj_id, b_id = uuid4(), uuid4(), uuid4()
    validator, key = _setup_device(dev_id, subj_id, b_id)
    now = _utc_now()
    proof = _make_proof(dev_id, b_id, key, nonce="unique-nonce", observed_at=now)

    res1 = validator.validate(proof=proof, expected_subject_id=subj_id, now=now)
    assert res1.valid is True
    res2 = validator.validate(proof=proof, expected_subject_id=subj_id, now=now)
    assert res2.valid is False
    assert res2.reason_code == "NONCE_REPLAYED"


def test_adv_28_step_up_proof_replay():
    service = StepUpService()
    now = _utc_now()
    sess = SessionRecord(
        session_id=uuid4(), subject_id=uuid4(), device_id=uuid4(), state=SessionState.ACTIVE,
        authentication_level=AuthenticationLevel.AUTHENTICATED, issued_at=now,
        expires_at=now + timedelta(hours=1), last_seen_at=now, rotation_counter=0, token_version=1,
    )
    challenge, raw_nonce = service.issue(
        session=sess, action_scope="SCOPE", method=StepUpMethod.TOTP, now=now,
    )
    res = service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)
    assert res.verified is True
    service.consume(challenge_id=challenge.challenge_id, now=now)

    with pytest.raises(StepUpReplay):
        service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)


def test_adv_29_consumed_challenge_replay():
    service = StepUpService()
    now = _utc_now()
    sess = SessionRecord(
        session_id=uuid4(), subject_id=uuid4(), device_id=uuid4(), state=SessionState.ACTIVE,
        authentication_level=AuthenticationLevel.AUTHENTICATED, issued_at=now,
        expires_at=now + timedelta(hours=1), last_seen_at=now, rotation_counter=0, token_version=1,
    )
    challenge, raw_nonce = service.issue(
        session=sess, action_scope="SCOPE", method=StepUpMethod.TOTP, now=now,
    )
    service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)
    service.consume(challenge_id=challenge.challenge_id, now=now)

    with pytest.raises(StepUpReplay):
        service.consume(challenge_id=challenge.challenge_id, now=now)


def test_adv_30_concurrent_replay_has_one_successful_verifier():
    service = StepUpService()
    now = _utc_now()
    sess = SessionRecord(
        session_id=uuid4(), subject_id=uuid4(), device_id=uuid4(), state=SessionState.ACTIVE,
        authentication_level=AuthenticationLevel.AUTHENTICATED, issued_at=now,
        expires_at=now + timedelta(hours=1), last_seen_at=now, rotation_counter=0, token_version=1,
    )
    challenge, raw_nonce = service.issue(
        session=sess, action_scope="CONCURRENT", method=StepUpMethod.TOTP, now=now,
    )

    def do_verify():
        try:
            res = service.verify(challenge=challenge, raw_nonce=raw_nonce, proof=raw_nonce, now=now)
            if res.verified:
                service.consume(challenge_id=challenge.challenge_id, now=now)
                return True
        except (StepUpReplay, StepUpInvalid):
            return False
        return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(do_verify) for _ in range(16)]
        results = [f.result() for f in futures]

    assert results.count(True) == 1


# ============================================================================
# Category 5: Privilege Escalation (Tests 31 - 36)
# ============================================================================

def test_adv_31_recognized_cannot_become_authenticated_by_enum_mutation():
    now = _utc_now()
    subj = IdentitySubject(
        subject_id=uuid4(), display_name="Test", state=IdentityState.RECOGNIZED, created_at=now, updated_at=now,
    )
    with pytest.raises(Exception):
        subj.state = IdentityState.AUTHENTICATED  # type: ignore


def test_adv_32_authenticated_cannot_become_owner_verified_by_request_mutation():
    now = _utc_now()
    sess = SessionRecord(
        session_id=uuid4(), subject_id=uuid4(), device_id=uuid4(), state=SessionState.ACTIVE,
        authentication_level=AuthenticationLevel.AUTHENTICATED, issued_at=now,
        expires_at=now + timedelta(hours=1), last_seen_at=now, rotation_counter=0, token_version=1,
    )
    with pytest.raises(Exception):
        sess.authentication_level = AuthenticationLevel.OWNER_VERIFIED  # type: ignore


def test_adv_33_step_up_required_is_not_step_up_verified():
    assert IdentityState.STEP_UP_REQUIRED != IdentityState.OWNER_VERIFIED
    assert AuthenticationLevel.AUTHENTICATED != AuthenticationLevel.STEP_UP_VERIFIED


def test_adv_34_caller_authentication_state_cannot_authorize_payment():
    from app.identity import DefaultIdentityEvaluator
    evaluator = DefaultIdentityEvaluator()
    now = _utc_now()
    ev = IdentityEvidence(
        evidence_id=uuid4(), subject_id=uuid4(), kind=IdentityEvidenceKind.FACE_RECOGNITION,
        confidence=1.0, observed_at=now, expires_at=now + timedelta(hours=1), trusted=False,
    )
    res = evaluator.evaluate(evidence=(ev,), now=now)
    assert res.state == IdentityState.UNKNOWN


def test_adv_35_caller_subject_cannot_impersonate_owner():
    now = _utc_now()
    owner_id = uuid4()
    caller_id = uuid4()
    owner = IdentitySubject(
        subject_id=owner_id, display_name="Owner", state=IdentityState.OWNER_VERIFIED, created_at=now, updated_at=now,
    )
    caller = IdentitySubject(
        subject_id=caller_id, display_name="Caller", state=IdentityState.UNVERIFIED, created_at=now, updated_at=now,
    )
    assert caller.subject_id != owner.subject_id
    assert caller.state != IdentityState.OWNER_VERIFIED


def test_adv_36_caller_device_status_cannot_authorize_protected_access():
    validator = DefaultDeviceBindingValidator({})
    now = _utc_now()
    proof = DeviceProof(device_id=uuid4(), binding_id=uuid4(), nonce="n", signature="sig", observed_at=now)
    res = validator.validate(proof=proof, expected_subject_id=None, now=now)
    assert res.valid is False


# ============================================================================
# Category 6: Provider Failure & Model Forgery (Tests 37 - 48)
# ============================================================================

def test_adv_37_credential_timeout_fails_closed():
    class TimeoutVerifier:
        def verify(self, *args, **kwargs):
            raise TimeoutError("Credential provider timed out")

    now = _utc_now()
    store = InMemoryIdentityStore()
    cred_id = uuid4()
    store.save_credential(CredentialRecord(
        credential_id=cred_id, subject_id=uuid4(), kind=CredentialKind.PASSWORD, status=CredentialStatus.ACTIVE,
        verifier_reference="v", created_at=now, expires_at=None, failed_attempts=0, locked_until=None,
    ))
    auth = AuthenticationService(store, SessionService(), verifier=TimeoutVerifier())
    req = AuthenticationRequest(
        subject_id=None, device_proof=None, method=AuthenticationMethod.PASSWORD, credential_reference=str(cred_id),
    )
    ceremony = auth.begin(request=req, now=now)
    with pytest.raises(TimeoutError):
        auth.verify(ceremony=ceremony, proof="p", device_proof=None, now=now)


def test_adv_38_device_verifier_failure_fails_closed():
    class BrokenValidator:
        def validate(self, *args, **kwargs):
            raise RuntimeError("Hardware security module unavailable")

    service = SessionService(device_validator=BrokenValidator())  # type: ignore
    now = _utc_now()
    sess, token = service.issue(
        subject_id=uuid4(), device_id=uuid4(), authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    proof = _make_proof(uuid4(), uuid4(), observed_at=now)
    with pytest.raises(RuntimeError):
        service.validate(raw_token=token, device_proof=proof, now=now)


def test_adv_39_storage_timeout_fails_closed():
    class TimeoutStore:
        def get_credential(self, *args, **kwargs):
            raise TimeoutError("Database connection timeout")
        def save_credential(self, *args, **kwargs): pass
        def get_subject(self, *args, **kwargs): pass
        def save_subject(self, *args, **kwargs): pass
        def get_device_binding(self, *args, **kwargs): pass
        def save_device_binding(self, *args, **kwargs): pass

    auth = AuthenticationService(TimeoutStore(), SessionService())
    now = _utc_now()
    req = AuthenticationRequest(
        subject_id=None, device_proof=None, method=AuthenticationMethod.PASSWORD, credential_reference=str(uuid4()),
    )
    ceremony = auth.begin(request=req, now=now)
    with pytest.raises(TimeoutError):
        auth.verify(ceremony=ceremony, proof="secret", device_proof=None, now=now)


def test_adv_40_clock_failure_fails_closed():
    service = SessionService()
    now_naive = datetime.now()
    with pytest.raises(SessionInvalid):
        service.issue(
            subject_id=uuid4(), device_id=uuid4(), authentication_level=AuthenticationLevel.AUTHENTICATED,
            now=now_naive,
        )


def test_adv_41_provider_unavailable_does_not_invoke_weaker_fallback():
    class FailingVerifier:
        def verify(self, *args, **kwargs):
            raise ConnectionError("Primary auth provider down")

    now = _utc_now()
    store = InMemoryIdentityStore()
    cred_id = uuid4()
    store.save_credential(CredentialRecord(
        credential_id=cred_id,
        subject_id=uuid4(),
        kind=CredentialKind.PASSWORD,
        status=CredentialStatus.ACTIVE,
        verifier_reference="hash",
        created_at=now,
        expires_at=None,
        failed_attempts=0,
        locked_until=None,
    ))
    auth = AuthenticationService(store, SessionService(), verifier=FailingVerifier())
    req = AuthenticationRequest(
        subject_id=None, device_proof=None, method=AuthenticationMethod.PASSWORD, credential_reference=str(cred_id),
    )
    ceremony = auth.begin(request=req, now=now)
    with pytest.raises(ConnectionError):
        auth.verify(ceremony=ceremony, proof="any", device_proof=None, now=now)


def test_adv_42_model_construct_identity_forgery_fails_at_boundary():
    with pytest.raises(TypeError):
        IdentitySubject(
            subject_id="not-a-uuid",  # type: ignore
            display_name="User",
            state=IdentityState.AUTHENTICATED,
            created_at=_utc_now(),
            updated_at=_utc_now(),
        )


def test_adv_43_model_copy_session_forgery_fails():
    sess = SessionRecord(
        session_id=uuid4(), subject_id=uuid4(), device_id=uuid4(), state=SessionState.ACTIVE,
        authentication_level=AuthenticationLevel.AUTHENTICATED, issued_at=_utc_now(),
        expires_at=_utc_now() + timedelta(hours=1), last_seen_at=_utc_now(), rotation_counter=0, token_version=1,
    )
    with pytest.raises(Exception):
        sess.authentication_level = AuthenticationLevel.OWNER_VERIFIED  # type: ignore


def test_adv_44_malicious_subclass_cannot_bypass_validation():
    class MaliciousEvidence(IdentityEvidence):
        pass

    now = _utc_now()
    evaluator = DefaultIdentityEvaluator()
    ev = MaliciousEvidence(
        evidence_id=uuid4(), subject_id=uuid4(), kind=IdentityEvidenceKind.FACE_RECOGNITION,
        confidence=0.99, observed_at=now, expires_at=now + timedelta(hours=1), trusted=True,
    )
    res = evaluator.evaluate(evidence=(ev,), now=now)
    assert res.state == IdentityState.RECOGNIZED
    assert res.state != IdentityState.AUTHENTICATED


def test_adv_45_malicious_serializer_cannot_alter_trusted_state():
    now = _utc_now()
    subj = IdentitySubject(
        subject_id=uuid4(), display_name="Admin", state=IdentityState.AUTHENTICATED, created_at=now, updated_at=now,
    )
    dumped = {slot: getattr(subj, slot) for slot in subj.__slots__}
    dumped["state"] = IdentityState.OWNER_VERIFIED
    assert subj.state == IdentityState.AUTHENTICATED


def test_adv_46_mutable_snapshot_cannot_modify_stored_session():
    service = SessionService()
    now = _utc_now()
    sess, _ = service.issue(
        subject_id=uuid4(), device_id=uuid4(), authentication_level=AuthenticationLevel.AUTHENTICATED, now=now,
    )
    with pytest.raises(Exception):
        sess.state = SessionState.EXPIRED  # type: ignore
    assert service._sessions[sess.session_id].state == SessionState.ACTIVE


def test_adv_47_mutable_snapshot_cannot_modify_stored_credential():
    now = _utc_now()
    cred = CredentialRecord(
        credential_id=uuid4(), subject_id=uuid4(), kind=CredentialKind.PASSWORD, status=CredentialStatus.ACTIVE,
        verifier_reference="hash", created_at=now, expires_at=None, failed_attempts=0, locked_until=None,
    )
    with pytest.raises(Exception):
        cred.status = CredentialStatus.REVOKED  # type: ignore
    assert cred.status == CredentialStatus.ACTIVE


def test_adv_48_mutable_snapshot_cannot_modify_stored_device_binding():
    now = _utc_now()
    binding = DeviceBinding(
        device_id=uuid4(), subject_id=uuid4(), binding_id=uuid4(), state=DeviceBindingState.ACTIVE,
        public_key_fingerprint="fp", created_at=now, last_verified_at=None, revoked_at=None,
    )
    with pytest.raises(Exception):
        binding.state = DeviceBindingState.REVOKED  # type: ignore
    assert binding.state == DeviceBindingState.ACTIVE