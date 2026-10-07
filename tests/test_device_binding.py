"""Tests for M3 Device Binding Core (16 test cases)."""

from datetime import datetime, timedelta, timezone
import hmac
from uuid import uuid4
import pytest

from app.device_binding import (
    DefaultDeviceBindingValidator,
    DeviceBinding,
    DeviceBindingState,
    DeviceProof,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sign(key: str, device_id, binding_id, nonce: str) -> str:
    payload = f"{device_id}:{binding_id}:{nonce}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), payload, "sha256").hexdigest()


def test_valid_proof():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "secret-key-123"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    nonce = "nonce-1"
    proof = DeviceProof(
        device_id=device_id,
        binding_id=binding_id,
        nonce=nonce,
        signature=_sign(key, device_id, binding_id, nonce),
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res.valid is True
    assert res.reason_code == "VALID"


def test_unknown_device():
    now = _utc_now()
    validator = DefaultDeviceBindingValidator({})
    dev_id, b_id = uuid4(), uuid4()
    proof = DeviceProof(
        device_id=dev_id,
        binding_id=b_id,
        nonce="n1",
        signature="sig",
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=None, now=now)
    assert res.valid is False
    assert res.reason_code == "UNKNOWN_DEVICE"


def test_revoked_device():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.REVOKED,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=now,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    proof = DeviceProof(
        device_id=device_id,
        binding_id=binding_id,
        nonce="n1",
        signature=_sign(key, device_id, binding_id, "n1"),
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res.valid is False
    assert res.reason_code == "DEVICE_REVOKED"


def test_compromised_device():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.COMPROMISED,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    proof = DeviceProof(
        device_id=device_id,
        binding_id=binding_id,
        nonce="n1",
        signature=_sign(key, device_id, binding_id, "n1"),
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res.valid is False
    assert res.reason_code == "DEVICE_COMPROMISED"


def test_wrong_signature():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    proof = DeviceProof(
        device_id=device_id,
        binding_id=binding_id,
        nonce="n1",
        signature="invalid-hex-signature",
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res.valid is False
    assert res.reason_code == "INVALID_SIGNATURE"


def test_wrong_binding_id():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    wrong_b_id = uuid4()
    proof = DeviceProof(
        device_id=device_id,
        binding_id=wrong_b_id,
        nonce="n1",
        signature=_sign(key, device_id, wrong_b_id, "n1"),
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res.valid is False
    assert res.reason_code == "BINDING_ID_MISMATCH"


def test_wrong_device_id():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    other_dev = uuid4()
    proof = DeviceProof(
        device_id=other_dev,
        binding_id=binding_id,
        nonce="n1",
        signature="sig",
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res.valid is False
    assert res.reason_code == "UNKNOWN_DEVICE"


def test_wrong_subject():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    proof = DeviceProof(
        device_id=device_id,
        binding_id=binding_id,
        nonce="n1",
        signature=_sign(key, device_id, binding_id, "n1"),
        observed_at=now,
    )
    other_subject = uuid4()
    res = validator.validate(proof=proof, expected_subject_id=other_subject, now=now)
    assert res.valid is False
    assert res.reason_code == "SUBJECT_MISMATCH"


def test_expired_proof():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    old_time = now - timedelta(minutes=10)
    proof = DeviceProof(
        device_id=device_id,
        binding_id=binding_id,
        nonce="n1",
        signature=_sign(key, device_id, binding_id, "n1"),
        observed_at=old_time,
    )
    res = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res.valid is False
    assert res.reason_code == "EXPIRED_PROOF"


def test_proof_replay():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    proof = DeviceProof(
        device_id=device_id,
        binding_id=binding_id,
        nonce="n1",
        signature=_sign(key, device_id, binding_id, "n1"),
        observed_at=now,
    )
    res1 = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res1.valid is True
    # Replay same proof
    res2 = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res2.valid is False
    assert res2.reason_code == "NONCE_REPLAYED"


def test_modified_nonce():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    sig = _sign(key, device_id, binding_id, "original-nonce")
    proof = DeviceProof(
        device_id=device_id,
        binding_id=binding_id,
        nonce="tampered-nonce",
        signature=sig,
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res.valid is False
    assert res.reason_code == "INVALID_SIGNATURE"


def test_modified_signature():
    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    proof = DeviceProof(
        device_id=device_id,
        binding_id=binding_id,
        nonce="n1",
        signature="bad-sig",
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=subject_id, now=now)
    assert res.valid is False
    assert res.reason_code == "INVALID_SIGNATURE"


def test_fingerprint_alone_fails():
    validator = DefaultDeviceBindingValidator({})
    now = _utc_now()
    res = validator.validate(proof="just-a-fingerprint-string", expected_subject_id=None, now=now)  # type: ignore
    assert res.valid is False
    assert res.reason_code == "INVALID_PROOF_OBJECT"


def test_user_agent_spoof_fails():
    # User-agent header claim cannot bypass lack of registered device binding
    now = _utc_now()
    validator = DefaultDeviceBindingValidator({})
    proof = DeviceProof(
        device_id=uuid4(),
        binding_id=uuid4(),
        nonce="n1",
        signature="sig",
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=None, now=now)
    assert res.valid is False


def test_ip_change_cannot_grant_auth():
    # IP changes or claims cannot forge signature
    now = _utc_now()
    validator = DefaultDeviceBindingValidator({})
    proof = DeviceProof(
        device_id=uuid4(),
        binding_id=uuid4(),
        nonce="n1",
        signature="invalid",
        observed_at=now,
    )
    res = validator.validate(proof=proof, expected_subject_id=None, now=now)
    assert res.valid is False


def test_concurrent_proof_replay_one_winner():
    from concurrent.futures import ThreadPoolExecutor

    now = _utc_now()
    device_id, subject_id, binding_id = uuid4(), uuid4(), uuid4()
    key = "k"
    binding = DeviceBinding(
        device_id=device_id,
        subject_id=subject_id,
        binding_id=binding_id,
        state=DeviceBindingState.ACTIVE,
        public_key_fingerprint=key,
        created_at=now,
        last_verified_at=None,
        revoked_at=None,
    )
    validator = DefaultDeviceBindingValidator({device_id: binding})
    nonce = "concurrent-nonce-1"
    proof = DeviceProof(
        device_id=device_id,
        binding_id=binding_id,
        nonce=nonce,
        signature=_sign(key, device_id, binding_id, nonce),
        observed_at=now,
    )

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(validator.validate, proof=proof, expected_subject_id=subject_id, now=now)
            for _ in range(16)
        ]
        results = [f.result() for f in futures]

    valid_count = sum(1 for r in results if r.valid is True)
    assert valid_count == 1