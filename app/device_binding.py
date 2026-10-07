"""
OVELA / JURIX Device Binding Core.

Security principle:
    - User-agent, IP, cookie, local-storage, or client-provided ID is not authentication.
    - Device validation requires an enrolled active binding, cryptographic signature,
      unexpired nonce, and exact subject matching.
    - Single-use proof: Nonce replay fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hmac
import threading
from typing import Final, Protocol
from uuid import UUID

_MAX_CLOCK_SKEW: Final[timedelta] = timedelta(seconds=5)


class DeviceBindingState(StrEnum):
    UNKNOWN = "UNKNOWN"
    PENDING = "PENDING"
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    COMPROMISED = "COMPROMISED"


class DeviceBindingError(Exception):
    """Base error for device binding violations."""


class DeviceBindingInvalid(DeviceBindingError):
    """Raised when device binding or proof parameters are invalid."""


class DeviceBindingRevoked(DeviceBindingError):
    """Raised when the device binding is revoked."""


class DeviceBindingCompromised(DeviceBindingError):
    """Raised when the device is flagged as compromised."""


class DeviceProofReplay(DeviceBindingError):
    """Raised when a device proof nonce is replayed."""


@dataclass(frozen=True, slots=True)
class DeviceBinding:
    device_id: UUID
    subject_id: UUID
    binding_id: UUID
    state: DeviceBindingState
    public_key_fingerprint: str
    created_at: datetime
    last_verified_at: datetime | None
    revoked_at: datetime | None

    def __post_init__(self) -> None:
        if not isinstance(self.device_id, UUID):
            raise TypeError("device_id must be a UUID")
        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        if not isinstance(self.binding_id, UUID):
            raise TypeError("binding_id must be a UUID")
        if not isinstance(self.state, DeviceBindingState):
            raise TypeError("state must be a DeviceBindingState")
        if not isinstance(self.public_key_fingerprint, str) or not self.public_key_fingerprint.strip():
            raise DeviceBindingInvalid("public_key_fingerprint must be a non-empty string")
        if not isinstance(self.created_at, datetime) or self.created_at.tzinfo is None:
            raise DeviceBindingInvalid("created_at must be a timezone-aware datetime")
        if self.last_verified_at is not None:
            if not isinstance(self.last_verified_at, datetime) or self.last_verified_at.tzinfo is None:
                raise DeviceBindingInvalid("last_verified_at must be a timezone-aware datetime")
        if self.revoked_at is not None:
            if not isinstance(self.revoked_at, datetime) or self.revoked_at.tzinfo is None:
                raise DeviceBindingInvalid("revoked_at must be a timezone-aware datetime")


@dataclass(frozen=True, slots=True)
class DeviceProof:
    device_id: UUID
    binding_id: UUID
    nonce: str
    signature: str
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.device_id, UUID):
            raise TypeError("device_id must be a UUID")
        if not isinstance(self.binding_id, UUID):
            raise TypeError("binding_id must be a UUID")
        if not isinstance(self.nonce, str) or not self.nonce.strip():
            raise DeviceBindingInvalid("nonce must be a non-empty string")
        if not isinstance(self.signature, str) or not self.signature.strip():
            raise DeviceBindingInvalid("signature must be a non-empty string")
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None:
            raise DeviceBindingInvalid("observed_at must be a timezone-aware datetime")


@dataclass(frozen=True, slots=True)
class DeviceValidationResult:
    valid: bool
    device_id: UUID | None
    subject_id: UUID | None
    reason_code: str
    verified_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.valid, bool):
            raise TypeError("valid must be a bool")
        if not isinstance(self.reason_code, str):
            raise TypeError("reason_code must be a str")
        if not isinstance(self.verified_at, datetime) or self.verified_at.tzinfo is None:
            raise DeviceBindingInvalid("verified_at must be a timezone-aware datetime")


class DeviceBindingValidator(Protocol):
    def validate(
        self,
        *,
        proof: DeviceProof,
        expected_subject_id: UUID | None,
        now: datetime,
    ) -> DeviceValidationResult:
        ...


class DefaultDeviceBindingValidator:
    """
    Cryptographic device proof validator with single-use nonce tracking.
    """

    def __init__(self, bindings: dict[UUID, DeviceBinding] | None = None) -> None:
        self._lock = threading.RLock()
        self._bindings: dict[UUID, DeviceBinding] = dict(bindings or {})
        self._consumed_nonces: set[tuple[UUID, str]] = set()

    def register_binding(self, binding: DeviceBinding) -> None:
        with self._lock:
            self._bindings[binding.device_id] = binding

    def validate(
        self,
        *,
        proof: DeviceProof,
        expected_subject_id: UUID | None,
        now: datetime,
    ) -> DeviceValidationResult:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise DeviceBindingInvalid("now must be a timezone-aware datetime")

        now_utc = now.astimezone(timezone.utc)

        if not isinstance(proof, DeviceProof):
            return DeviceValidationResult(
                valid=False,
                device_id=None,
                subject_id=None,
                reason_code="INVALID_PROOF_OBJECT",
                verified_at=now,
            )

        with self._lock:
            binding = self._bindings.get(proof.device_id)
            if binding is None:
                return DeviceValidationResult(
                    valid=False,
                    device_id=proof.device_id,
                    subject_id=None,
                    reason_code="UNKNOWN_DEVICE",
                    verified_at=now,
                )

            if binding.binding_id != proof.binding_id:
                return DeviceValidationResult(
                    valid=False,
                    device_id=proof.device_id,
                    subject_id=binding.subject_id,
                    reason_code="BINDING_ID_MISMATCH",
                    verified_at=now,
                )

            if binding.state == DeviceBindingState.REVOKED:
                return DeviceValidationResult(
                    valid=False,
                    device_id=proof.device_id,
                    subject_id=binding.subject_id,
                    reason_code="DEVICE_REVOKED",
                    verified_at=now,
                )

            if binding.state == DeviceBindingState.COMPROMISED:
                return DeviceValidationResult(
                    valid=False,
                    device_id=proof.device_id,
                    subject_id=binding.subject_id,
                    reason_code="DEVICE_COMPROMISED",
                    verified_at=now,
                )

            if binding.state != DeviceBindingState.ACTIVE:
                return DeviceValidationResult(
                    valid=False,
                    device_id=proof.device_id,
                    subject_id=binding.subject_id,
                    reason_code="DEVICE_NOT_ACTIVE",
                    verified_at=now,
                )

            if expected_subject_id is not None and binding.subject_id != expected_subject_id:
                return DeviceValidationResult(
                    valid=False,
                    device_id=proof.device_id,
                    subject_id=binding.subject_id,
                    reason_code="SUBJECT_MISMATCH",
                    verified_at=now,
                )

            # Check proof age with clock skew tolerance
            observed_utc = proof.observed_at.astimezone(timezone.utc)
            if observed_utc > now_utc + _MAX_CLOCK_SKEW:
                return DeviceValidationResult(
                    valid=False,
                    device_id=proof.device_id,
                    subject_id=binding.subject_id,
                    reason_code="FUTURE_DATED_PROOF",
                    verified_at=now,
                )

            if (now_utc - observed_utc).total_seconds() > 300:
                return DeviceValidationResult(
                    valid=False,
                    device_id=proof.device_id,
                    subject_id=binding.subject_id,
                    reason_code="EXPIRED_PROOF",
                    verified_at=now,
                )

            # Replay protection on (device_id, nonce)
            nonce_key = (proof.device_id, proof.nonce)
            if nonce_key in self._consumed_nonces:
                return DeviceValidationResult(
                    valid=False,
                    device_id=proof.device_id,
                    subject_id=binding.subject_id,
                    reason_code="NONCE_REPLAYED",
                    verified_at=now,
                )

            # Signature verification: expected signature is HMAC(fingerprint, f"{device_id}:{binding_id}:{nonce}")
            expected_payload = f"{proof.device_id}:{proof.binding_id}:{proof.nonce}".encode("utf-8")
            expected_sig = hmac.new(
                binding.public_key_fingerprint.encode("utf-8"),
                expected_payload,
                "sha256",
            ).hexdigest()

            if not hmac.compare_digest(proof.signature, expected_sig):
                return DeviceValidationResult(
                    valid=False,
                    device_id=proof.device_id,
                    subject_id=binding.subject_id,
                    reason_code="INVALID_SIGNATURE",
                    verified_at=now,
                )

            # Atomically record consumption
            self._consumed_nonces.add(nonce_key)

            return DeviceValidationResult(
                valid=True,
                device_id=proof.device_id,
                subject_id=binding.subject_id,
                reason_code="VALID",
                verified_at=now,
            )