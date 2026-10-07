"""
OVELA / JURIX Authentication Ceremony Engine.

Security principles:
    - Failed/expired/cancelled ceremonies can never become verified.
    - Verification is single-use; proof replay fails closed.
    - Provider and storage failures raise dedicated exceptions and fail closed.
    - Successful ceremonies issue trusted sessions only through SessionService.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hmac
import threading
from typing import Protocol
from uuid import UUID, uuid4

from .device_binding import DeviceBindingValidator, DeviceProof
from .identity_store import (
    AuthenticationError,
    AuthenticationLocked,
    AuthenticationStorageUnavailable,
    CredentialKind,
    CredentialRecord,
    CredentialStatus,
    IdentityStore,
)
from .session import AuthenticationLevel, SessionRecord, SessionService


class CeremonyState(StrEnum):
    CREATED = "CREATED"
    CHALLENGE_ISSUED = "CHALLENGE_ISSUED"
    AWAITING_PROOF = "AWAITING_PROOF"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


class AuthenticationMethod(StrEnum):
    PASSWORD = "PASSWORD"
    PASSKEY = "PASSKEY"
    TOTP = "TOTP"
    RECOVERY_CODE = "RECOVERY_CODE"


class AuthenticationInvalid(AuthenticationError):
    """Raised when ceremony parameters or proofs are malformed."""


class AuthenticationExpired(AuthenticationError):
    """Raised when an authentication ceremony has expired."""


class AuthenticationReplay(AuthenticationError):
    """Raised when a completed ceremony or proof is replayed."""


class AuthenticationProviderUnavailable(AuthenticationError):
    """Raised when an external or internal authentication provider is unavailable."""


@dataclass(frozen=True, slots=True)
class AuthenticationCeremony:
    ceremony_id: UUID
    subject_id: UUID | None
    device_id: UUID | None
    method: AuthenticationMethod
    state: CeremonyState
    created_at: datetime
    expires_at: datetime
    attempt_count: int
    max_attempts: int

    def __post_init__(self) -> None:
        if not isinstance(self.ceremony_id, UUID):
            raise TypeError("ceremony_id must be a UUID")
        if self.subject_id is not None and not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID or None")
        if self.device_id is not None and not isinstance(self.device_id, UUID):
            raise TypeError("device_id must be a UUID or None")
        if not isinstance(self.method, AuthenticationMethod):
            raise TypeError("method must be an AuthenticationMethod")
        if not isinstance(self.state, CeremonyState):
            raise TypeError("state must be a CeremonyState")
        if not isinstance(self.created_at, datetime) or self.created_at.tzinfo is None:
            raise AuthenticationInvalid("created_at must be timezone-aware")
        if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None:
            raise AuthenticationInvalid("expires_at must be timezone-aware")
        if self.expires_at.astimezone(timezone.utc) <= self.created_at.astimezone(timezone.utc):
            raise AuthenticationInvalid("expires_at must be strictly later than created_at")
        if not isinstance(self.attempt_count, int) or self.attempt_count < 0:
            raise AuthenticationInvalid("attempt_count must be non-negative")
        if not isinstance(self.max_attempts, int) or self.max_attempts <= 0:
            raise AuthenticationInvalid("max_attempts must be strictly positive")


@dataclass(frozen=True, slots=True)
class AuthenticationRequest:
    subject_id: UUID | None
    device_proof: DeviceProof | None
    method: AuthenticationMethod
    credential_reference: str

    def __post_init__(self) -> None:
        if self.subject_id is not None and not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID or None")
        if not isinstance(self.method, AuthenticationMethod):
            raise TypeError("method must be an AuthenticationMethod")
        if not isinstance(self.credential_reference, str) or not self.credential_reference.strip():
            raise AuthenticationInvalid("credential_reference must be non-empty")


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    authenticated: bool
    subject_id: UUID | None
    session_id: UUID | None
    authentication_level: AuthenticationLevel
    ceremony_id: UUID
    reason_code: str
    authenticated_at: datetime


class CredentialVerifier(Protocol):
    def verify(
        self,
        *,
        credential: CredentialRecord,
        presented_proof: str,
        ceremony_id: UUID,
        now: datetime,
    ) -> bool:
        ...


class ConstantTimeCredentialVerifier:
    """Standard credential verifier using constant-time string/hash comparison."""

    def verify(
        self,
        *,
        credential: CredentialRecord,
        presented_proof: str,
        ceremony_id: UUID,
        now: datetime,
    ) -> bool:
        if not isinstance(presented_proof, str):
            return False
        return hmac.compare_digest(credential.verifier_reference, presented_proof)


class AuthenticationService:
    """Ceremony coordinator and trusted session issuer."""

    def __init__(
        self,
        identity_store: IdentityStore,
        session_service: SessionService,
        verifier: CredentialVerifier | None = None,
        device_validator: DeviceBindingValidator | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._store = identity_store
        self._session_service = session_service
        self._verifier = verifier or ConstantTimeCredentialVerifier()
        self._device_validator = device_validator
        self._ceremonies: dict[UUID, AuthenticationCeremony] = {}
        self._ceremony_credentials: dict[UUID, UUID] = {}

    def begin(
        self,
        *,
        request: AuthenticationRequest,
        now: datetime,
        max_attempts: int = 3,
        lifetime_seconds: int = 300,
    ) -> AuthenticationCeremony:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise AuthenticationInvalid("now must be timezone-aware")

        now_utc = now.astimezone(timezone.utc)
        ceremony_id = uuid4()
        dev_id = request.device_proof.device_id if request.device_proof else None

        ceremony = AuthenticationCeremony(
            ceremony_id=ceremony_id,
            subject_id=request.subject_id,
            device_id=dev_id,
            method=request.method,
            state=CeremonyState.AWAITING_PROOF,
            created_at=now_utc,
            expires_at=now_utc + timedelta(seconds=lifetime_seconds),
            attempt_count=0,
            max_attempts=max_attempts,
        )

        with self._lock:
            self._ceremonies[ceremony_id] = ceremony
            try:
                cred_uuid = UUID(request.credential_reference)
                self._ceremony_credentials[ceremony_id] = cred_uuid
            except (ValueError, TypeError):
                pass

        return ceremony

    def verify(
        self,
        *,
        ceremony: AuthenticationCeremony,
        proof: str,
        device_proof: DeviceProof | None,
        now: datetime,
    ) -> AuthenticationResult:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise AuthenticationInvalid("now must be timezone-aware")

        now_utc = now.astimezone(timezone.utc)

        with self._lock:
            stored_ceremony = self._ceremonies.get(ceremony.ceremony_id)
            if stored_ceremony is None:
                return AuthenticationResult(
                    authenticated=False,
                    subject_id=None,
                    session_id=None,
                    authentication_level=AuthenticationLevel.NONE,
                    ceremony_id=ceremony.ceremony_id,
                    reason_code="CEREMONY_NOT_FOUND",
                    authenticated_at=now,
                )

            # Check expired
            if now_utc >= stored_ceremony.expires_at.astimezone(timezone.utc):
                self._ceremonies[ceremony.ceremony_id] = AuthenticationCeremony(
                    ceremony_id=stored_ceremony.ceremony_id,
                    subject_id=stored_ceremony.subject_id,
                    device_id=stored_ceremony.device_id,
                    method=stored_ceremony.method,
                    state=CeremonyState.EXPIRED,
                    created_at=stored_ceremony.created_at,
                    expires_at=stored_ceremony.expires_at,
                    attempt_count=stored_ceremony.attempt_count,
                    max_attempts=stored_ceremony.max_attempts,
                )
                raise AuthenticationExpired("Ceremony has expired")

            if stored_ceremony.state in (CeremonyState.CANCELLED, CeremonyState.FAILED):
                raise AuthenticationInvalid(f"Ceremony in terminal state: {stored_ceremony.state}")

            if stored_ceremony.state == CeremonyState.VERIFIED:
                raise AuthenticationReplay("Ceremony was already completed")

            if stored_ceremony.attempt_count >= stored_ceremony.max_attempts:
                self._ceremonies[ceremony.ceremony_id] = AuthenticationCeremony(
                    ceremony_id=stored_ceremony.ceremony_id,
                    subject_id=stored_ceremony.subject_id,
                    device_id=stored_ceremony.device_id,
                    method=stored_ceremony.method,
                    state=CeremonyState.FAILED,
                    created_at=stored_ceremony.created_at,
                    expires_at=stored_ceremony.expires_at,
                    attempt_count=stored_ceremony.attempt_count,
                    max_attempts=stored_ceremony.max_attempts,
                )
                raise AuthenticationLocked("Maximum ceremony attempts exceeded")

            # Increment attempt count
            new_attempts = stored_ceremony.attempt_count + 1
            updated_ceremony = AuthenticationCeremony(
                ceremony_id=stored_ceremony.ceremony_id,
                subject_id=stored_ceremony.subject_id,
                device_id=stored_ceremony.device_id,
                method=stored_ceremony.method,
                state=stored_ceremony.state,
                created_at=stored_ceremony.created_at,
                expires_at=stored_ceremony.expires_at,
                attempt_count=new_attempts,
                max_attempts=stored_ceremony.max_attempts,
            )
            self._ceremonies[ceremony.ceremony_id] = updated_ceremony

            # Verify device proof if required or present
            resolved_device_id = None
            if device_proof is not None and self._device_validator is not None:
                dev_res = self._device_validator.validate(
                    proof=device_proof,
                    expected_subject_id=stored_ceremony.subject_id,
                    now=now,
                )
                if not dev_res.valid:
                    return AuthenticationResult(
                        authenticated=False,
                        subject_id=stored_ceremony.subject_id,
                        session_id=None,
                        authentication_level=AuthenticationLevel.NONE,
                        ceremony_id=ceremony.ceremony_id,
                        reason_code=f"DEVICE_INVALID_{dev_res.reason_code}",
                        authenticated_at=now,
                    )
                resolved_device_id = dev_res.device_id
            elif stored_ceremony.device_id is not None:
                resolved_device_id = stored_ceremony.device_id
            else:
                resolved_device_id = uuid4()

            # Resolve credential
            cred_id = self._ceremony_credentials.get(ceremony.ceremony_id)
            if cred_id is None:
                return AuthenticationResult(
                    authenticated=False,
                    subject_id=stored_ceremony.subject_id,
                    session_id=None,
                    authentication_level=AuthenticationLevel.NONE,
                    ceremony_id=ceremony.ceremony_id,
                    reason_code="CREDENTIAL_NOT_FOUND",
                    authenticated_at=now,
                )

            credential = self._store.get_credential(cred_id)
            if credential is None:
                return AuthenticationResult(
                    authenticated=False,
                    subject_id=stored_ceremony.subject_id,
                    session_id=None,
                    authentication_level=AuthenticationLevel.NONE,
                    ceremony_id=ceremony.ceremony_id,
                    reason_code="CREDENTIAL_NOT_FOUND",
                    authenticated_at=now,
                )

            # Check credential usability
            if not credential.is_usable_at(now):
                reason = "CREDENTIAL_INACTIVE"
                if credential.status == CredentialStatus.REVOKED:
                    reason = "CREDENTIAL_REVOKED"
                elif credential.status == CredentialStatus.EXPIRED or (
                    credential.expires_at is not None and now_utc >= credential.expires_at.astimezone(timezone.utc)
                ):
                    reason = "CREDENTIAL_EXPIRED"
                elif credential.status == CredentialStatus.LOCKED or credential.locked_until is not None:
                    reason = "CREDENTIAL_LOCKED"
                return AuthenticationResult(
                    authenticated=False,
                    subject_id=stored_ceremony.subject_id,
                    session_id=None,
                    authentication_level=AuthenticationLevel.NONE,
                    ceremony_id=ceremony.ceremony_id,
                    reason_code=reason,
                    authenticated_at=now,
                )

            # Verify credential proof
            if not self._verifier.verify(
                credential=credential,
                presented_proof=proof,
                ceremony_id=ceremony.ceremony_id,
                now=now,
            ):
                return AuthenticationResult(
                    authenticated=False,
                    subject_id=stored_ceremony.subject_id,
                    session_id=None,
                    authentication_level=AuthenticationLevel.NONE,
                    ceremony_id=ceremony.ceremony_id,
                    reason_code="INVALID_CREDENTIAL_PROOF",
                    authenticated_at=now,
                )

            # Mark ceremony VERIFIED
            self._ceremonies[ceremony.ceremony_id] = AuthenticationCeremony(
                ceremony_id=stored_ceremony.ceremony_id,
                subject_id=stored_ceremony.subject_id,
                device_id=resolved_device_id,
                method=stored_ceremony.method,
                state=CeremonyState.VERIFIED,
                created_at=stored_ceremony.created_at,
                expires_at=stored_ceremony.expires_at,
                attempt_count=new_attempts,
                max_attempts=stored_ceremony.max_attempts,
            )

            # Mint trusted server session
            target_subject = stored_ceremony.subject_id or credential.subject_id
            session, _ = self._session_service.issue(
                subject_id=target_subject,
                device_id=resolved_device_id,
                authentication_level=AuthenticationLevel.AUTHENTICATED,
                now=now,
            )

            return AuthenticationResult(
                authenticated=True,
                subject_id=target_subject,
                session_id=session.session_id,
                authentication_level=AuthenticationLevel.AUTHENTICATED,
                ceremony_id=ceremony.ceremony_id,
                reason_code="AUTHENTICATED",
                authenticated_at=now,
            )

    def cancel(self, *, ceremony_id: UUID, now: datetime) -> None:
        if not isinstance(ceremony_id, UUID):
            raise TypeError("ceremony_id must be a UUID")
        with self._lock:
            ceremony = self._ceremonies.get(ceremony_id)
            if ceremony is not None:
                self._ceremonies[ceremony_id] = AuthenticationCeremony(
                    ceremony_id=ceremony.ceremony_id,
                    subject_id=ceremony.subject_id,
                    device_id=ceremony.device_id,
                    method=ceremony.method,
                    state=CeremonyState.CANCELLED,
                    created_at=ceremony.created_at,
                    expires_at=ceremony.expires_at,
                    attempt_count=ceremony.attempt_count,
                    max_attempts=ceremony.max_attempts,
                )