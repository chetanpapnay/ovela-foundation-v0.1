"""
OVELA / JURIX Identity and Credential Persistence Contracts.

Security guarantees:
    - Passwords and raw secrets are never stored in plaintext.
    - Revoked, locked, or expired credentials cannot authenticate.
    - Storage failures raise AuthenticationStorageUnavailable and fail closed.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
import threading
from typing import Protocol
from uuid import UUID

from .identity import IdentitySubject


class CredentialKind(StrEnum):
    PASSWORD = "PASSWORD"
    PASSKEY = "PASSKEY"
    TOTP = "TOTP"
    RECOVERY_CODE = "RECOVERY_CODE"


class CredentialStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    LOCKED = "LOCKED"


class AuthenticationError(Exception):
    """Base error for authentication and credential verification."""


class AuthenticationStorageUnavailable(AuthenticationError):
    """Raised when the identity persistence layer fails or is unreachable."""


class AuthenticationLocked(AuthenticationError):
    """Raised when an account or credential is locked due to excessive failed attempts."""


@dataclass(frozen=True, slots=True)
class CredentialRecord:
    credential_id: UUID
    subject_id: UUID
    kind: CredentialKind
    status: CredentialStatus
    verifier_reference: str
    created_at: datetime
    expires_at: datetime | None
    failed_attempts: int
    locked_until: datetime | None

    def __post_init__(self) -> None:
        if not isinstance(self.credential_id, UUID):
            raise TypeError("credential_id must be a UUID")
        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        if not isinstance(self.kind, CredentialKind):
            raise TypeError("kind must be a CredentialKind")
        if not isinstance(self.status, CredentialStatus):
            raise TypeError("status must be a CredentialStatus")
        if not isinstance(self.verifier_reference, str) or not self.verifier_reference.strip():
            raise ValueError("verifier_reference must be a non-empty string")
        if not isinstance(self.created_at, datetime) or self.created_at.tzinfo is None:
            raise ValueError("created_at must be a timezone-aware datetime")
        if self.expires_at is not None:
            if not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None:
                raise ValueError("expires_at must be a timezone-aware datetime")
            if self.expires_at.astimezone(timezone.utc) <= self.created_at.astimezone(timezone.utc):
                raise ValueError("expires_at must be strictly later than created_at")
        if not isinstance(self.failed_attempts, int) or self.failed_attempts < 0:
            raise ValueError("failed_attempts must be a non-negative integer")
        if self.locked_until is not None:
            if not isinstance(self.locked_until, datetime) or self.locked_until.tzinfo is None:
                raise ValueError("locked_until must be a timezone-aware datetime")

    def is_usable_at(self, now: datetime) -> bool:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ValueError("now must be a timezone-aware datetime")

        now_utc = now.astimezone(timezone.utc)

        if self.status != CredentialStatus.ACTIVE:
            return False

        if self.expires_at is not None and now_utc >= self.expires_at.astimezone(timezone.utc):
            return False

        if self.locked_until is not None and now_utc < self.locked_until.astimezone(timezone.utc):
            return False

        return True


class IdentityStore(Protocol):
    def get_subject(self, subject_id: UUID) -> IdentitySubject | None:
        ...

    def save_subject(self, subject: IdentitySubject) -> None:
        ...

    def get_credential(self, credential_id: UUID) -> CredentialRecord | None:
        ...

    def save_credential(self, credential: CredentialRecord) -> None:
        ...

    def get_device_binding(self, device_id: UUID) -> object | None:
        ...

    def save_device_binding(self, binding: object) -> None:
        ...


class InMemoryIdentityStore:
    """Thread-safe reference implementation for tests and local runtime."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._subjects: dict[UUID, IdentitySubject] = {}
        self._credentials: dict[UUID, CredentialRecord] = {}
        self._device_bindings: dict[UUID, object] = {}

    def get_subject(self, subject_id: UUID) -> IdentitySubject | None:
        if not isinstance(subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        with self._lock:
            return self._subjects.get(subject_id)

    def save_subject(self, subject: IdentitySubject) -> None:
        if not isinstance(subject, IdentitySubject):
            raise TypeError("subject must be an IdentitySubject")
        with self._lock:
            self._subjects[subject.subject_id] = subject

    def get_credential(self, credential_id: UUID) -> CredentialRecord | None:
        if not isinstance(credential_id, UUID):
            raise TypeError("credential_id must be a UUID")
        with self._lock:
            return self._credentials.get(credential_id)

    def save_credential(self, credential: CredentialRecord) -> None:
        if not isinstance(credential, CredentialRecord):
            raise TypeError("credential must be a CredentialRecord")
        with self._lock:
            self._credentials[credential.credential_id] = credential

    def get_device_binding(self, device_id: UUID) -> object | None:
        if not isinstance(device_id, UUID):
            raise TypeError("device_id must be a UUID")
        with self._lock:
            return self._device_bindings.get(device_id)

    def save_device_binding(self, binding: object) -> None:
        if not hasattr(binding, "device_id") or not isinstance(getattr(binding, "device_id"), UUID):
            raise TypeError("binding must have a valid device_id UUID")
        with self._lock:
            self._device_bindings[getattr(binding, "device_id")] = binding