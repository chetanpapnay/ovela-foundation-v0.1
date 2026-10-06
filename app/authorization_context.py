from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Final
from uuid import UUID, uuid4


class AuthorizationState(StrEnum):
    """
    Authentication state established by a trusted security subsystem.

    These values are security facts only when issued by the trusted
    authorization-context issuer. They must never be accepted directly
    from an untrusted request.
    """

    UNVERIFIED = "UNVERIFIED"
    AUTHENTICATED = "AUTHENTICATED"
    STEP_UP_VERIFIED = "STEP_UP_VERIFIED"


class AuthorizationContextError(ValueError):
    """Base error for invalid trusted authorization contexts."""


class AuthorizationContextExpired(AuthorizationContextError):
    """Raised when an authorization context is expired."""


class AuthorizationContextInvalid(AuthorizationContextError):
    """Raised when an authorization context violates its invariants."""


@dataclass(frozen=True, slots=True)
class AuthorizationContext:
    """
    Trusted authorization context.

    This object deliberately does not derive security state from an
    ActionRequest or any externally supplied content.

    The eventual authentication/session subsystem must establish the
    values represented here before a sensitive action reaches the
    execution boundary.
    """

    context_id: UUID
    session_id: UUID
    subject_id: UUID
    state: AuthorizationState
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.context_id, UUID):
            raise TypeError("context_id must be a UUID")

        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")

        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")

        if not isinstance(self.state, AuthorizationState):
            raise TypeError("state must be an AuthorizationState")

        if not isinstance(self.issued_at, datetime):
            raise TypeError("issued_at must be a datetime")

        if not isinstance(self.expires_at, datetime):
            raise TypeError("expires_at must be a datetime")

        if self.issued_at.tzinfo is None:
            raise AuthorizationContextInvalid(
                "issued_at must be timezone-aware"
            )

        if self.expires_at.tzinfo is None:
            raise AuthorizationContextInvalid(
                "expires_at must be timezone-aware"
            )

        issued_at_utc = self.issued_at.astimezone(timezone.utc)
        expires_at_utc = self.expires_at.astimezone(timezone.utc)

        if expires_at_utc <= issued_at_utc:
            raise AuthorizationContextInvalid(
                "expires_at must be later than issued_at"
            )

    def is_expired(self, now: datetime) -> bool:
        """
        Determine whether this context is expired at the supplied time.

        The caller must provide an explicit time so authorization decisions
        remain deterministic and testable.
        """
        if not isinstance(now, datetime):
            raise TypeError("now must be a datetime")

        if now.tzinfo is None:
            raise AuthorizationContextInvalid(
                "now must be timezone-aware"
            )

        return now.astimezone(timezone.utc) >= self.expires_at.astimezone(
            timezone.utc
        )

    def require_valid_at(self, now: datetime) -> None:
        """
        Fail closed if the context is expired.
        """
        if self.is_expired(now):
            raise AuthorizationContextExpired(
                "authorization context has expired"
            )

    def permits_authenticated(self) -> bool:
        """
        Return whether the context represents authenticated access.
        """
        return self.state in {
            AuthorizationState.AUTHENTICATED,
            AuthorizationState.STEP_UP_VERIFIED,
        }

    def permits_step_up(self) -> bool:
        """
        Return whether the context represents completed step-up
        verification.
        """
        return self.state is AuthorizationState.STEP_UP_VERIFIED


@dataclass(frozen=True, slots=True)
class _IssuerCapability:
    """
    Internal capability required to issue an AuthorizationContext.

    The capability is intentionally not representable by a caller-provided
    string, boolean, UUID, or enum value.

    A future authentication/session subsystem will own the issuer and the
    evidence required to obtain this capability.
    """

    nonce: UUID


_INTERNAL_ISSUER_CAPABILITY: Final[_IssuerCapability] = _IssuerCapability(
    nonce=uuid4(),
)


class TrustedAuthorizationContextIssuer:
    """
    Narrow issuance boundary for trusted authorization contexts.

    This is deliberately separate from ActionRequest.

    The current implementation establishes the structural boundary only.
    A production authentication subsystem must become the sole legitimate
    caller that possesses the issuer capability and can establish the
    underlying authentication evidence.

    No request payload, external content, threat assessment, or conversational
    statement can manufacture this capability.
    """

    __slots__ = ()

    @staticmethod
    def _validate_capability(
        capability: _IssuerCapability,
    ) -> None:
        if not isinstance(capability, _IssuerCapability):
            raise PermissionError(
                "trusted issuer capability is required"
            )

        if capability is not _INTERNAL_ISSUER_CAPABILITY:
            raise PermissionError(
                "invalid trusted issuer capability"
            )

    @classmethod
    def issue(
        cls,
        *,
        capability: _IssuerCapability,
        session_id: UUID,
        subject_id: UUID,
        state: AuthorizationState,
        issued_at: datetime,
        expires_at: datetime,
    ) -> AuthorizationContext:
        """
        Issue a trusted authorization context.

        This method is intentionally capability-gated. It must not be exposed
        as a generic API endpoint or called from untrusted request handling.
        """
        cls._validate_capability(capability)

        return AuthorizationContext(
            context_id=uuid4(),
            session_id=session_id,
            subject_id=subject_id,
            state=state,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def _issue_internal_authorization_context(
    *,
    session_id: UUID,
    subject_id: UUID,
    state: AuthorizationState,
    issued_at: datetime,
    expires_at: datetime,
) -> AuthorizationContext:
    """
    Internal application hook for the future authentication subsystem.

    This function is intentionally private. It exists so the authentication
    layer can later be introduced without allowing ActionRequest or external
    content to become an authorization authority.
    """
    return TrustedAuthorizationContextIssuer.issue(
        capability=_INTERNAL_ISSUER_CAPABILITY,
        session_id=session_id,
        subject_id=subject_id,
        state=state,
        issued_at=issued_at,
        expires_at=expires_at,
    )