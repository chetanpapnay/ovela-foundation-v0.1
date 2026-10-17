from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Final
from uuid import UUID


class FinancialAccountContextError(Exception):
    """Base exception for financial-account context failures."""


class FinancialAccountContextExpired(FinancialAccountContextError):
    """Raised when a financial-account context is expired."""


class FinancialAccountContextInvalid(FinancialAccountContextError):
    """Raised when a financial-account context is invalid or untrusted."""


@dataclass(frozen=True, slots=True)
class FinancialAccountContext:
    """
    Trusted execution context binding a financial account to a subject and session.

    This context deliberately separates financial-account identity from session
    identity. A session identifies an authenticated interaction; an account_id
    identifies the financial account against which a financial operation may
    execute.

    Direct construction is intentionally untrusted. Only the trusted issuer
    creates contexts accepted by the execution boundary.
    """

    account_id: UUID
    subject_id: UUID
    session_id: UUID
    issued_at: datetime
    expires_at: datetime
    _issuer_marker: object | None = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.account_id, UUID):
            raise TypeError("account_id must be a UUID")

        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")

        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")

        if not isinstance(self.issued_at, datetime):
            raise TypeError("issued_at must be a datetime")

        if not isinstance(self.expires_at, datetime):
            raise TypeError("expires_at must be a datetime")

        if self.issued_at.tzinfo is None:
            raise FinancialAccountContextInvalid(
                "issued_at must be timezone-aware"
            )

        if self.expires_at.tzinfo is None:
            raise FinancialAccountContextInvalid(
                "expires_at must be timezone-aware"
            )

        issued_at_utc = self.issued_at.astimezone(timezone.utc)
        expires_at_utc = self.expires_at.astimezone(timezone.utc)

        if expires_at_utc <= issued_at_utc:
            raise FinancialAccountContextInvalid(
                "expires_at must be later than issued_at"
            )

    def is_trusted(self) -> bool:
        return self._issuer_marker is _INTERNAL_ACCOUNT_CONTEXT_MARKER

    def require_trusted(self) -> None:
        if not self.is_trusted():
            raise FinancialAccountContextInvalid(
                "financial account context is not trusted"
            )

    def is_expired(self, now: datetime) -> bool:
        if not isinstance(now, datetime):
            raise TypeError("now must be a datetime")

        if now.tzinfo is None:
            raise FinancialAccountContextInvalid(
                "now must be timezone-aware"
            )

        return (
            now.astimezone(timezone.utc)
            >= self.expires_at.astimezone(timezone.utc)
        )

    def require_valid_at(self, now: datetime) -> None:
        self.require_trusted()

        if self.is_expired(now):
            raise FinancialAccountContextExpired(
                "financial account context has expired"
            )


@dataclass(frozen=True, slots=True)
class _FinancialAccountContextIssuerCapability:
    """
    Opaque capability required to issue trusted financial-account contexts.

    The capability is intentionally not exported as a public authority
    mechanism. The singleton below is process-local protection against
    ordinary caller-controlled construction.
    """

    nonce: UUID


_INTERNAL_ACCOUNT_CONTEXT_ISSUER_CAPABILITY: Final[
    _FinancialAccountContextIssuerCapability
] = _FinancialAccountContextIssuerCapability(nonce=UUID(
    "3f4f2a6d-7d7c-4c1a-8f3d-4a2a9a8e5b71"
))

_INTERNAL_ACCOUNT_CONTEXT_MARKER: Final[object] = object()


class TrustedFinancialAccountContextIssuer:
    """
    Restricted issuer for trusted financial-account execution contexts.

    The issuer requires the exact internal capability object. Possessing the
    public class alone does not grant authority to mint trusted contexts.
    """

    @staticmethod
    def issue(
        *,
        capability: _FinancialAccountContextIssuerCapability,
        account_id: UUID,
        subject_id: UUID,
        session_id: UUID,
        issued_at: datetime,
        expires_at: datetime,
    ) -> FinancialAccountContext:
        if capability is not _INTERNAL_ACCOUNT_CONTEXT_ISSUER_CAPABILITY:
            raise FinancialAccountContextInvalid(
                "invalid financial-account context issuer capability"
            )

        context = FinancialAccountContext(
            account_id=account_id,
            subject_id=subject_id,
            session_id=session_id,
            issued_at=issued_at,
            expires_at=expires_at,
            _issuer_marker=_INTERNAL_ACCOUNT_CONTEXT_MARKER,
        )

        context.require_trusted()

        return context


def _issue_internal_financial_account_context(
    *,
    account_id: UUID,
    subject_id: UUID,
    session_id: UUID,
    issued_at: datetime,
    expires_at: datetime,
) -> FinancialAccountContext:
    """
    Internal test/application seam for trusted issuance.

    Production authentication/account-binding infrastructure should be the
    real caller of TrustedFinancialAccountContextIssuer.
    """

    return TrustedFinancialAccountContextIssuer.issue(
        capability=_INTERNAL_ACCOUNT_CONTEXT_ISSUER_CAPABILITY,
        account_id=account_id,
        subject_id=subject_id,
        session_id=session_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )