from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from threading import RLock
from typing import Final
from uuid import UUID, uuid4


class ApprovalEvidenceError(ValueError):
    """Base error for invalid approval evidence."""


class ApprovalEvidenceExpired(ApprovalEvidenceError):
    """Raised when approval evidence is expired."""


class ApprovalEvidenceInvalid(ApprovalEvidenceError):
    """Raised when approval evidence violates its invariants."""


class ApprovalEvidenceConsumed(ApprovalEvidenceError):
    """Raised when approval evidence has already been consumed."""


@dataclass(frozen=True, slots=True)
class ApprovalEvidence:
    """
    Trusted evidence that a specific transaction was explicitly approved.

    ActionRequest represents requested intent.

    ApprovalEvidence represents trusted approval evidence for the exact
    transaction that may be executed.

    The evidence is bound to:
    - action
    - session
    - subject
    - destination
    - amount
    - currency
    - approval time
    - expiry

    Structural validity is not the same as trusted provenance.
    """

    approval_id: UUID
    action_id: UUID
    session_id: UUID
    subject_id: UUID

    destination_id: str
    amount: Decimal
    currency: str

    approved_at: datetime
    expires_at: datetime

    _issuer_marker: object = field(
        default=None,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        if not isinstance(self.action_id, UUID):
            raise TypeError("action_id must be a UUID")

        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")

        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")

        if not isinstance(self.destination_id, str):
            raise TypeError("destination_id must be a string")

        normalized_destination = self.destination_id.strip()

        if not normalized_destination:
            raise ApprovalEvidenceInvalid(
                "destination_id must not be blank"
            )

        if normalized_destination != self.destination_id:
            raise ApprovalEvidenceInvalid(
                "destination_id must not contain surrounding whitespace"
            )

        if not isinstance(self.amount, Decimal):
            raise TypeError("amount must be a Decimal")

        if not self.amount.is_finite():
            raise ApprovalEvidenceInvalid(
                "amount must be finite"
            )

        if self.amount <= Decimal("0"):
            raise ApprovalEvidenceInvalid(
                "amount must be strictly positive"
            )

        if not isinstance(self.currency, str):
            raise TypeError("currency must be a string")

        normalized_currency = self.currency.strip()

        if (
            len(normalized_currency) != 3
            or not normalized_currency.isalpha()
            or normalized_currency.upper() != normalized_currency
            or normalized_currency != self.currency
        ):
            raise ApprovalEvidenceInvalid(
                "currency must be an uppercase three-letter code"
            )

        if not isinstance(self.approved_at, datetime):
            raise TypeError("approved_at must be a datetime")

        if not isinstance(self.expires_at, datetime):
            raise TypeError("expires_at must be a datetime")

        if self.approved_at.tzinfo is None:
            raise ApprovalEvidenceInvalid(
                "approved_at must be timezone-aware"
            )

        if self.expires_at.tzinfo is None:
            raise ApprovalEvidenceInvalid(
                "expires_at must be timezone-aware"
            )

        approved_at_utc = self.approved_at.astimezone(timezone.utc)
        expires_at_utc = self.expires_at.astimezone(timezone.utc)

        if expires_at_utc <= approved_at_utc:
            raise ApprovalEvidenceInvalid(
                "expires_at must be later than approved_at"
            )

    def is_trusted(self) -> bool:
        """Return whether trusted issuer provenance is attached."""
        return self._issuer_marker is _INTERNAL_APPROVAL_MARKER

    def require_trusted(self) -> None:
        """Fail closed unless trusted issuer provenance exists."""
        if not self.is_trusted():
            raise ApprovalEvidenceInvalid(
                "approval evidence lacks trusted issuer provenance"
            )

    def is_expired(self, now: datetime) -> bool:
        """Return whether this approval is expired at the supplied time."""
        if not isinstance(now, datetime):
            raise TypeError("now must be a datetime")

        if now.tzinfo is None:
            raise ApprovalEvidenceInvalid(
                "now must be timezone-aware"
            )

        return now.astimezone(timezone.utc) >= (
            self.expires_at.astimezone(timezone.utc)
        )

    def require_valid_at(self, now: datetime) -> None:
        """
        Fail closed unless the evidence is trusted and unexpired.
        """
        self.require_trusted()

        if self.is_expired(now):
            raise ApprovalEvidenceExpired(
                "approval evidence has expired"
            )

    def matches_transaction(
        self,
        *,
        action_id: UUID,
        session_id: UUID,
        subject_id: UUID,
        destination_id: str,
        amount: Decimal,
        currency: str,
    ) -> bool:
        """
        Require exact transaction binding.

        Any change to a security-sensitive transaction parameter invalidates
        the approval.
        """
        return (
            self.action_id == action_id
            and self.session_id == session_id
            and self.subject_id == subject_id
            and self.destination_id == destination_id
            and self.amount == amount
            and self.currency == currency
        )


@dataclass(frozen=True, slots=True)
class _ApprovalIssuerCapability:
    """Opaque capability required to issue trusted approval evidence."""

    nonce: UUID


_INTERNAL_APPROVAL_ISSUER_CAPABILITY: Final[
    _ApprovalIssuerCapability
] = _ApprovalIssuerCapability(
    nonce=uuid4(),
)


_INTERNAL_APPROVAL_MARKER: Final[object] = object()


class TrustedApprovalEvidenceIssuer:
    """
    Narrow internal issuance boundary for approval evidence.

    Request payloads, ActionRequest fields, external content, and
    conversational claims cannot manufacture this capability.
    """

    __slots__ = ()

    @staticmethod
    def _validate_capability(
        capability: _ApprovalIssuerCapability,
    ) -> None:
        if not isinstance(
            capability,
            _ApprovalIssuerCapability,
        ):
            raise PermissionError(
                "trusted approval issuer capability is required"
            )

        if capability is not _INTERNAL_APPROVAL_ISSUER_CAPABILITY:
            raise PermissionError(
                "invalid trusted approval issuer capability"
            )

    @classmethod
    def issue(
        cls,
        *,
        capability: _ApprovalIssuerCapability,
        action_id: UUID,
        session_id: UUID,
        subject_id: UUID,
        destination_id: str,
        amount: Decimal,
        currency: str,
        approved_at: datetime,
        expires_at: datetime,
    ) -> ApprovalEvidence:
        """Issue trusted approval evidence."""
        cls._validate_capability(capability)

        return ApprovalEvidence(
            approval_id=uuid4(),
            action_id=action_id,
            session_id=session_id,
            subject_id=subject_id,
            destination_id=destination_id,
            amount=amount,
            currency=currency,
            approved_at=approved_at,
            expires_at=expires_at,
            _issuer_marker=_INTERNAL_APPROVAL_MARKER,
        )


def _issue_internal_approval_evidence(
    *,
    action_id: UUID,
    session_id: UUID,
    subject_id: UUID,
    destination_id: str,
    amount: Decimal,
    currency: str,
    approved_at: datetime,
    expires_at: datetime,
) -> ApprovalEvidence:
    """
    Private application hook for the future approval subsystem.

    This is the only current internal issuance path.
    """
    return TrustedApprovalEvidenceIssuer.issue(
        capability=_INTERNAL_APPROVAL_ISSUER_CAPABILITY,
        action_id=action_id,
        session_id=session_id,
        subject_id=subject_id,
        destination_id=destination_id,
        amount=amount,
        currency=currency,
        approved_at=approved_at,
        expires_at=expires_at,
    )


class ApprovalEvidenceRegistry:
    """
    Thread-safe single-use registry for trusted approval evidence.

    Consumption is atomic.

    The registry does not create authority. It only prevents the same
    trusted approval evidence from being successfully consumed twice.
    """

    __slots__ = (
        "_consumed",
        "_lock",
    )

    def __init__(self) -> None:
        self._consumed: set[UUID] = set()
        self._lock = RLock()

    def consume(
        self,
        approval: ApprovalEvidence,
        *,
        now: datetime,
    ) -> None:
        """
        Atomically validate and consume one approval.

        The approval is consumed only after trusted provenance, expiry,
        and single-use checks succeed.
        """
        if not isinstance(approval, ApprovalEvidence):
            raise ApprovalEvidenceInvalid(
                "approval evidence is missing or invalid"
            )

        approval.require_valid_at(now)

        with self._lock:
            if approval.approval_id in self._consumed:
                raise ApprovalEvidenceConsumed(
                    "approval evidence has already been consumed"
                )

            self._consumed.add(approval.approval_id)

    def is_consumed(self, approval_id: UUID) -> bool:
        """Return whether an approval ID has already been consumed."""
        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        with self._lock:
            return approval_id in self._consumed