"""
Trusted approval evidence and single-use consumption stores.

ApprovalEvidence is trusted proof that one exact transaction was explicitly
approved. This module also defines the ``ApprovalStore`` protocol that every
single-use consumption backend implements, plus the in-memory implementation
and the legacy ``ApprovalEvidenceRegistry``.

Backends
--------
- ``InMemoryApprovalStore``: process-local, thread-safe. Not shared between
  workers or restarts.
- ``ApprovalEvidenceRegistry``: the M1-M4 registry, preserved exactly. It adds
  an optional legacy ``ApprovalConsumptionStore`` for shared consumption.
- ``app.durable_approval_store.DurableApprovalStore``: tenant-scoped, durable,
  atomic consumption through a single-statement SQL UPDATE.

Tenant semantics
----------------
``ApprovalEvidence.tenant_id`` is optional so legacy evidence stays valid.
Every store requires ``evidence.tenant_id == tenant_id`` at consumption time.
The durable store additionally rejects ``None`` on either side (no implicit
system tenant).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from threading import RLock
from typing import Final, Protocol, cast, runtime_checkable
from uuid import UUID, uuid4

from .approval_store import (
    ApprovalConsumptionStore,
    store_from_environment,
)


# Tolerance for clock differences between the issuer and the verifier.
# Evidence dated further in the future than this is rejected.
_MAX_CLOCK_SKEW: Final[timedelta] = timedelta(seconds=5)


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
    - tenant (optional; required by durable stores)

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

    # Declared last so legacy positional constructions remain valid.
    tenant_id: UUID | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        if not isinstance(self.action_id, UUID):
            raise TypeError("action_id must be a UUID")

        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")

        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")

        if self.tenant_id is not None and not isinstance(self.tenant_id, UUID):
            raise TypeError("tenant_id must be a UUID or None")

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

    def is_not_yet_valid(self, now: datetime) -> bool:
        """
        Return whether this approval is dated in the future.

        A small clock-skew tolerance is allowed so evidence issued a
        moment ago is not rejected because of minor clock differences.
        """
        if not isinstance(now, datetime):
            raise TypeError("now must be a datetime")

        if now.tzinfo is None:
            raise ApprovalEvidenceInvalid(
                "now must be timezone-aware"
            )

        return (
            self.approved_at.astimezone(timezone.utc)
            > now.astimezone(timezone.utc) + _MAX_CLOCK_SKEW
        )

    def require_valid_at(self, now: datetime) -> None:
        """
        Fail closed unless the evidence is trusted, unexpired, and
        not dated in the future.
        """
        self.require_trusted()

        if self.is_expired(now):
            raise ApprovalEvidenceExpired(
                "approval evidence has expired"
            )

        if self.is_not_yet_valid(now):
            raise ApprovalEvidenceInvalid(
                "approval evidence is not yet valid"
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
        tenant_id: UUID | None = None,
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
            tenant_id=tenant_id,
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
    tenant_id: UUID | None = None,
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
        tenant_id=tenant_id,
    )


@runtime_checkable
class ApprovalStore(Protocol):
    """
    Single-use consumption boundary for trusted approval evidence.

    Implementations must make ``consume`` atomic: for a given approval,
    exactly one call may ever return ``True``, even under concurrency.
    """

    __slots__ = ()

    def register(self, evidence: ApprovalEvidence) -> None:
        """
        Record trusted evidence so it can later be consumed.

        Raises ApprovalEvidenceInvalid for untrusted, malformed or duplicate
        evidence. Never silently overwrites an existing registration.
        """
        ...

    def consume(
        self,
        evidence: ApprovalEvidence,
        now: datetime,
        *,
        tenant_id: UUID | None = None,
        executor_id: UUID | None = None,
    ) -> bool:
        """
        Atomically consume evidence.

        Returns True only for the single successful consumption and False
        when the approval cannot be consumed because it was already used.
        Invalid, untrusted, expired or cross-tenant evidence raises.
        """
        ...

    def is_consumed(self, approval_id: UUID) -> bool:
        """Return whether the approval has been consumed."""
        ...


def _validate_for_consumption(
    evidence: object,
    now: datetime,
    tenant_id: UUID | None,
) -> ApprovalEvidence:
    """
    Shared pre-consumption validation: type, provenance, validity window,
    and tenant binding. Raises; never returns a partially valid result.
    """
    if not isinstance(evidence, ApprovalEvidence):
        raise ApprovalEvidenceInvalid(
            "approval evidence is missing or invalid"
        )

    evidence.require_valid_at(now)

    if tenant_id is not None and not isinstance(tenant_id, UUID):
        raise TypeError("tenant_id must be a UUID or None")

    if evidence.tenant_id != tenant_id:
        raise ApprovalEvidenceInvalid(
            "approval evidence tenant does not match the consuming tenant"
        )

    return evidence


class InMemoryApprovalStore(ApprovalStore):
    """
    Thread-safe, process-local ``ApprovalStore``.

    Consumption is atomic within the process (lock). It is NOT shared
    between worker processes or preserved across restarts; use a durable
    store for that. Registration is optional for consumption, which keeps
    M1-M4 behavior: evidence may be consumed without prior ``register``.
    """

    __slots__ = (
        "_consumed",
        "_lock",
        "_registered",
    )

    def __init__(self) -> None:
        self._consumed: set[UUID] = set()
        self._registered: set[UUID] = set()
        self._lock = RLock()

    def register(self, evidence: ApprovalEvidence) -> None:
        if not isinstance(evidence, ApprovalEvidence):
            raise ApprovalEvidenceInvalid(
                "approval evidence is missing or invalid"
            )

        evidence.require_trusted()

        with self._lock:
            if evidence.approval_id in self._registered:
                raise ApprovalEvidenceInvalid(
                    "approval evidence is already registered"
                )

            self._registered.add(evidence.approval_id)

    def consume(
        self,
        evidence: ApprovalEvidence,
        now: datetime,
        *,
        tenant_id: UUID | None = None,
        executor_id: UUID | None = None,
    ) -> bool:
        validated = _validate_for_consumption(evidence, now, tenant_id)

        with self._lock:
            if validated.approval_id in self._consumed:
                return False

            self._consumed.add(validated.approval_id)
            return True

    def is_consumed(self, approval_id: UUID) -> bool:
        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        with self._lock:
            return approval_id in self._consumed


_MISSING_NOW: Final[datetime] = cast(datetime, object())


class ApprovalEvidenceRegistry(InMemoryApprovalStore):
    """
    Thread-safe single-use registry for trusted approval evidence.

    This is the M1-M4 registry, preserved: same constructor, same
    exceptions, same lock behavior. It is now an ``InMemoryApprovalStore``.

    Consumption is atomic within the process (lock) and, when a shared
    ApprovalConsumptionStore is configured, atomic across processes and
    restarts (the store's atomic first-use insert).

    If the shared store fails for any reason, consumption is refused
    (fail closed). The registry never falls back to memory-only
    consumption when a store was configured.

    Unlike the base store, ``consume`` here keeps its legacy contract:
    it returns None on success and RAISES ``ApprovalEvidenceConsumed`` on
    reuse instead of returning False.

    The registry does not create authority. It only prevents the same
    trusted approval evidence from being successfully consumed twice.
    """

    __slots__ = ("_store",)

    def __init__(
        self,
        store: ApprovalConsumptionStore | None = None,
    ) -> None:
        if store is not None and not isinstance(
            store,
            ApprovalConsumptionStore,
        ):
            raise TypeError(
                "store must be an ApprovalConsumptionStore or None"
            )

        super().__init__()
        self._store = store

    @classmethod
    def from_environment(cls) -> "ApprovalEvidenceRegistry":
        """
        Build a registry using the shared SQL Server store when
        OVELA_APPROVAL_DB_CONNECTION is set, otherwise memory only.
        """
        return cls(store=store_from_environment())

    def consume(  # type: ignore[override]
        self,
        approval: ApprovalEvidence,
        now: datetime = _MISSING_NOW,
        *,
        tenant_id: UUID | None = None,
        executor_id: UUID | None = None,
    ) -> None:
        """
        Atomically validate and consume one approval.

        The approval is consumed only after trusted provenance, expiry,
        not-before, tenant binding, and single-use checks succeed.

        ``executor_id`` is accepted for protocol compatibility and is not
        recorded by the in-memory registry.
        """
        if now is _MISSING_NOW:
            raise TypeError(
                "consume() missing required argument: 'now'"
            )

        validated = _validate_for_consumption(approval, now, tenant_id)

        with self._lock:
            if validated.approval_id in self._consumed:
                raise ApprovalEvidenceConsumed(
                    "approval evidence has already been consumed"
                )

            if self._store is not None:
                try:
                    first_use = self._store.try_consume(
                        validated.approval_id,
                        validated.expires_at,
                    )
                except Exception as exc:
                    raise ApprovalEvidenceInvalid(
                        "approval store unavailable; failing closed"
                    ) from exc

                if first_use is not True:
                    self._consumed.add(validated.approval_id)
                    raise ApprovalEvidenceConsumed(
                        "approval evidence has already been consumed"
                    )

            self._consumed.add(validated.approval_id)

    def is_consumed(self, approval_id: UUID) -> bool:
        """Return whether an approval ID has already been consumed."""
        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        with self._lock:
            if approval_id in self._consumed:
                return True

            if self._store is not None:
                return self._store.is_consumed(approval_id)

            return False