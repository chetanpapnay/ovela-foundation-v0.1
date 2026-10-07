"""Ovela Foundation - Milestone M8: External Financial Rail Adapters & Inbound Webhook Ingestion.

This module provides:

* Rail types: ``RailSubmissionStatus``, ``RailInstruction``,
  ``RailSubmissionResult`` and the ``FinancialRailAdapter`` protocol.
* Fail-closed helpers: ``coerce_submission_result`` and ``safe_submit`` map
  exceptions and malformed adapter output to ``UNKNOWN``
  (``retryable=True, authoritative=False``).
* ``PaymentRailAdapterBridge``, which adapts a ``FinancialRailAdapter`` to the
  M7 ``PaymentRailAdapter`` protocol so the M7 ``OutboxDispatcher`` can drive
  M8 rails unchanged.
* ``MockBankRailAdapter``, a pathological mock rail with configurable behaviour
  modes and HMAC webhook signing/verification for end-to-end tests.
* Webhook evidence: ``VerifiedWebhookEvidence`` and
  ``verify_webhook_signature`` (HMAC-SHA256 over the exact raw body bytes,
  constant-time comparison).
* ``RailEventReconciliationService``, which ingests verified webhook evidence
  idempotently, correlates it to a durable execution, binds it to the
  monetary terms of the original payment intent and advances the M6 state
  machine.

Design notes
------------
* External content is evidence, never authority. A webhook can never change an
  amount or currency. The amount and currency come from the M6
  ``PaymentIntent`` and a webhook that disagrees is flagged
  ``RECONCILIATION_CONFLICT`` and mutates nothing.
* Fail closed. Timeouts, connection resets, ambiguous provider errors and
  malformed adapter output are ``UNKNOWN`` with ``retryable=True`` and
  ``authoritative=False``. They never assume success or failure.
* Atomicity and the M6 engine. ``DurableTransactionEngine`` opens its own
  connection and transaction per call. Calling it while this service holds an
  open ``BEGIN IMMEDIATE`` transaction would deadlock on SQLite and would
  split the work across two connections elsewhere. The service therefore
  keeps each of its own transactions short and runs the engine transition
  between them, in a crash-safe way:

  1. The first transaction atomically deduplicates and records the webhook as
     ``RECEIVED``. Uniqueness on ``(tenant_id, provider, idempotency_key)``
     and ``(tenant_id, provider, provider_event_id)`` is enforced by the
     database.
  2. Correlation, monetary binding and the state transition then run through
     the engine's public API, using optimistic ``expected_version``
     compare-and-set.
  3. The second transaction marks the record ``PROCESSED`` (or
     ``QUARANTINED`` / ``CONFLICT`` / ``DEFERRED``).

  A crash between steps leaves the record ``RECEIVED``. A redelivery resumes
  from the stored evidence, and terminal states make the transition a safe
  no-op, so replays cannot double-apply.
* Duplicates (``PROCESSED`` records) return ``(True, "DUPLICATE_IDEMPOTENT")``
  with zero side effects. ``CONFLICT`` records stay conflicted.
  ``QUARANTINED``, ``DEFERRED`` and ``RECEIVED`` records are re-evaluated on
  redelivery, because the missing correlation or ordering may have resolved.
* Terminal executions (``SETTLED`` / ``FAILED``) make out-of-order or duplicate
  webhooks a safe no-op (``NOOP_TERMINAL``). A webhook for an execution not
  yet ``SUBMITTED`` or ``UNKNOWN`` is deferred rather than guessed at.
* ``UNKNOWN -> SETTLED/FAILED`` is passed to the engine with
  ``reconciled=True``, since verified provider evidence is the reconciliation.
* The service owns two new tables (``rail_webhook_events`` and
  ``rail_provider_executions``, created by ``ensure_schema``). Nothing in the
  M6 or M7 schema is altered.
* Money is never a float.
* Supported dialects: ``"sqlite"`` (qmark params, ``BEGIN IMMEDIATE``) and
  ``"postgres"`` (``%s`` params).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import logging
import re
import threading
import uuid
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Callable, Dict, Iterator, List, Optional, Protocol, Sequence, Tuple
from uuid import UUID

try:  # Python 3.11+
    from enum import StrEnum
except ImportError:  # pragma: no cover - compatibility for older interpreters

    class StrEnum(str, Enum):  # type: ignore[no-redef]
        """Minimal ``StrEnum`` backport."""

        def __str__(self) -> str:
            return str(self.value)


from app.outbox_dispatcher import (
    PaymentInstruction,
    RailDispatchResult,
    RailDispatchStatus,
)
from app.transaction_engine import (
    TERMINAL_STATES,
    ConcurrentModificationError,
    InvalidStateTransitionError,
    TransactionExecutionState,
    TransactionNotFoundError,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RailAdapterError(Exception):
    """Base class for all rail adapter and webhook errors."""


class WebhookVerificationError(RailAdapterError):
    """Raised when a webhook fails signature verification or cannot be parsed."""


class RailIdempotencyConflictError(RailAdapterError):
    """Raised when a provider idempotency key is reused with a different instruction."""


class ProviderLinkConflictError(RailAdapterError):
    """Raised when a provider execution id is already linked to a different execution."""


class ReconciliationError(RailAdapterError):
    """Raised when reconciliation cannot complete; the webhook is left for retry."""


class ReconciliationConflictError(ReconciliationError):
    """Raised (when ``raise_on_conflict=True``) after a conflict has been flagged."""


# ---------------------------------------------------------------------------
# Rail types
# ---------------------------------------------------------------------------


class RailSubmissionStatus(StrEnum):
    ACCEPTED = "ACCEPTED"
    PENDING = "PENDING"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RailInstruction:
    """Immutable payment instruction handed to a financial rail."""

    transaction_id: str
    amount: Decimal
    currency: str
    destination_id: str


@dataclass(frozen=True)
class RailSubmissionResult:
    """Outcome reported by (or synthesised for) a rail submission."""

    status: RailSubmissionStatus
    provider_execution_id: str | None
    provider_reference: str | None
    provider_code: str | None
    provider_message: str | None
    retryable: bool
    authoritative: bool
    observed_at: datetime


@dataclass(frozen=True)
class VerifiedWebhookEvidence:
    """Webhook content whose signature has been verified. Evidence, never authority."""

    webhook_id: UUID
    tenant_id: UUID
    provider: str
    idempotency_key: str
    provider_event_id: str | None
    event_type: str
    amount: Decimal
    currency: str
    transaction_execution_id: UUID | None
    provider_execution_id: str | None
    status: str
    received_at: datetime


class FinancialRailAdapter(Protocol):
    """Protocol every external financial rail adapter implements."""

    def submit(self, instruction: RailInstruction, idempotency_key: str) -> RailSubmissionResult: ...

    def verify_webhook(
        self, headers: Mapping[str, str], raw_body: bytes, secret: bytes
    ) -> VerifiedWebhookEvidence: ...


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f+00:00"
_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_SUPPORTED_DIALECTS = ("sqlite", "postgres")
WEBHOOK_SIGNATURE_HEADER = "X-Ovela-Signature"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _require_aware(name: str, value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


def _require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _ts(value: Optional[datetime]) -> Optional[str]:
    """Fixed-width UTC serialisation so lexicographic order equals time order."""
    if value is None:
        return None
    return value.astimezone(timezone.utc).strftime(_TS_FORMAT)


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _parse_amount(value: Any) -> Decimal:
    """Parse an amount; floats and booleans are rejected, value must be finite and > 0."""
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError("amount must be a Decimal, int or str; floats are not accepted")
    try:
        amount = value if isinstance(value, Decimal) else Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"invalid amount: {value!r}") from exc
    if not amount.is_finite() or amount <= 0:
        raise ValueError("amount must be finite and strictly positive")
    return amount


def _amount_text(amount: Decimal) -> str:
    return format(amount.normalize(), "f")


def _canonical_currency(value: Any) -> str:
    return _require_text("currency", value).strip().upper()


def _is_integrity_error(exc: BaseException) -> bool:
    return any(cls.__name__ == "IntegrityError" for cls in type(exc).__mro__)


# ---------------------------------------------------------------------------
# Fail-closed submission helpers
# ---------------------------------------------------------------------------


def _unknown_result(code: str, message: str, observed_at: datetime) -> RailSubmissionResult:
    return RailSubmissionResult(
        status=RailSubmissionStatus.UNKNOWN,
        provider_execution_id=None,
        provider_reference=None,
        provider_code=code,
        provider_message=message,
        retryable=True,
        authoritative=False,
        observed_at=observed_at,
    )


def coerce_submission_result(
    raw: Any, *, clock: Callable[[], datetime] = _utcnow
) -> RailSubmissionResult:
    """Return ``raw`` if it is a well-formed result, else a fail-closed ``UNKNOWN`` result."""
    now = clock()
    if (
        isinstance(raw, RailSubmissionResult)
        and isinstance(raw.status, RailSubmissionStatus)
        and isinstance(raw.retryable, bool)
        and isinstance(raw.authoritative, bool)
        and isinstance(raw.observed_at, datetime)
        and raw.observed_at.tzinfo is not None
    ):
        return raw
    return _unknown_result("MALFORMED_ADAPTER_RESULT", "adapter returned a malformed result", now)


def safe_submit(
    adapter: FinancialRailAdapter,
    instruction: RailInstruction,
    idempotency_key: str,
    *,
    clock: Callable[[], datetime] = _utcnow,
) -> RailSubmissionResult:
    """Submit to ``adapter`` and never raise: any failure becomes ``UNKNOWN`` (fail-closed)."""
    try:
        raw = adapter.submit(instruction, idempotency_key)
    except Exception as exc:
        logger.error("rail submit raised %s; mapping to UNKNOWN", type(exc).__name__)
        return _unknown_result(
            f"ADAPTER_EXCEPTION:{type(exc).__name__}", "rail submission raised an exception", clock()
        )
    return coerce_submission_result(raw, clock=clock)


class PaymentRailAdapterBridge:
    """Adapts a ``FinancialRailAdapter`` to the M7 ``PaymentRailAdapter`` protocol.

    Mapping (fail-closed):

    * authoritative ``ACCEPTED`` / ``PENDING`` -> ``SUBMITTED``
    * authoritative, non-retryable ``REJECTED`` -> ``FAILED``
    * everything else (non-authoritative, retryable, ``UNKNOWN``, malformed,
      exceptions) -> ``UNKNOWN``
    """

    def __init__(
        self,
        rail: FinancialRailAdapter,
        *,
        provider: str = "",
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        if rail is None or not callable(getattr(rail, "submit", None)):
            raise TypeError("rail must implement submit")
        self._rail = rail
        self._provider = provider
        self._clock = clock

    def submit_payment(
        self, instruction: PaymentInstruction, *, idempotency_key: str
    ) -> RailDispatchResult:
        rail_instruction = RailInstruction(
            transaction_id=instruction.transaction_id,
            amount=instruction.amount,
            currency=instruction.currency,
            destination_id=instruction.destination_id,
        )
        result = safe_submit(self._rail, rail_instruction, idempotency_key, clock=self._clock)
        reference = result.provider_reference or result.provider_execution_id
        raw_status = result.status.value

        if result.authoritative and result.status in (
            RailSubmissionStatus.ACCEPTED,
            RailSubmissionStatus.PENDING,
        ):
            return RailDispatchResult(
                status=RailDispatchStatus.SUBMITTED,
                provider_reference=reference,
                provider=self._provider,
                raw_provider_status=raw_status,
            )
        if (
            result.authoritative
            and not result.retryable
            and result.status is RailSubmissionStatus.REJECTED
        ):
            return RailDispatchResult(
                status=RailDispatchStatus.FAILED,
                provider_reference=reference,
                failure_code=result.provider_code or "REJECTED",
                provider=self._provider,
                raw_provider_status=raw_status,
            )
        return RailDispatchResult(
            status=RailDispatchStatus.UNKNOWN,
            provider_reference=reference,
            failure_code=result.provider_code or "UNKNOWN",
            provider=self._provider,
            raw_provider_status=raw_status,
        )


# ---------------------------------------------------------------------------
# Webhook signatures
# ---------------------------------------------------------------------------


def compute_webhook_signature(raw_body: bytes, secret: bytes) -> str:
    """Return the lowercase hex HMAC-SHA256 of the exact ``raw_body`` bytes."""
    if not isinstance(raw_body, (bytes, bytearray)):
        raise TypeError("raw_body must be bytes")
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise ValueError("secret must be non-empty bytes")
    return hmac.new(bytes(secret), bytes(raw_body), hashlib.sha256).hexdigest()


def _decode_signature(signature_header: Any) -> Optional[bytes]:
    """Decode a hex (optionally ``sha256=`` prefixed) or base64 signature to 32 raw bytes."""
    if not isinstance(signature_header, str):
        return None
    value = signature_header.strip()
    if value.lower().startswith("sha256="):
        value = value[len("sha256="):].strip()
    if not value:
        return None
    if _HEX_RE.fullmatch(value):
        return bytes.fromhex(value)
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) == hashlib.sha256().digest_size else None


def _signature_matches(raw_body: Any, signature_header: Any, secret: Any) -> bool:
    if not isinstance(raw_body, (bytes, bytearray)):
        return False
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        return False
    provided = _decode_signature(signature_header)
    if provided is None:
        return False
    expected = hmac.new(bytes(secret), bytes(raw_body), hashlib.sha256).digest()
    return hmac.compare_digest(expected, provided)


def verify_webhook_signature(
    tenant_id: UUID,
    provider: str,
    raw_body: bytes,
    signature_header: str,
    secret: bytes,
) -> bool:
    """Verify an HMAC-SHA256 webhook signature over the exact ``raw_body`` bytes.

    Fails closed: returns ``False`` for an empty or undecodable signature
    (invalid hex/base64), a wrong-length digest, a mismatched digest, an empty
    secret or any malformed argument. The digest comparison is constant-time
    (``hmac.compare_digest``). ``tenant_id`` and ``provider`` are validated and
    logged only; they are not mixed into the MAC, which is computed strictly
    over the raw body.
    """
    if not isinstance(tenant_id, UUID):
        return False
    if not isinstance(provider, str) or not provider.strip():
        return False
    ok = _signature_matches(raw_body, signature_header, secret)
    if not ok:
        logger.warning(
            "webhook signature verification failed tenant_id=%s provider=%s", tenant_id, provider
        )
    return ok


# ---------------------------------------------------------------------------
# Mock bank rail
# ---------------------------------------------------------------------------


class MockRailMode(StrEnum):
    NORMAL_ACCEPTED = "NORMAL_ACCEPTED"
    PENDING_QUEUE = "PENDING_QUEUE"
    DEFINITIVE_REJECT = "DEFINITIVE_REJECT"
    RETRYABLE_ERROR = "RETRYABLE_ERROR"
    TIMEOUT = "TIMEOUT"
    CONNECTION_RESET = "CONNECTION_RESET"
    MALFORMED = "MALFORMED"


class MockBankRailAdapter:
    """Pathological mock rail with configurable behaviour modes.

    * ``NORMAL_ACCEPTED``: authoritative ``ACCEPTED``.
    * ``PENDING_QUEUE``: authoritative ``PENDING``; final outcome arrives by webhook.
    * ``DEFINITIVE_REJECT``: authoritative, non-retryable ``REJECTED``.
    * ``RETRYABLE_ERROR``: an ambiguous 5xx-style error. It is ``UNKNOWN``,
      ``retryable=True`` and ``authoritative=False`` because the provider may
      or may not have processed the request.
    * ``TIMEOUT`` / ``CONNECTION_RESET``: fail closed. By default
      ``submit`` returns ``UNKNOWN`` (``retryable=True``,
      ``authoritative=False``); with ``raise_on_network_fault=True`` it raises
      ``TimeoutError`` / ``ConnectionResetError`` instead. With
      ``process_before_fault=True`` the provider records the payment as
      accepted before the fault, so a later resubmission with the same key
      returns the original ``ACCEPTED`` outcome.
    * ``MALFORMED``: returns an object that is not a ``RailSubmissionResult``.

    Definitive outcomes are stored per idempotency key. A replay returns the
    stored outcome, and reusing a key with a different instruction raises
    ``RailIdempotencyConflictError``. The adapter also signs and verifies
    HMAC-SHA256 webhooks for end-to-end tests.
    """

    def __init__(
        self,
        mode: MockRailMode = MockRailMode.NORMAL_ACCEPTED,
        *,
        provider_name: str = "mockbank",
        clock: Callable[[], datetime] = _utcnow,
        reject_code: str = "INSUFFICIENT_FUNDS",
        raise_on_network_fault: bool = False,
        process_before_fault: bool = False,
    ) -> None:
        self.mode = MockRailMode(mode)
        self.provider_name = _require_text("provider_name", provider_name)
        self._clock = clock
        self._reject_code = reject_code
        self._raise_on_network_fault = raise_on_network_fault
        self._process_before_fault = process_before_fault
        self._lock = threading.Lock()
        self._records: Dict[str, Tuple[Tuple[str, str, str, str], RailSubmissionResult]] = {}
        self._queued_modes: List[MockRailMode] = []
        self.calls: List[Tuple[RailInstruction, str, MockRailMode]] = []

    # -- configuration -----------------------------------------------------

    def set_mode(self, mode: MockRailMode) -> None:
        with self._lock:
            self.mode = MockRailMode(mode)

    def queue_modes(self, *modes: MockRailMode) -> None:
        """Queue one-shot modes consumed (in order) by the next calls to ``submit``."""
        with self._lock:
            self._queued_modes.extend(MockRailMode(m) for m in modes)

    # -- submission --------------------------------------------------------------

    @staticmethod
    def _fingerprint(instruction: RailInstruction) -> Tuple[str, str, str, str]:
        return (
            instruction.transaction_id,
            _amount_text(_parse_amount(instruction.amount)),
            _canonical_currency(instruction.currency),
            instruction.destination_id,
        )

    def _ids(self, idempotency_key: str) -> Tuple[str, str]:
        digest = hashlib.sha256(f"{self.provider_name}:{idempotency_key}".encode("utf-8")).hexdigest()
        return f"mbx_{digest[:24]}", f"ref_{digest[24:40]}"

    def _result(
        self,
        status: RailSubmissionStatus,
        *,
        idempotency_key: Optional[str],
        code: str,
        message: str,
        retryable: bool,
        authoritative: bool,
    ) -> RailSubmissionResult:
        execution_id: Optional[str] = None
        reference: Optional[str] = None
        if idempotency_key is not None and status in (
            RailSubmissionStatus.ACCEPTED,
            RailSubmissionStatus.PENDING,
        ):
            execution_id, reference = self._ids(idempotency_key)
        return RailSubmissionResult(
            status=status,
            provider_execution_id=execution_id,
            provider_reference=reference,
            provider_code=code,
            provider_message=message,
            retryable=retryable,
            authoritative=authoritative,
            observed_at=self._clock(),
        )

    def submit(self, instruction: RailInstruction, idempotency_key: str) -> RailSubmissionResult:
        if not isinstance(instruction, RailInstruction):
            raise TypeError("instruction must be a RailInstruction")
        _require_text("idempotency_key", idempotency_key)
        fingerprint = self._fingerprint(instruction)

        with self._lock:
            mode = self._queued_modes.pop(0) if self._queued_modes else self.mode
            self.calls.append((instruction, idempotency_key, mode))

            stored = self._records.get(idempotency_key)
            if stored is not None and stored[0] != fingerprint:
                raise RailIdempotencyConflictError(
                    "idempotency key was already used with a different instruction"
                )

            if mode in (MockRailMode.TIMEOUT, MockRailMode.CONNECTION_RESET):
                if self._process_before_fault and stored is None:
                    self._records[idempotency_key] = (
                        fingerprint,
                        self._result(
                            RailSubmissionStatus.ACCEPTED,
                            idempotency_key=idempotency_key,
                            code="ACCEPTED",
                            message="payment accepted",
                            retryable=False,
                            authoritative=True,
                        ),
                    )
                is_timeout = mode is MockRailMode.TIMEOUT
                if self._raise_on_network_fault:
                    if is_timeout:
                        raise TimeoutError("mock rail timed out")
                    raise ConnectionResetError("mock rail connection reset")
                return self._result(
                    RailSubmissionStatus.UNKNOWN,
                    idempotency_key=None,
                    code="TIMEOUT" if is_timeout else "CONNECTION_RESET",
                    message="network fault; outcome unknown",
                    retryable=True,
                    authoritative=False,
                )

            if stored is not None:
                return stored[1]

            if mode is MockRailMode.MALFORMED:
                return {"status": "OK", "note": "not a RailSubmissionResult"}  # type: ignore[return-value]

            if mode is MockRailMode.RETRYABLE_ERROR:
                return self._result(
                    RailSubmissionStatus.UNKNOWN,
                    idempotency_key=None,
                    code="RETRYABLE_PROVIDER_ERROR",
                    message="provider temporarily unavailable; outcome unknown",
                    retryable=True,
                    authoritative=False,
                )

            if mode is MockRailMode.DEFINITIVE_REJECT:
                result = self._result(
                    RailSubmissionStatus.REJECTED,
                    idempotency_key=None,
                    code=self._reject_code,
                    message="payment definitively rejected",
                    retryable=False,
                    authoritative=True,
                )
            elif mode is MockRailMode.PENDING_QUEUE:
                result = self._result(
                    RailSubmissionStatus.PENDING,
                    idempotency_key=idempotency_key,
                    code="QUEUED",
                    message="payment queued for settlement",
                    retryable=False,
                    authoritative=True,
                )
            else:
                result = self._result(
                    RailSubmissionStatus.ACCEPTED,
                    idempotency_key=idempotency_key,
                    code="ACCEPTED",
                    message="payment accepted",
                    retryable=False,
                    authoritative=True,
                )
            self._records[idempotency_key] = (fingerprint, result)
            return result

    # -- webhooks ------------------------------------------------------------------

    def sign_webhook(self, raw_body: bytes, secret: bytes) -> Dict[str, str]:
        """Return signed headers for ``raw_body``."""
        return {
            WEBHOOK_SIGNATURE_HEADER: compute_webhook_signature(raw_body, secret),
            "Content-Type": "application/json",
        }

    def build_signed_webhook(
        self,
        *,
        tenant_id: UUID,
        idempotency_key: str,
        event_type: str,
        amount: Any,
        currency: str,
        status: str,
        secret: bytes,
        transaction_execution_id: Optional[UUID] = None,
        provider_execution_id: Optional[str] = None,
        provider_event_id: Optional[str] = None,
    ) -> Tuple[Dict[str, str], bytes]:
        """Build a signed ``(headers, raw_body)`` pair for end-to-end verification tests."""
        body: Dict[str, Any] = {
            "tenant_id": str(tenant_id),
            "idempotency_key": idempotency_key,
            "provider_event_id": provider_event_id,
            "event_type": event_type,
            "amount": _amount_text(_parse_amount(amount)),
            "currency": _canonical_currency(currency),
            "transaction_execution_id": (
                str(transaction_execution_id) if transaction_execution_id is not None else None
            ),
            "provider_execution_id": provider_execution_id,
            "status": status,
        }
        raw_body = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self.sign_webhook(raw_body, secret), raw_body

    def verify_webhook(
        self, headers: Mapping[str, str], raw_body: bytes, secret: bytes
    ) -> VerifiedWebhookEvidence:
        """Verify the signature over ``raw_body`` and return evidence. Raises on any failure."""
        if not isinstance(headers, Mapping):
            raise WebhookVerificationError("headers must be a mapping")
        lowered = {str(k).lower(): v for k, v in headers.items()}
        signature = lowered.get(WEBHOOK_SIGNATURE_HEADER.lower())
        if not _signature_matches(raw_body, signature, secret):
            raise WebhookVerificationError("webhook signature verification failed")

        try:
            body = json.loads(bytes(raw_body).decode("utf-8"), parse_float=Decimal)
        except (UnicodeDecodeError, ValueError) as exc:
            raise WebhookVerificationError("webhook body is not valid UTF-8 JSON") from exc
        if not isinstance(body, dict):
            raise WebhookVerificationError("webhook body must be a JSON object")

        try:
            tenant_id = UUID(str(body.get("tenant_id")))
            raw_tx = body.get("transaction_execution_id")
            transaction_execution_id = UUID(str(raw_tx)) if raw_tx is not None else None
            provider_event_id = body.get("provider_event_id")
            provider_execution_id = body.get("provider_execution_id")
            for name, value in (
                ("provider_event_id", provider_event_id),
                ("provider_execution_id", provider_execution_id),
            ):
                if value is not None:
                    _require_text(name, value)
            return VerifiedWebhookEvidence(
                webhook_id=uuid.uuid4(),
                tenant_id=tenant_id,
                provider=self.provider_name,
                idempotency_key=_require_text("idempotency_key", body.get("idempotency_key")),
                provider_event_id=provider_event_id,
                event_type=_require_text("event_type", body.get("event_type")),
                amount=_parse_amount(body.get("amount")),
                currency=_canonical_currency(body.get("currency")),
                transaction_execution_id=transaction_execution_id,
                provider_execution_id=provider_execution_id,
                status=_require_text("status", body.get("status")),
                received_at=_require_aware("received_at", self._clock()),
            )
        except (ValueError, TypeError) as exc:
            raise WebhookVerificationError(f"webhook body is invalid: {exc}") from exc


# ---------------------------------------------------------------------------
# Reconciliation service
# ---------------------------------------------------------------------------

WEBHOOK_STATUS_RECEIVED = "RECEIVED"
WEBHOOK_STATUS_PROCESSED = "PROCESSED"
WEBHOOK_STATUS_QUARANTINED = "QUARANTINED"
WEBHOOK_STATUS_CONFLICT = "CONFLICT"
WEBHOOK_STATUS_DEFERRED = "DEFERRED"

RESULT_PROCESSED = "PROCESSED"
RESULT_DUPLICATE = "DUPLICATE_IDEMPOTENT"
RESULT_NOOP_TERMINAL = "NOOP_TERMINAL"
RESULT_NO_STATE_CHANGE = "NO_STATE_CHANGE"
RESULT_QUARANTINED = "QUARANTINED"
RESULT_CONFLICT = "RECONCILIATION_CONFLICT"
RESULT_DEFERRED = "OUT_OF_ORDER_DEFERRED"
RESULT_UNSUPPORTED_STATUS = "UNSUPPORTED_STATUS"

_SETTLED_STATUSES = frozenset({"SETTLED", "COMPLETED", "SUCCEEDED", "SUCCESS", "PAID"})
_FAILED_STATUSES = frozenset(
    {"FAILED", "REJECTED", "RETURNED", "CANCELLED", "CANCELED", "REVERSED"}
)
_PROGRESS_STATUSES = frozenset({"PENDING", "PROCESSING", "ACCEPTED", "SUBMITTED", "IN_PROGRESS"})

_EVENTS_TABLE = "rail_webhook_events"
_LINKS_TABLE = "rail_provider_executions"
_MAX_TRANSITION_ATTEMPTS = 3

_EVENT_COLUMNS = (
    "webhook_id, tenant_id, provider, idempotency_key, provider_event_id, event_type, "
    "amount, currency, transaction_execution_id, provider_execution_id, provider_status, "
    "status, outcome, received_at, processed_at"
)

_SCHEMA_STATEMENTS: Tuple[str, ...] = (
    f"""
    CREATE TABLE IF NOT EXISTS {_EVENTS_TABLE} (
        webhook_id               TEXT PRIMARY KEY,
        tenant_id                TEXT NOT NULL,
        provider                 TEXT NOT NULL,
        idempotency_key          TEXT NOT NULL,
        provider_event_id        TEXT,
        event_type               TEXT NOT NULL,
        amount                   TEXT NOT NULL,
        currency                 TEXT NOT NULL,
        transaction_execution_id TEXT,
        provider_execution_id    TEXT,
        provider_status          TEXT NOT NULL,
        status                   TEXT NOT NULL,
        outcome                  TEXT,
        received_at              TEXT NOT NULL,
        processed_at             TEXT,
        UNIQUE (tenant_id, provider, idempotency_key),
        UNIQUE (tenant_id, provider, provider_event_id)
    )
    """,
    f"""
    CREATE TABLE IF NOT EXISTS {_LINKS_TABLE} (
        tenant_id                TEXT NOT NULL,
        provider                 TEXT NOT NULL,
        provider_execution_id    TEXT NOT NULL,
        transaction_execution_id TEXT NOT NULL,
        created_at               TEXT NOT NULL,
        PRIMARY KEY (tenant_id, provider, provider_execution_id)
    )
    """,
)


@dataclass(frozen=True)
class WebhookRecord:
    """Immutable snapshot of one stored webhook record."""

    webhook_id: UUID
    tenant_id: UUID
    provider: str
    idempotency_key: str
    provider_event_id: Optional[str]
    event_type: str
    amount: Decimal
    currency: str
    transaction_execution_id: Optional[UUID]
    provider_execution_id: Optional[str]
    provider_status: str
    status: str
    outcome: Optional[str]
    received_at: datetime
    processed_at: Optional[datetime]


def _evidence_from_row(row: Sequence[Any]) -> VerifiedWebhookEvidence:
    return VerifiedWebhookEvidence(
        webhook_id=UUID(row[0]),
        tenant_id=UUID(row[1]),
        provider=row[2],
        idempotency_key=row[3],
        provider_event_id=row[4],
        event_type=row[5],
        amount=Decimal(row[6]),
        currency=row[7],
        transaction_execution_id=UUID(row[8]) if row[8] is not None else None,
        provider_execution_id=row[9],
        status=row[10],
        received_at=_parse_ts(row[13]),  # type: ignore[arg-type]
    )


def _record_from_row(row: Sequence[Any]) -> WebhookRecord:
    return WebhookRecord(
        webhook_id=UUID(row[0]),
        tenant_id=UUID(row[1]),
        provider=row[2],
        idempotency_key=row[3],
        provider_event_id=row[4],
        event_type=row[5],
        amount=Decimal(row[6]),
        currency=row[7],
        transaction_execution_id=UUID(row[8]) if row[8] is not None else None,
        provider_execution_id=row[9],
        provider_status=row[10],
        status=row[11],
        outcome=row[12],
        received_at=_parse_ts(row[13]),  # type: ignore[arg-type]
        processed_at=_parse_ts(row[14]),
    )


class RailEventReconciliationService:
    """Ingests verified rail webhooks idempotently and reconciles execution state.

    ``connection_factory`` is a zero-argument callable returning a fresh
    DB-API 2.0 connection. One connection is opened per DB transaction; it is
    committed on success, rolled back on any exception and always closed.
    ``transaction_engine`` is the M6 ``DurableTransactionEngine`` (or a
    compatible object exposing ``get_execution``, ``get_intent`` and
    ``transition_state``).
    """

    def __init__(
        self,
        connection_factory: Callable[[], Any],
        transaction_engine: Any,
        *,
        dialect: str = "sqlite",
        clock: Callable[[], datetime] = _utcnow,
        raise_on_conflict: bool = False,
    ) -> None:
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        for method in ("get_execution", "get_intent", "transition_state"):
            if transaction_engine is None or not callable(getattr(transaction_engine, method, None)):
                raise TypeError(f"transaction_engine must implement {method}")
        if dialect not in _SUPPORTED_DIALECTS:
            raise ValueError(f"dialect must be one of {_SUPPORTED_DIALECTS}")
        self._connection_factory = connection_factory
        self._engine = transaction_engine
        self._dialect = dialect
        self._clock = clock
        self._raise_on_conflict = raise_on_conflict

    # -- low level helpers -------------------------------------------------

    def _adapt(self, sql: str) -> str:
        if self._dialect == "postgres":
            return sql.replace("?", "%s")
        return sql

    def _fetchone(self, conn: Any, sql: str, params: Sequence[Any] = ()) -> Optional[Sequence[Any]]:
        cur = conn.cursor()
        try:
            cur.execute(self._adapt(sql), tuple(params))
            return cur.fetchone()
        finally:
            cur.close()

    def _write(self, conn: Any, sql: str, params: Sequence[Any] = ()) -> int:
        cur = conn.cursor()
        try:
            cur.execute(self._adapt(sql), tuple(params))
            return cur.rowcount
        finally:
            cur.close()

    def _begin(self, conn: Any) -> None:
        if self._dialect == "sqlite":
            cur = conn.cursor()
            try:
                cur.execute("BEGIN IMMEDIATE")
            finally:
                cur.close()
        elif getattr(conn, "autocommit", False) is True:
            cur = conn.cursor()
            try:
                cur.execute("BEGIN")
            finally:
                cur.close()

    @staticmethod
    def _safe_rollback(conn: Any) -> None:
        try:
            conn.rollback()
        except Exception:  # pragma: no cover - best effort
            logger.exception("rollback failed")

    @staticmethod
    def _safe_close(conn: Any) -> None:
        try:
            conn.close()
        except Exception:  # pragma: no cover - best effort
            logger.exception("connection close failed")

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        conn = self._connection_factory()
        try:
            self._begin(conn)
            try:
                yield conn
            except BaseException:
                self._safe_rollback(conn)
                raise
            try:
                conn.commit()
            except BaseException:
                self._safe_rollback(conn)
                raise
        finally:
            self._safe_close(conn)

    def _now(self) -> datetime:
        return _require_aware("clock()", self._clock())

    # -- schema --------------------------------------------------------------

    def ensure_schema(self) -> None:
        """Create the service's tables if they do not exist (idempotent)."""
        with self._transaction() as conn:
            for statement in _SCHEMA_STATEMENTS:
                self._write(conn, statement)

    # -- provider execution links ----------------------------------------------

    def record_provider_execution(
        self,
        tenant_id: UUID | str,
        provider: str,
        provider_execution_id: str,
        transaction_execution_id: UUID | str,
    ) -> None:
        """Idempotently link a provider execution id to a durable execution.

        Re-linking the same pair is a no-op; linking an id already bound to a
        different execution raises ``ProviderLinkConflictError``.
        """
        tenant = str(tenant_id)
        _require_text("tenant_id", tenant)
        _require_text("provider", provider)
        _require_text("provider_execution_id", provider_execution_id)
        execution = str(transaction_execution_id)
        _require_text("transaction_execution_id", execution)
        now_s = _ts(self._now())

        last_error: Optional[BaseException] = None
        for _attempt in range(2):
            try:
                with self._transaction() as conn:
                    row = self._fetchone(
                        conn,
                        f"SELECT transaction_execution_id FROM {_LINKS_TABLE} "
                        f"WHERE tenant_id = ? AND provider = ? AND provider_execution_id = ?",
                        (tenant, provider, provider_execution_id),
                    )
                    if row is not None:
                        if row[0] == execution:
                            return
                        raise ProviderLinkConflictError(
                            "provider execution id is already linked to a different execution"
                        )
                    self._write(
                        conn,
                        f"INSERT INTO {_LINKS_TABLE} (tenant_id, provider, provider_execution_id, "
                        f"transaction_execution_id, created_at) VALUES (?, ?, ?, ?, ?)",
                        (tenant, provider, provider_execution_id, execution, now_s),
                    )
                    return
            except Exception as exc:
                if _is_integrity_error(exc):
                    last_error = exc
                    continue
                raise
        assert last_error is not None
        raise ProviderLinkConflictError("concurrent conflicting provider link") from last_error

    def _lookup_link(self, tenant: str, provider: str, provider_execution_id: str) -> Optional[str]:
        with self._transaction() as conn:
            row = self._fetchone(
                conn,
                f"SELECT transaction_execution_id FROM {_LINKS_TABLE} "
                f"WHERE tenant_id = ? AND provider = ? AND provider_execution_id = ?",
                (tenant, provider, provider_execution_id),
            )
        return row[0] if row is not None else None

    # -- reads ---------------------------------------------------------------------

    def get_webhook_record(
        self, tenant_id: UUID, provider: str, idempotency_key: str
    ) -> Optional[WebhookRecord]:
        """Return the stored webhook record for the idempotency key, or ``None``."""
        with self._transaction() as conn:
            row = self._fetchone(
                conn,
                f"SELECT {_EVENT_COLUMNS} FROM {_EVENTS_TABLE} "
                f"WHERE tenant_id = ? AND provider = ? AND idempotency_key = ?",
                (str(tenant_id), provider, idempotency_key),
            )
        return _record_from_row(row) if row is not None else None

    # -- validation --------------------------------------------------------------------

    @staticmethod
    def _validate_evidence(evidence: Any) -> VerifiedWebhookEvidence:
        if not isinstance(evidence, VerifiedWebhookEvidence):
            raise TypeError("webhook_evidence must be a VerifiedWebhookEvidence")
        if not isinstance(evidence.webhook_id, UUID):
            raise ValueError("webhook_id must be a uuid.UUID")
        if not isinstance(evidence.tenant_id, UUID):
            raise ValueError("tenant_id must be a uuid.UUID")
        _require_text("provider", evidence.provider)
        _require_text("idempotency_key", evidence.idempotency_key)
        if evidence.provider_event_id is not None:
            _require_text("provider_event_id", evidence.provider_event_id)
        _require_text("event_type", evidence.event_type)
        _parse_amount(evidence.amount)
        _canonical_currency(evidence.currency)
        if evidence.transaction_execution_id is not None and not isinstance(
            evidence.transaction_execution_id, UUID
        ):
            raise ValueError("transaction_execution_id must be a uuid.UUID or None")
        if evidence.provider_execution_id is not None:
            _require_text("provider_execution_id", evidence.provider_execution_id)
        _require_text("status", evidence.status)
        _require_aware("received_at", evidence.received_at)
        return evidence

    # -- ingestion ----------------------------------------------------------------------

    def _register(
        self, evidence: VerifiedWebhookEvidence
    ) -> Tuple[str, VerifiedWebhookEvidence, Optional[Tuple[bool, str]]]:
        """Atomically deduplicate and record the webhook as ``RECEIVED``.

        Returns ``(webhook_id, evidence_to_process, early_result)``. A non-None
        ``early_result`` means no further processing is needed.
        """
        tenant = str(evidence.tenant_id)
        last_error: Optional[BaseException] = None
        for _attempt in range(2):
            try:
                with self._transaction() as conn:
                    sql = (
                        f"SELECT {_EVENT_COLUMNS} FROM {_EVENTS_TABLE} "
                        f"WHERE tenant_id = ? AND provider = ? AND (idempotency_key = ?"
                    )
                    params: List[Any] = [tenant, evidence.provider, evidence.idempotency_key]
                    if evidence.provider_event_id is not None:
                        sql += " OR provider_event_id = ?"
                        params.append(evidence.provider_event_id)
                    sql += ") ORDER BY received_at LIMIT 1"
                    row = self._fetchone(conn, sql, params)

                    if row is not None:
                        stored_status = row[11]
                        if stored_status == WEBHOOK_STATUS_PROCESSED:
                            return row[0], evidence, (True, RESULT_DUPLICATE)
                        if stored_status == WEBHOOK_STATUS_CONFLICT:
                            return row[0], evidence, (False, RESULT_CONFLICT)
                        # RECEIVED / DEFERRED / QUARANTINED: resume from the stored evidence.
                        return row[0], _evidence_from_row(row), None

                    self._write(
                        conn,
                        f"INSERT INTO {_EVENTS_TABLE} ("
                        "webhook_id, tenant_id, provider, idempotency_key, provider_event_id, "
                        "event_type, amount, currency, transaction_execution_id, "
                        "provider_execution_id, provider_status, status, outcome, received_at, "
                        "processed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL)",
                        (
                            str(evidence.webhook_id),
                            tenant,
                            evidence.provider,
                            evidence.idempotency_key,
                            evidence.provider_event_id,
                            evidence.event_type,
                            _amount_text(evidence.amount),
                            _canonical_currency(evidence.currency),
                            (
                                str(evidence.transaction_execution_id)
                                if evidence.transaction_execution_id is not None
                                else None
                            ),
                            evidence.provider_execution_id,
                            evidence.status,
                            WEBHOOK_STATUS_RECEIVED,
                            _ts(evidence.received_at),
                        ),
                    )
                    return str(evidence.webhook_id), evidence, None
            except Exception as exc:
                # A concurrent ingest won the unique constraint: re-read and resolve idempotently.
                if _is_integrity_error(exc):
                    last_error = exc
                    continue
                raise
        assert last_error is not None
        raise ReconciliationError("concurrent conflicting webhook ingestion") from last_error

    def _finalize(self, webhook_id: str, status: str, outcome: str, now: datetime) -> None:
        processed_at = _ts(now) if status == WEBHOOK_STATUS_PROCESSED else None
        with self._transaction() as conn:
            self._write(
                conn,
                f"UPDATE {_EVENTS_TABLE} SET status = ?, outcome = ?, processed_at = ? "
                f"WHERE webhook_id = ? AND status NOT IN (?, ?)",
                (
                    status,
                    outcome,
                    processed_at,
                    webhook_id,
                    WEBHOOK_STATUS_PROCESSED,
                    WEBHOOK_STATUS_CONFLICT,
                ),
            )

    def ingest_and_reconcile(self, webhook_evidence: VerifiedWebhookEvidence) -> tuple[bool, str]:
        """Ingest verified webhook evidence and reconcile the execution state.

        Returns ``(ok, code)``:

        * ``(True, "DUPLICATE_IDEMPOTENT")``: already processed; zero side effects.
        * ``(True, "PROCESSED")``: the execution advanced to ``SETTLED`` or ``FAILED``.
        * ``(True, "NOOP_TERMINAL")``: execution already terminal; safe no-op.
        * ``(True, "NO_STATE_CHANGE")``: progress-only event (e.g. ``PENDING``).
        * ``(False, "QUARANTINED")``: no matching execution/intent; flagged.
        * ``(False, "UNSUPPORTED_STATUS")``: unrecognised provider status; quarantined.
        * ``(False, "RECONCILIATION_CONFLICT")``: monetary or correlation conflict; nothing mutated.
        * ``(False, "OUT_OF_ORDER_DEFERRED")``: execution not yet ``SUBMITTED``/``UNKNOWN``.

        Infrastructure failures raise ``ReconciliationError`` and leave the
        webhook ``RECEIVED`` so a redelivery resumes safely.
        """
        evidence = self._validate_evidence(webhook_evidence)
        now = self._now()

        webhook_id, to_process, early = self._register(evidence)
        if early is not None:
            return early

        try:
            record_status, code, ok = self._reconcile(to_process, now)
        except ReconciliationError:
            raise
        except Exception as exc:
            logger.error(
                "reconciliation failed; webhook left RECEIVED for retry webhook_id=%s error=%s",
                webhook_id,
                type(exc).__name__,
                exc_info=True,
            )
            raise ReconciliationError(
                "reconciliation failed; webhook left for redelivery"
            ) from exc

        self._finalize(webhook_id, record_status, code, now)
        if record_status == WEBHOOK_STATUS_CONFLICT and self._raise_on_conflict:
            raise ReconciliationConflictError(code)
        return ok, code

    # -- reconciliation -----------------------------------------------------------------------

    @staticmethod
    def _target_state(provider_status: str) -> Tuple[str, Optional[TransactionExecutionState]]:
        """Classify a provider status as ``terminal``, ``progress`` or ``unsupported``."""
        normalized = provider_status.strip().upper()
        if normalized in _SETTLED_STATUSES:
            return "terminal", TransactionExecutionState.SETTLED
        if normalized in _FAILED_STATUSES:
            return "terminal", TransactionExecutionState.FAILED
        if normalized in _PROGRESS_STATUSES:
            return "progress", None
        return "unsupported", None

    def _reconcile(
        self, evidence: VerifiedWebhookEvidence, now: datetime
    ) -> Tuple[str, str, bool]:
        """Return ``(webhook record status, result code, ok)``. Never mutates amounts."""
        tenant = str(evidence.tenant_id)

        # 2. Correlation.
        explicit = (
            str(evidence.transaction_execution_id)
            if evidence.transaction_execution_id is not None
            else None
        )
        linked = (
            self._lookup_link(tenant, evidence.provider, evidence.provider_execution_id)
            if evidence.provider_execution_id is not None
            else None
        )
        if explicit is not None and linked is not None and explicit != linked:
            logger.error(
                "correlation mismatch between transaction_execution_id and provider_execution_id "
                "webhook_id=%s",
                evidence.webhook_id,
            )
            return WEBHOOK_STATUS_CONFLICT, RESULT_CONFLICT, False
        execution_id = explicit if explicit is not None else linked
        if execution_id is None:
            logger.warning("webhook has no correlation; quarantined webhook_id=%s", evidence.webhook_id)
            return WEBHOOK_STATUS_QUARANTINED, RESULT_QUARANTINED, False

        try:
            execution = self._engine.get_execution(execution_id, tenant)
        except TransactionNotFoundError:
            logger.warning(
                "no execution found for webhook; quarantined webhook_id=%s", evidence.webhook_id
            )
            return WEBHOOK_STATUS_QUARANTINED, RESULT_QUARANTINED, False

        # 3. Monetary binding: the intent is the authority, the webhook is only evidence.
        try:
            intent = self._engine.get_intent(execution.payment_intent_id, tenant)
        except TransactionNotFoundError:
            logger.error(
                "execution has no payment intent; quarantined webhook_id=%s", evidence.webhook_id
            )
            return WEBHOOK_STATUS_QUARANTINED, RESULT_QUARANTINED, False
        if intent.amount != evidence.amount or _canonical_currency(intent.currency) != _canonical_currency(
            evidence.currency
        ):
            logger.error(
                "RECONCILIATION_CONFLICT: webhook amount/currency differ from payment intent "
                "webhook_id=%s execution_id=%s",
                evidence.webhook_id,
                execution_id,
            )
            return WEBHOOK_STATUS_CONFLICT, RESULT_CONFLICT, False

        kind, target = self._target_state(evidence.status)
        if kind == "unsupported":
            logger.warning(
                "unsupported provider status; quarantined webhook_id=%s status=%s",
                evidence.webhook_id,
                evidence.status,
            )
            return WEBHOOK_STATUS_QUARANTINED, RESULT_UNSUPPORTED_STATUS, False
        if kind == "progress" or target is None:
            return WEBHOOK_STATUS_PROCESSED, RESULT_NO_STATE_CHANGE, True

        # 4./5. State machine transition (terminal states are safe no-ops).
        failure_reason = f"WEBHOOK:{evidence.event_type}:{evidence.status}"[:200]
        for _attempt in range(_MAX_TRANSITION_ATTEMPTS):
            state = execution.state
            if state in TERMINAL_STATES:
                if state is not target:
                    logger.warning(
                        "webhook disagrees with terminal state; no-op webhook_id=%s state=%s "
                        "webhook_status=%s",
                        evidence.webhook_id,
                        state.value,
                        evidence.status,
                    )
                return WEBHOOK_STATUS_PROCESSED, RESULT_NOOP_TERMINAL, True
            if state not in (TransactionExecutionState.SUBMITTED, TransactionExecutionState.UNKNOWN):
                logger.info(
                    "webhook arrived before execution was submitted; deferred webhook_id=%s state=%s",
                    evidence.webhook_id,
                    state.value,
                )
                return WEBHOOK_STATUS_DEFERRED, RESULT_DEFERRED, False
            try:
                kwargs: Dict[str, Any] = {
                    "now": now,
                    "expected_version": execution.version,
                    "reconciled": state is TransactionExecutionState.UNKNOWN,
                }
                if target is TransactionExecutionState.FAILED:
                    kwargs["failure_reason"] = failure_reason
                self._engine.transition_state(execution_id, tenant, target, **kwargs)
                return WEBHOOK_STATUS_PROCESSED, RESULT_PROCESSED, True
            except (ConcurrentModificationError, InvalidStateTransitionError):
                # Lost a race with another writer: reload and re-evaluate.
                execution = self._engine.get_execution(execution_id, tenant)
        raise ReconciliationError("could not apply transition after repeated concurrent changes")