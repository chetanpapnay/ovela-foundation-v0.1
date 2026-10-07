"""Ovela Foundation - Milestone M6: Durable Transaction Engine & State Machine.

This module provides:

* ``TransactionExecutionState`` and the explicit transition map.
* Immutable ``PaymentIntent`` and ``TransactionExecution`` records.
* ``compute_request_fingerprint`` for deterministic request fingerprinting.
* ``DurableTransactionEngine``, a DB-API 2.0 backed engine that provides
  idempotent intent creation, atomic state transitions and an atomic
  reservation boundary (approval consumption + state change + ledger entry +
  provider outbox record).

Design notes
------------
* Money is never stored as a float. Amounts are canonical decimal strings.
* Every public engine method runs inside exactly one DB transaction. Any
  exception rolls back everything done in that transaction.
* Invalid transitions are rejected *before* any write is issued, so they have
  zero side effects.
* Approval consumption is performed through the ``ApprovalStore`` protocol,
  whose signature does not accept a connection. If the approval store is not
  enrolled in the same database transaction, a failure after a successful
  ``consume`` cannot un-consume the approval. The engine fails closed in that
  case: the approval stays consumed, the reservation is rolled back, and a
  CRITICAL log is emitted so operators can reconcile. This can never allow a
  double spend, because the approval cannot be consumed twice.
* Supported dialects: ``"sqlite"`` (qmark params, ``BEGIN IMMEDIATE``) and
  ``"postgres"`` (``%s`` params, ``SELECT ... FOR UPDATE`` row locks).
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Callable, Dict, FrozenSet, Iterator, Optional, Sequence, Tuple

from app.approval_evidence import (
    ApprovalEvidence,
    ApprovalEvidenceConsumed,
    ApprovalEvidenceExpired,
    ApprovalEvidenceInvalid,
    ApprovalStore,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class TransactionEngineError(Exception):
    """Base class for all transaction engine errors."""


class InvalidStateTransitionError(TransactionEngineError):
    """Raised when a state transition is not permitted by the state machine."""


class IdempotencyConflictError(TransactionEngineError):
    """Raised when an idempotency key or action id is reused with a different request."""


class TransactionNotFoundError(TransactionEngineError):
    """Raised when an intent or execution does not exist for the given tenant."""


class ConcurrentModificationError(TransactionEngineError):
    """Raised when an optimistic concurrency check fails."""


# ---------------------------------------------------------------------------
# State machine
# ---------------------------------------------------------------------------


class TransactionExecutionState(str, Enum):
    CREATED = "CREATED"
    AUTHORIZED = "AUTHORIZED"
    APPROVED = "APPROVED"
    RESERVED = "RESERVED"
    SUBMITTED = "SUBMITTED"
    SETTLED = "SETTLED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


_S = TransactionExecutionState

ALLOWED_TRANSITIONS: Dict[TransactionExecutionState, FrozenSet[TransactionExecutionState]] = {
    _S.CREATED: frozenset({_S.AUTHORIZED, _S.FAILED}),
    _S.AUTHORIZED: frozenset({_S.APPROVED, _S.FAILED}),
    _S.APPROVED: frozenset({_S.RESERVED, _S.FAILED}),
    _S.RESERVED: frozenset({_S.SUBMITTED, _S.FAILED, _S.UNKNOWN}),
    _S.SUBMITTED: frozenset({_S.SETTLED, _S.FAILED, _S.UNKNOWN}),
    _S.UNKNOWN: frozenset({_S.SETTLED, _S.FAILED, _S.SUBMITTED}),
    _S.SETTLED: frozenset(),
    _S.FAILED: frozenset(),
}

TERMINAL_STATES: FrozenSet[TransactionExecutionState] = frozenset({_S.SETTLED, _S.FAILED})

# Transitions out of UNKNOWN are only legal after reconciliation.
_RECONCILIATION_REQUIRED_FROM: FrozenSet[TransactionExecutionState] = frozenset({_S.UNKNOWN})

# Whitelisted mapping of state -> timestamp column (safe for SQL interpolation).
_STATE_TIMESTAMP_COLUMN: Dict[TransactionExecutionState, str] = {
    _S.CREATED: "created_at",
    _S.AUTHORIZED: "authorized_at",
    _S.APPROVED: "approved_at",
    _S.RESERVED: "reserved_at",
    _S.SUBMITTED: "submitted_at",
    _S.SETTLED: "settled_at",
    _S.FAILED: "failed_at",
    _S.UNKNOWN: "unknown_at",
}


def validate_transition(
    current: TransactionExecutionState,
    target: TransactionExecutionState,
    *,
    reconciled: bool = False,
) -> None:
    """Raise ``InvalidStateTransitionError`` unless ``current -> target`` is allowed."""
    if not isinstance(current, TransactionExecutionState) or not isinstance(
        target, TransactionExecutionState
    ):
        raise InvalidStateTransitionError("states must be TransactionExecutionState members")
    if current in TERMINAL_STATES:
        raise InvalidStateTransitionError(
            f"{current.value} is a terminal state; cannot transition to {target.value}"
        )
    if target not in ALLOWED_TRANSITIONS[current]:
        raise InvalidStateTransitionError(
            f"transition {current.value} -> {target.value} is not allowed"
        )
    if current in _RECONCILIATION_REQUIRED_FROM and not reconciled:
        raise InvalidStateTransitionError(
            f"transition {current.value} -> {target.value} requires reconciliation"
        )


# ---------------------------------------------------------------------------
# Canonicalisation helpers
# ---------------------------------------------------------------------------


def _canonical_amount(amount: Any) -> str:
    """Return a canonical, locale-independent decimal string for ``amount``."""
    if isinstance(amount, bool) or isinstance(amount, float):
        raise ValueError("amount must be a Decimal, int or str; floats are not accepted")
    try:
        value = Decimal(str(amount).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"invalid amount: {amount!r}") from exc
    if not value.is_finite():
        raise ValueError("amount must be finite")
    if value <= 0:
        raise ValueError("amount must be strictly positive")
    return format(value.normalize(), "f")


def _canonical_currency(currency: Any) -> str:
    if not isinstance(currency, str) or not currency.strip():
        raise ValueError("currency must be a non-empty string")
    return currency.strip().upper()


def _require_text(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _require_aware(name: str, value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be a timezone-aware datetime")
    return value


def _iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()


def _parse_iso(value: Optional[str]) -> Optional[datetime]:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def compute_request_fingerprint(
    tenant_id: str,
    action_id: str,
    payment_intent_id: str,
    amount: Any,
    currency: str,
    destination_id: str,
) -> str:
    """Deterministic SHA-256 hex digest of the canonical request tuple."""
    canonical = json.dumps(
        [
            _require_text("tenant_id", tenant_id),
            _require_text("action_id", action_id),
            _require_text("payment_intent_id", payment_intent_id),
            _canonical_amount(amount),
            _canonical_currency(currency),
            _require_text("destination_id", destination_id),
        ],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _derive_id(prefix: str, tenant_id: str, key: str) -> str:
    digest = hashlib.sha256(
        json.dumps([tenant_id, key], separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return f"{prefix}_{digest[:32]}"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PaymentIntent:
    """Immutable representation of a payment intent."""

    payment_intent_id: str
    tenant_id: str
    action_id: str
    session_id: str
    subject_id: str
    amount: Decimal
    currency: str
    destination_id: str
    idempotency_key: str
    request_fingerprint: str
    security_context_id: str
    approval_id: Optional[str]
    created_at: datetime


@dataclass(frozen=True)
class TransactionExecution:
    """Snapshot of the durable execution record."""

    transaction_execution_id: str
    tenant_id: str
    payment_intent_id: str
    action_id: str
    idempotency_key: str
    request_fingerprint: str
    state: TransactionExecutionState
    version: int
    created_at: datetime
    updated_at: datetime
    authorized_at: Optional[datetime] = None
    approved_at: Optional[datetime] = None
    reserved_at: Optional[datetime] = None
    submitted_at: Optional[datetime] = None
    settled_at: Optional[datetime] = None
    failed_at: Optional[datetime] = None
    unknown_at: Optional[datetime] = None
    failure_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_SCHEMA_STATEMENTS: Tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS payment_intents (
        payment_intent_id   TEXT PRIMARY KEY,
        tenant_id           TEXT NOT NULL,
        action_id           TEXT NOT NULL,
        session_id          TEXT NOT NULL,
        subject_id          TEXT NOT NULL,
        amount              TEXT NOT NULL,
        currency            TEXT NOT NULL,
        destination_id      TEXT NOT NULL,
        idempotency_key     TEXT NOT NULL,
        request_fingerprint TEXT NOT NULL,
        security_context_id TEXT NOT NULL,
        approval_id         TEXT,
        created_at          TEXT NOT NULL,
        UNIQUE (tenant_id, idempotency_key),
        UNIQUE (tenant_id, action_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS transaction_executions (
        transaction_execution_id TEXT PRIMARY KEY,
        tenant_id                TEXT NOT NULL,
        payment_intent_id        TEXT NOT NULL UNIQUE,
        action_id                TEXT NOT NULL,
        idempotency_key          TEXT NOT NULL,
        request_fingerprint      TEXT NOT NULL,
        state                    TEXT NOT NULL,
        version                  INTEGER NOT NULL,
        created_at               TEXT NOT NULL,
        updated_at               TEXT NOT NULL,
        authorized_at            TEXT,
        approved_at              TEXT,
        reserved_at              TEXT,
        submitted_at             TEXT,
        settled_at               TEXT,
        failed_at                TEXT,
        unknown_at               TEXT,
        failure_reason           TEXT,
        UNIQUE (tenant_id, idempotency_key),
        UNIQUE (tenant_id, action_id)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS transaction_ledger_entries (
        ledger_entry_id          TEXT PRIMARY KEY,
        tenant_id                TEXT NOT NULL,
        transaction_execution_id TEXT NOT NULL,
        payment_intent_id        TEXT NOT NULL,
        entry_type               TEXT NOT NULL,
        amount                   TEXT NOT NULL,
        currency                 TEXT NOT NULL,
        destination_id           TEXT NOT NULL,
        executor_id              TEXT,
        created_at               TEXT NOT NULL,
        UNIQUE (tenant_id, transaction_execution_id, entry_type)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS provider_outbox (
        outbox_id                TEXT PRIMARY KEY,
        tenant_id                TEXT NOT NULL,
        transaction_execution_id TEXT NOT NULL,
        payment_intent_id        TEXT NOT NULL,
        idempotency_key          TEXT NOT NULL,
        request_fingerprint      TEXT NOT NULL,
        payload                  TEXT NOT NULL,
        status                   TEXT NOT NULL,
        attempts                 INTEGER NOT NULL,
        created_at               TEXT NOT NULL,
        UNIQUE (tenant_id, transaction_execution_id)
    )
    """,
)

_INTENT_COLUMNS = (
    "payment_intent_id, tenant_id, action_id, session_id, subject_id, amount, "
    "currency, destination_id, idempotency_key, request_fingerprint, "
    "security_context_id, approval_id, created_at"
)

_EXECUTION_COLUMNS = (
    "transaction_execution_id, tenant_id, payment_intent_id, action_id, "
    "idempotency_key, request_fingerprint, state, version, created_at, updated_at, "
    "authorized_at, approved_at, reserved_at, submitted_at, settled_at, failed_at, "
    "unknown_at, failure_reason"
)

_SUPPORTED_DIALECTS = ("sqlite", "postgres")


def _intent_from_row(row: Sequence[Any]) -> PaymentIntent:
    return PaymentIntent(
        payment_intent_id=row[0],
        tenant_id=row[1],
        action_id=row[2],
        session_id=row[3],
        subject_id=row[4],
        amount=Decimal(row[5]),
        currency=row[6],
        destination_id=row[7],
        idempotency_key=row[8],
        request_fingerprint=row[9],
        security_context_id=row[10],
        approval_id=row[11],
        created_at=_parse_iso(row[12]),  # type: ignore[arg-type]
    )


def _execution_from_row(row: Sequence[Any]) -> TransactionExecution:
    return TransactionExecution(
        transaction_execution_id=row[0],
        tenant_id=row[1],
        payment_intent_id=row[2],
        action_id=row[3],
        idempotency_key=row[4],
        request_fingerprint=row[5],
        state=TransactionExecutionState(row[6]),
        version=int(row[7]),
        created_at=_parse_iso(row[8]),  # type: ignore[arg-type]
        updated_at=_parse_iso(row[9]),  # type: ignore[arg-type]
        authorized_at=_parse_iso(row[10]),
        approved_at=_parse_iso(row[11]),
        reserved_at=_parse_iso(row[12]),
        submitted_at=_parse_iso(row[13]),
        settled_at=_parse_iso(row[14]),
        failed_at=_parse_iso(row[15]),
        unknown_at=_parse_iso(row[16]),
        failure_reason=row[17],
    )


def _is_integrity_error(exc: BaseException) -> bool:
    return any(cls.__name__ == "IntegrityError" for cls in type(exc).__mro__)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class DurableTransactionEngine:
    """DB-API 2.0 backed durable transaction engine.

    ``connection_factory`` is a zero-argument callable returning a fresh
    DB-API 2.0 connection (e.g. ``lambda: sqlite3.connect(path)`` or a
    psycopg connection). The engine opens one connection per operation,
    commits on success, rolls back on any exception and always closes it.
    """

    def __init__(
        self,
        connection_factory: Callable[[], Any],
        *,
        dialect: str = "sqlite",
        clock: Callable[[], datetime] = _utcnow,
    ) -> None:
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        if dialect not in _SUPPORTED_DIALECTS:
            raise ValueError(f"dialect must be one of {_SUPPORTED_DIALECTS}")
        self._connection_factory = connection_factory
        self._dialect = dialect
        self._clock = clock

    # -- low level helpers -------------------------------------------------

    def _adapt(self, sql: str) -> str:
        if self._dialect == "postgres":
            return sql.replace("?", "%s")
        return sql

    @property
    def _lock_clause(self) -> str:
        return " FOR UPDATE" if self._dialect == "postgres" else ""

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

    # -- schema --------------------------------------------------------------

    def ensure_schema(self) -> None:
        """Create the engine's tables if they do not exist (idempotent)."""
        with self._transaction() as conn:
            for statement in _SCHEMA_STATEMENTS:
                self._write(conn, statement)

    # -- loaders -----------------------------------------------------------------

    def _load_intent(
        self, conn: Any, tenant_id: str, payment_intent_id: str, lock: bool = False
    ) -> Optional[PaymentIntent]:
        row = self._fetchone(
            conn,
            f"SELECT {_INTENT_COLUMNS} FROM payment_intents "
            f"WHERE payment_intent_id = ? AND tenant_id = ?" + (self._lock_clause if lock else ""),
            (payment_intent_id, tenant_id),
        )
        return _intent_from_row(row) if row else None

    def _load_intent_by_key(
        self, conn: Any, tenant_id: str, idempotency_key: str
    ) -> Optional[PaymentIntent]:
        row = self._fetchone(
            conn,
            f"SELECT {_INTENT_COLUMNS} FROM payment_intents "
            f"WHERE tenant_id = ? AND idempotency_key = ?",
            (tenant_id, idempotency_key),
        )
        return _intent_from_row(row) if row else None

    def _load_intent_by_action(
        self, conn: Any, tenant_id: str, action_id: str
    ) -> Optional[PaymentIntent]:
        row = self._fetchone(
            conn,
            f"SELECT {_INTENT_COLUMNS} FROM payment_intents "
            f"WHERE tenant_id = ? AND action_id = ?",
            (tenant_id, action_id),
        )
        return _intent_from_row(row) if row else None

    def _load_execution(
        self, conn: Any, tenant_id: str, transaction_execution_id: str, lock: bool = False
    ) -> Optional[TransactionExecution]:
        row = self._fetchone(
            conn,
            f"SELECT {_EXECUTION_COLUMNS} FROM transaction_executions "
            f"WHERE transaction_execution_id = ? AND tenant_id = ?"
            + (self._lock_clause if lock else ""),
            (transaction_execution_id, tenant_id),
        )
        return _execution_from_row(row) if row else None

    def _load_execution_by_intent(
        self, conn: Any, tenant_id: str, payment_intent_id: str, lock: bool = False
    ) -> Optional[TransactionExecution]:
        row = self._fetchone(
            conn,
            f"SELECT {_EXECUTION_COLUMNS} FROM transaction_executions "
            f"WHERE payment_intent_id = ? AND tenant_id = ?" + (self._lock_clause if lock else ""),
            (payment_intent_id, tenant_id),
        )
        return _execution_from_row(row) if row else None

    # -- public reads ----------------------------------------------------------------

    def get_intent(self, payment_intent_id: str, tenant_id: str) -> PaymentIntent:
        _require_text("payment_intent_id", payment_intent_id)
        _require_text("tenant_id", tenant_id)
        with self._transaction() as conn:
            intent = self._load_intent(conn, tenant_id, payment_intent_id)
        if intent is None:
            raise TransactionNotFoundError("payment intent not found")
        return intent

    def get_execution(self, transaction_execution_id: str, tenant_id: str) -> TransactionExecution:
        _require_text("transaction_execution_id", transaction_execution_id)
        _require_text("tenant_id", tenant_id)
        with self._transaction() as conn:
            execution = self._load_execution(conn, tenant_id, transaction_execution_id)
        if execution is None:
            raise TransactionNotFoundError("transaction execution not found")
        return execution

    def get_execution_for_intent(
        self, payment_intent_id: str, tenant_id: str
    ) -> TransactionExecution:
        _require_text("payment_intent_id", payment_intent_id)
        _require_text("tenant_id", tenant_id)
        with self._transaction() as conn:
            execution = self._load_execution_by_intent(conn, tenant_id, payment_intent_id)
        if execution is None:
            raise TransactionNotFoundError("transaction execution not found")
        return execution

    # -- intent creation --------------------------------------------------------------

    def create_or_get_intent(
        self,
        tenant_id: str,
        action_id: str,
        session_id: str,
        subject_id: str,
        amount: Any,
        currency: str,
        destination_id: str,
        idempotency_key: str,
        security_context_id: str,
        approval_id: Optional[str] = None,
    ) -> PaymentIntent:
        """Create a payment intent plus its CREATED execution, or return the existing one.

        Uniqueness is enforced on ``(tenant_id, idempotency_key)`` and
        ``(tenant_id, action_id)``. A repeated request with the same
        fingerprint returns the existing intent; any divergence raises
        ``IdempotencyConflictError``.
        """
        _require_text("tenant_id", tenant_id)
        _require_text("action_id", action_id)
        _require_text("session_id", session_id)
        _require_text("subject_id", subject_id)
        _require_text("destination_id", destination_id)
        _require_text("idempotency_key", idempotency_key)
        _require_text("security_context_id", security_context_id)
        if approval_id is not None:
            _require_text("approval_id", approval_id)
        canonical_amount = _canonical_amount(amount)
        canonical_currency = _canonical_currency(currency)

        # Deterministic ids make retries converge on the same fingerprint.
        payment_intent_id = _derive_id("pi", tenant_id, idempotency_key)
        transaction_execution_id = _derive_id("te", tenant_id, idempotency_key)
        fingerprint = compute_request_fingerprint(
            tenant_id,
            action_id,
            payment_intent_id,
            canonical_amount,
            canonical_currency,
            destination_id,
        )

        last_error: Optional[BaseException] = None
        for _attempt in range(2):
            try:
                with self._transaction() as conn:
                    existing = self._load_intent_by_key(conn, tenant_id, idempotency_key)
                    if existing is not None:
                        if existing.request_fingerprint != fingerprint:
                            raise IdempotencyConflictError(
                                "idempotency key was already used with a different request"
                            )
                        return existing

                    by_action = self._load_intent_by_action(conn, tenant_id, action_id)
                    if by_action is not None:
                        raise IdempotencyConflictError(
                            "action_id is already bound to a different payment intent"
                        )

                    now = self._clock()
                    _require_aware("clock()", now)
                    now_iso = _iso(now)

                    self._write(
                        conn,
                        "INSERT INTO payment_intents ("
                        "payment_intent_id, tenant_id, action_id, session_id, subject_id, "
                        "amount, currency, destination_id, idempotency_key, "
                        "request_fingerprint, security_context_id, approval_id, created_at"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            payment_intent_id,
                            tenant_id,
                            action_id,
                            session_id,
                            subject_id,
                            canonical_amount,
                            canonical_currency,
                            destination_id,
                            idempotency_key,
                            fingerprint,
                            security_context_id,
                            approval_id,
                            now_iso,
                        ),
                    )
                    self._write(
                        conn,
                        "INSERT INTO transaction_executions ("
                        "transaction_execution_id, tenant_id, payment_intent_id, action_id, "
                        "idempotency_key, request_fingerprint, state, version, created_at, "
                        "updated_at"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            transaction_execution_id,
                            tenant_id,
                            payment_intent_id,
                            action_id,
                            idempotency_key,
                            fingerprint,
                            TransactionExecutionState.CREATED.value,
                            1,
                            now_iso,
                            now_iso,
                        ),
                    )
                    return PaymentIntent(
                        payment_intent_id=payment_intent_id,
                        tenant_id=tenant_id,
                        action_id=action_id,
                        session_id=session_id,
                        subject_id=subject_id,
                        amount=Decimal(canonical_amount),
                        currency=canonical_currency,
                        destination_id=destination_id,
                        idempotency_key=idempotency_key,
                        request_fingerprint=fingerprint,
                        security_context_id=security_context_id,
                        approval_id=approval_id,
                        created_at=now,
                    )
            except Exception as exc:
                # A concurrent creator won the race on a unique constraint:
                # retry once so we re-read and resolve idempotently.
                if _is_integrity_error(exc):
                    last_error = exc
                    continue
                raise
        assert last_error is not None
        raise IdempotencyConflictError(
            "concurrent conflicting creation of payment intent"
        ) from last_error

    # -- generic transitions ------------------------------------------------------------

    def transition_state(
        self,
        transaction_execution_id: str,
        tenant_id: str,
        target_state: TransactionExecutionState,
        *,
        now: Optional[datetime] = None,
        expected_version: Optional[int] = None,
        reconciled: bool = False,
        failure_reason: Optional[str] = None,
    ) -> TransactionExecution:
        """Atomically move an execution to ``target_state`` and bump its version.

        * Transitions are validated against ``ALLOWED_TRANSITIONS`` before any
          write; an invalid transition raises ``InvalidStateTransitionError``
          with no side effects.
        * ``UNKNOWN -> *`` requires ``reconciled=True``.
        * ``APPROVED -> RESERVED`` is only reachable through
          ``reserve_execution`` because it must consume approval evidence and
          write the ledger/outbox records atomically.
        * ``expected_version`` enables optimistic concurrency control.
        """
        _require_text("transaction_execution_id", transaction_execution_id)
        _require_text("tenant_id", tenant_id)
        if not isinstance(target_state, TransactionExecutionState):
            raise InvalidStateTransitionError("target_state must be a TransactionExecutionState")
        if target_state is TransactionExecutionState.RESERVED:
            raise InvalidStateTransitionError(
                "RESERVED can only be entered through reserve_execution"
            )
        if target_state is TransactionExecutionState.CREATED:
            raise InvalidStateTransitionError("CREATED cannot be a transition target")
        effective_now = now if now is not None else self._clock()
        _require_aware("now", effective_now)

        with self._transaction() as conn:
            execution = self._load_execution(conn, tenant_id, transaction_execution_id, lock=True)
            if execution is None:
                raise TransactionNotFoundError("transaction execution not found")
            if expected_version is not None and execution.version != expected_version:
                raise ConcurrentModificationError(
                    f"expected version {expected_version}, found {execution.version}"
                )
            validate_transition(execution.state, target_state, reconciled=reconciled)
            return self._apply_transition(
                conn, execution, target_state, effective_now, failure_reason
            )

    def _apply_transition(
        self,
        conn: Any,
        execution: TransactionExecution,
        target_state: TransactionExecutionState,
        now: datetime,
        failure_reason: Optional[str],
    ) -> TransactionExecution:
        """Persist an already-validated transition using compare-and-set on state+version."""
        column = _STATE_TIMESTAMP_COLUMN[target_state]  # whitelisted constant
        now_iso = _iso(now)
        reason = failure_reason if target_state is TransactionExecutionState.FAILED else None
        rowcount = self._write(
            conn,
            f"UPDATE transaction_executions SET state = ?, version = version + 1, "
            f"updated_at = ?, {column} = ?, failure_reason = COALESCE(?, failure_reason) "
            f"WHERE transaction_execution_id = ? AND tenant_id = ? AND state = ? AND version = ?",
            (
                target_state.value,
                now_iso,
                now_iso,
                reason,
                execution.transaction_execution_id,
                execution.tenant_id,
                execution.state.value,
                execution.version,
            ),
        )
        if rowcount != 1:
            raise ConcurrentModificationError("execution was modified concurrently")
        updated = self._load_execution(
            conn, execution.tenant_id, execution.transaction_execution_id
        )
        if updated is None:  # pragma: no cover - defensive
            raise TransactionNotFoundError("transaction execution disappeared during update")
        return updated

    # -- reservation boundary ---------------------------------------------------------------

    @staticmethod
    def _verify_evidence_bindings(intent: PaymentIntent, evidence: ApprovalEvidence) -> None:
        """Verify that the approval evidence is bound to exactly this intent."""
        if evidence.tenant_id != intent.tenant_id:
            raise ApprovalEvidenceInvalid("approval evidence tenant mismatch")
        if intent.approval_id is not None and evidence.approval_id != intent.approval_id:
            raise ApprovalEvidenceInvalid("approval evidence approval_id mismatch")
        if evidence.action_id != intent.action_id:
            raise ApprovalEvidenceInvalid("approval evidence action_id mismatch")
        if evidence.session_id != intent.session_id:
            raise ApprovalEvidenceInvalid("approval evidence session_id mismatch")
        if evidence.subject_id != intent.subject_id:
            raise ApprovalEvidenceInvalid("approval evidence subject_id mismatch")
        if evidence.destination_id != intent.destination_id:
            raise ApprovalEvidenceInvalid("approval evidence destination_id mismatch")
        try:
            evidence_amount = _canonical_amount(evidence.amount)
            evidence_currency = _canonical_currency(evidence.currency)
        except ValueError as exc:
            raise ApprovalEvidenceInvalid("approval evidence amount/currency invalid") from exc
        if evidence_amount != _canonical_amount(intent.amount):
            raise ApprovalEvidenceInvalid("approval evidence amount mismatch")
        if evidence_currency != intent.currency:
            raise ApprovalEvidenceInvalid("approval evidence currency mismatch")

    def reserve_execution(
        self,
        payment_intent_id: str,
        tenant_id: str,
        approval_evidence: ApprovalEvidence,
        approval_store: ApprovalStore,
        now: datetime,
        executor_id: str,
    ) -> TransactionExecution:
        """Atomic reservation boundary (``APPROVED -> RESERVED``).

        Inside a single DB transaction:

        1. Lock/load the intent and execution; verify tenant and state.
        2. Verify the approval evidence is trusted, unexpired and bound
           exactly to the intent.
        3. Consume the approval via ``approval_store.consume``; ``False``
           rolls back and raises ``ApprovalEvidenceConsumed``.
        4. Transition the execution ``APPROVED -> RESERVED``.
        5. Insert a ``RESERVATION`` ledger entry.
        6. Insert a ``PENDING`` provider outbox record.

        Any failure rolls back every database write. The state is verified
        before the approval is consumed so a mis-ordered call never burns an
        approval.
        """
        _require_text("payment_intent_id", payment_intent_id)
        _require_text("tenant_id", tenant_id)
        _require_text("executor_id", executor_id)
        _require_aware("now", now)
        if approval_evidence is None or approval_store is None:
            raise ApprovalEvidenceInvalid("approval evidence and approval store are required")

        with self._transaction() as conn:
            # 1. Lock/load and verify tenant + state.
            intent = self._load_intent(conn, tenant_id, payment_intent_id, lock=True)
            if intent is None:
                raise TransactionNotFoundError("payment intent not found")
            execution = self._load_execution_by_intent(
                conn, tenant_id, payment_intent_id, lock=True
            )
            if execution is None:
                raise TransactionNotFoundError("transaction execution not found")
            if execution.state is not TransactionExecutionState.APPROVED:
                raise InvalidStateTransitionError(
                    f"transition {execution.state.value} -> "
                    f"{TransactionExecutionState.RESERVED.value} is not allowed"
                )
            validate_transition(execution.state, TransactionExecutionState.RESERVED)

            # 2. Verify evidence bindings, trust and expiry.
            self._verify_evidence_bindings(intent, approval_evidence)
            if not approval_evidence.is_trusted():
                raise ApprovalEvidenceInvalid("approval evidence is not trusted")
            if approval_evidence.is_expired(now):
                raise ApprovalEvidenceExpired("approval evidence has expired")

            # 3. Atomically consume the approval.
            consumed = approval_store.consume(
                approval_evidence,
                now,
                tenant_id=tenant_id,
                executor_id=executor_id,
            )
            if not consumed:
                raise ApprovalEvidenceConsumed("approval evidence was already consumed")

            try:
                # 4. APPROVED -> RESERVED.
                reserved = self._apply_transition(
                    conn, execution, TransactionExecutionState.RESERVED, now, None
                )
                now_iso = _iso(now)
                amount_text = _canonical_amount(intent.amount)

                # 5. Ledger entry.
                self._write(
                    conn,
                    "INSERT INTO transaction_ledger_entries ("
                    "ledger_entry_id, tenant_id, transaction_execution_id, payment_intent_id, "
                    "entry_type, amount, currency, destination_id, executor_id, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        f"le_{uuid.uuid4().hex}",
                        tenant_id,
                        reserved.transaction_execution_id,
                        intent.payment_intent_id,
                        "RESERVATION",
                        amount_text,
                        intent.currency,
                        intent.destination_id,
                        executor_id,
                        now_iso,
                    ),
                )

                # 6. Provider outbox record.
                payload = json.dumps(
                    {
                        "transaction_execution_id": reserved.transaction_execution_id,
                        "payment_intent_id": intent.payment_intent_id,
                        "tenant_id": tenant_id,
                        "action_id": intent.action_id,
                        "subject_id": intent.subject_id,
                        "amount": amount_text,
                        "currency": intent.currency,
                        "destination_id": intent.destination_id,
                        "idempotency_key": intent.idempotency_key,
                        "request_fingerprint": intent.request_fingerprint,
                        "approval_id": approval_evidence.approval_id,
                        "executor_id": executor_id,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                self._write(
                    conn,
                    "INSERT INTO provider_outbox ("
                    "outbox_id, tenant_id, transaction_execution_id, payment_intent_id, "
                    "idempotency_key, request_fingerprint, payload, status, attempts, created_at"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        f"ob_{uuid.uuid4().hex}",
                        tenant_id,
                        reserved.transaction_execution_id,
                        intent.payment_intent_id,
                        intent.idempotency_key,
                        intent.request_fingerprint,
                        payload,
                        "PENDING",
                        0,
                        now_iso,
                    ),
                )
                return reserved
            except BaseException:
                logger.critical(
                    "reservation rolled back after approval consumption; approval remains "
                    "consumed (fail-closed) tenant_id=%s payment_intent_id=%s approval_id=%s",
                    tenant_id,
                    payment_intent_id,
                    getattr(approval_evidence, "approval_id", None),
                    exc_info=True,
                )
                raise