"""Ovela Foundation - Milestone M7: Outbox Pattern, Dispatcher & Rail Orchestration.

This module provides:

* Rail adapter types: ``RailDispatchStatus``, ``PaymentInstruction``,
  ``RailDispatchResult`` and the ``PaymentRailAdapter`` protocol.
* ``OutboxEntry``, the immutable snapshot of one outbox row, plus the outbox
  state constants (``PENDING``, ``CLAIMED``, ``DISPATCHED``,
  ``RECONCILIATION_REQUIRED``).
* ``OutboxDispatcher``, a DB-API 2.0 backed dispatcher implementing the
  claim -> dispatch -> persist cycle with lease fencing.

Design notes
------------
* Three strictly separated phases. ``claim_next_entry`` and
  ``persist_dispatch_result`` are short DB transactions. ``dispatch_entry``
  performs the network call and touches no database, so DB locks are never held
  across network I/O.
* Fail closed. Any exception, timeout, connection reset or malformed adapter
  response during dispatch maps to ``RailDispatchStatus.UNKNOWN``, which
  persists as ``RECONCILIATION_REQUIRED``. Money may have moved, so it is never
  retried automatically and never returned to ``PENDING``.
* Expired leases (``CLAIMED`` with ``lease_until < now``) go straight to
  ``RECONCILIATION_REQUIRED``, never back to ``PENDING``. The payment may
  already have reached the provider.
* Lease fencing. Persisting a result requires
  ``id AND status = 'CLAIMED' AND claim_token AND claimed_by`` to match. A
  worker that lost its lease (recovered, re-claimed or already persisted)
  cannot overwrite state. By default a fencing violation returns ``False``;
  construct the dispatcher with ``raise_on_stale=True`` to raise
  ``StaleWorkerError`` instead.
* The M6 ``DurableTransactionEngine`` opens its own connection and
  transaction, so the outbox update commits first and the execution
  transition runs afterwards. If that transition fails, the outbox row is
  flagged ``RECONCILIATION_REQUIRED``, a CRITICAL log is emitted and
  ``TransactionStateSyncError`` is raised. State is never silently diverged.
* The dispatcher owns the ``outbox_entries`` table (created by
  ``ensure_schema``). It is a new table and does not alter the M6
  ``provider_outbox`` table, so M1-M6 behaviour is untouched. ``enqueue_entry``
  is the idempotent bridge that lets an orchestration layer enqueue a dispatch
  entry for a reserved execution.
* Money is never a float. Amounts travel as canonical decimal strings.
* Supported dialects: ``"sqlite"`` (qmark params, ``BEGIN IMMEDIATE``, atomic
  conditional ``UPDATE``) and ``"postgres"`` (``%s`` params,
  ``FOR UPDATE SKIP LOCKED``).
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Callable, Dict, Iterator, List, Optional, Protocol, Sequence, Tuple, Union
from uuid import UUID

try:  # Python 3.11+
    from enum import StrEnum
except ImportError:  # pragma: no cover - compatibility for older interpreters

    class StrEnum(str, Enum):  # type: ignore[no-redef]
        """Minimal ``StrEnum`` backport."""

        def __str__(self) -> str:
            return str(self.value)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class OutboxDispatcherError(Exception):
    """Base class for all outbox dispatcher errors."""


class StaleWorkerError(OutboxDispatcherError):
    """Raised when a worker no longer holds the claim it is acting on (fencing violation)."""


class OutboxConflictError(OutboxDispatcherError):
    """Raised when an idempotency key is re-enqueued with a different request."""


class OutboxEntryNotFoundError(OutboxDispatcherError):
    """Raised when an outbox entry does not exist."""


class TransactionStateSyncError(OutboxDispatcherError):
    """Raised when the outbox was updated but the execution transition failed."""


# ---------------------------------------------------------------------------
# Rail adapter types
# ---------------------------------------------------------------------------


class RailDispatchStatus(StrEnum):
    SUBMITTED = "SUBMITTED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class PaymentInstruction:
    """Immutable instruction handed to a payment rail."""

    transaction_id: str
    amount: Decimal
    currency: str
    destination_id: str


@dataclass(frozen=True)
class RailDispatchResult:
    """Outcome reported by (or synthesised for) a payment rail dispatch."""

    status: RailDispatchStatus
    provider_reference: str | None = None
    failure_code: str | None = None
    provider: str = ""
    raw_provider_status: str | None = None


class PaymentRailAdapter(Protocol):
    """Protocol every payment rail adapter implements."""

    def submit_payment(
        self, instruction: PaymentInstruction, *, idempotency_key: str
    ) -> RailDispatchResult: ...


# ---------------------------------------------------------------------------
# Outbox states and model
# ---------------------------------------------------------------------------

OUTBOX_STATUS_PENDING = "PENDING"
OUTBOX_STATUS_CLAIMED = "CLAIMED"
OUTBOX_STATUS_DISPATCHED = "DISPATCHED"
OUTBOX_STATUS_RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"

OUTBOX_STATUSES: Tuple[str, ...] = (
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_CLAIMED,
    OUTBOX_STATUS_DISPATCHED,
    OUTBOX_STATUS_RECONCILIATION_REQUIRED,
)


@dataclass(frozen=True)
class OutboxEntry:
    """Immutable snapshot of one outbox row."""

    id: UUID
    transaction_id: UUID
    status: str
    payload: Dict[str, Any]
    idempotency_key: str
    available_at: datetime
    claimed_by: Optional[str]
    claim_token: Optional[UUID]
    lease_until: Optional[datetime]
    attempt_count: int
    created_at: datetime
    updated_at: datetime
    tenant_id: str = ""
    provider_reference: Optional[str] = None
    failure_code: Optional[str] = None
    provider: Optional[str] = None
    raw_provider_status: Optional[str] = None
    dispatched_at: Optional[datetime] = field(default=None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS_FORMAT = "%Y-%m-%dT%H:%M:%S.%f+00:00"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SUPPORTED_DIALECTS = ("sqlite", "postgres")


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


def _require_uuid(name: str, value: Any) -> UUID:
    if isinstance(value, UUID):
        return value
    raise ValueError(f"{name} must be a uuid.UUID")


def _coerce_uuid(name: str, value: Any) -> UUID:
    if isinstance(value, UUID):
        return value
    if isinstance(value, str):
        try:
            return UUID(value)
        except ValueError as exc:
            raise ValueError(f"{name} must be a valid UUID") from exc
    raise ValueError(f"{name} must be a uuid.UUID or UUID string")


def _ts(value: Optional[datetime]) -> Optional[str]:
    """Serialise to a fixed-width UTC string so lexicographic order equals time order."""
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


def _canonical_payload(payload: Any) -> str:
    if isinstance(payload, str):
        try:
            decoded = json.loads(payload)
        except ValueError as exc:
            raise ValueError("payload string must be valid JSON") from exc
        if not isinstance(decoded, dict):
            raise ValueError("payload must be a JSON object")
        payload = decoded
    if not isinstance(payload, dict):
        raise ValueError("payload must be a dict or a JSON object string")
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _parse_amount(value: Any) -> Decimal:
    if isinstance(value, bool) or isinstance(value, float):
        raise ValueError("amount must be a Decimal, int or str; floats are not accepted")
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"invalid amount: {value!r}") from exc
    if not amount.is_finite() or amount <= 0:
        raise ValueError("amount must be finite and strictly positive")
    return amount


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DEFAULT_TABLE = "outbox_entries"

_ENTRY_COLUMNS = (
    "id, transaction_id, tenant_id, status, payload, idempotency_key, available_at, "
    "claimed_by, claim_token, lease_until, attempt_count, created_at, updated_at, "
    "provider_reference, failure_code, provider, raw_provider_status, dispatched_at"
)


def _schema_statements(table: str) -> Tuple[str, ...]:
    return (
        f"""
        CREATE TABLE IF NOT EXISTS {table} (
            id                  TEXT PRIMARY KEY,
            transaction_id      TEXT NOT NULL,
            tenant_id           TEXT NOT NULL,
            status              TEXT NOT NULL,
            payload             TEXT NOT NULL,
            idempotency_key     TEXT NOT NULL,
            available_at        TEXT NOT NULL,
            claimed_by          TEXT,
            claim_token         TEXT,
            lease_until         TEXT,
            attempt_count       INTEGER NOT NULL DEFAULT 0,
            created_at          TEXT NOT NULL,
            updated_at          TEXT NOT NULL,
            provider_reference  TEXT,
            failure_code        TEXT,
            provider            TEXT,
            raw_provider_status TEXT,
            dispatched_at       TEXT,
            UNIQUE (tenant_id, idempotency_key),
            UNIQUE (tenant_id, transaction_id)
        )
        """,
        f"CREATE INDEX IF NOT EXISTS idx_{table}_claim ON {table} (status, available_at)",
        f"CREATE INDEX IF NOT EXISTS idx_{table}_lease ON {table} (status, lease_until)",
    )


def _is_integrity_error(exc: BaseException) -> bool:
    return any(cls.__name__ == "IntegrityError" for cls in type(exc).__mro__)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------


class OutboxDispatcher:
    """Claims outbox entries, dispatches them to a payment rail and persists the outcome.

    ``connection_factory`` is a zero-argument callable returning a fresh
    DB-API 2.0 connection. One connection is opened per DB operation; it is
    committed on success, rolled back on any exception and always closed.
    """

    def __init__(
        self,
        connection_factory: Callable[[], Any],
        adapter: PaymentRailAdapter,
        *,
        dialect: str = "sqlite",
        clock: Callable[[], datetime] = _utcnow,
        table_name: str = _DEFAULT_TABLE,
        raise_on_stale: bool = False,
    ) -> None:
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")
        if adapter is None or not callable(getattr(adapter, "submit_payment", None)):
            raise TypeError("adapter must implement submit_payment")
        if dialect not in _SUPPORTED_DIALECTS:
            raise ValueError(f"dialect must be one of {_SUPPORTED_DIALECTS}")
        if not isinstance(table_name, str) or not _IDENTIFIER_RE.match(table_name):
            raise ValueError("table_name must be a simple SQL identifier")
        self._connection_factory = connection_factory
        self._adapter = adapter
        self._dialect = dialect
        self._clock = clock
        self._table = table_name
        self._raise_on_stale = raise_on_stale

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

    def _fetchall(self, conn: Any, sql: str, params: Sequence[Any] = ()) -> List[Sequence[Any]]:
        cur = conn.cursor()
        try:
            cur.execute(self._adapt(sql), tuple(params))
            return list(cur.fetchall())
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

    @property
    def _skip_locked_clause(self) -> str:
        return " FOR UPDATE SKIP LOCKED" if self._dialect == "postgres" else ""

    @staticmethod
    def _entry_from_row(row: Sequence[Any]) -> OutboxEntry:
        return OutboxEntry(
            id=UUID(row[0]),
            transaction_id=UUID(row[1]),
            tenant_id=row[2],
            status=row[3],
            payload=json.loads(row[4]),
            idempotency_key=row[5],
            available_at=_parse_ts(row[6]),  # type: ignore[arg-type]
            claimed_by=row[7],
            claim_token=UUID(row[8]) if row[8] is not None else None,
            lease_until=_parse_ts(row[9]),
            attempt_count=int(row[10]),
            created_at=_parse_ts(row[11]),  # type: ignore[arg-type]
            updated_at=_parse_ts(row[12]),  # type: ignore[arg-type]
            provider_reference=row[13],
            failure_code=row[14],
            provider=row[15],
            raw_provider_status=row[16],
            dispatched_at=_parse_ts(row[17]),
        )

    def _now(self) -> datetime:
        now = self._clock()
        return _require_aware("clock()", now)

    # -- schema -----------------------------------------------------------------

    def ensure_schema(self) -> None:
        """Create the outbox table and indexes if they do not exist (idempotent)."""
        with self._transaction() as conn:
            for statement in _schema_statements(self._table):
                self._write(conn, statement)

    # -- reads -------------------------------------------------------------------

    def get_entry(self, entry_id: UUID) -> OutboxEntry:
        entry_id = _coerce_uuid("entry_id", entry_id)
        with self._transaction() as conn:
            row = self._fetchone(
                conn,
                f"SELECT {_ENTRY_COLUMNS} FROM {self._table} WHERE id = ?",
                (str(entry_id),),
            )
        if row is None:
            raise OutboxEntryNotFoundError("outbox entry not found")
        return self._entry_from_row(row)

    # -- enqueue -----------------------------------------------------------------

    def enqueue_entry(
        self,
        transaction_id: Union[UUID, str],
        tenant_id: str,
        payload: Union[Dict[str, Any], str],
        idempotency_key: str,
        *,
        available_at: Optional[datetime] = None,
    ) -> OutboxEntry:
        """Idempotently enqueue a ``PENDING`` entry.

        Uniqueness is enforced on ``(tenant_id, idempotency_key)`` and
        ``(tenant_id, transaction_id)``. Re-enqueueing an identical request
        returns the existing entry; a diverging request raises
        ``OutboxConflictError``.
        """
        tx_id = _coerce_uuid("transaction_id", transaction_id)
        _require_text("tenant_id", tenant_id)
        _require_text("idempotency_key", idempotency_key)
        canonical = _canonical_payload(payload)
        now = self._now()
        available = _require_aware("available_at", available_at) if available_at else now

        last_error: Optional[BaseException] = None
        for _attempt in range(2):
            try:
                with self._transaction() as conn:
                    row = self._fetchone(
                        conn,
                        f"SELECT {_ENTRY_COLUMNS} FROM {self._table} "
                        f"WHERE tenant_id = ? AND (idempotency_key = ? OR transaction_id = ?)",
                        (tenant_id, idempotency_key, str(tx_id)),
                    )
                    if row is not None:
                        existing = self._entry_from_row(row)
                        if (
                            existing.idempotency_key == idempotency_key
                            and existing.transaction_id == tx_id
                            and _canonical_payload(existing.payload) == canonical
                        ):
                            return existing
                        raise OutboxConflictError(
                            "outbox entry already exists for a different request"
                        )
                    entry_id = uuid.uuid4()
                    self._write(
                        conn,
                        f"INSERT INTO {self._table} ("
                        "id, transaction_id, tenant_id, status, payload, idempotency_key, "
                        "available_at, claimed_by, claim_token, lease_until, attempt_count, "
                        "created_at, updated_at"
                        ") VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 0, ?, ?)",
                        (
                            str(entry_id),
                            str(tx_id),
                            tenant_id,
                            OUTBOX_STATUS_PENDING,
                            canonical,
                            idempotency_key,
                            _ts(available),
                            _ts(now),
                            _ts(now),
                        ),
                    )
                    return OutboxEntry(
                        id=entry_id,
                        transaction_id=tx_id,
                        tenant_id=tenant_id,
                        status=OUTBOX_STATUS_PENDING,
                        payload=json.loads(canonical),
                        idempotency_key=idempotency_key,
                        available_at=available,
                        claimed_by=None,
                        claim_token=None,
                        lease_until=None,
                        attempt_count=0,
                        created_at=now,
                        updated_at=now,
                    )
            except Exception as exc:
                if _is_integrity_error(exc):
                    last_error = exc
                    continue
                raise
        assert last_error is not None
        raise OutboxConflictError("concurrent conflicting enqueue") from last_error

    # -- claim -------------------------------------------------------------------

    def claim_next_entry(self, worker_id: str, lease_seconds: int = 30) -> OutboxEntry | None:
        """Atomically claim one due ``PENDING`` entry in a short transaction.

        The claim sets ``status = 'CLAIMED'``, ``claimed_by``, a fresh
        ``claim_token``, ``lease_until`` and increments ``attempt_count``, then
        commits immediately so no DB lock is held during network dispatch.
        Returns ``None`` when nothing is due.
        """
        _require_text("worker_id", worker_id)
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int) or lease_seconds <= 0:
            raise ValueError("lease_seconds must be a positive integer")
        now = self._now()
        now_s = _ts(now)
        lease_s = _ts(now + timedelta(seconds=lease_seconds))
        token = uuid.uuid4()

        with self._transaction() as conn:
            row = self._fetchone(
                conn,
                f"SELECT id FROM {self._table} "
                f"WHERE status = ? AND available_at <= ? "
                f"ORDER BY available_at, created_at, id LIMIT 1" + self._skip_locked_clause,
                (OUTBOX_STATUS_PENDING, now_s),
            )
            if row is None:
                return None
            entry_id = row[0]
            # Conditional update: the status guard makes the claim atomic even
            # when row locks are unavailable (SQLite).
            affected = self._write(
                conn,
                f"UPDATE {self._table} SET status = ?, claimed_by = ?, claim_token = ?, "
                f"lease_until = ?, attempt_count = attempt_count + 1, updated_at = ? "
                f"WHERE id = ? AND status = ?",
                (
                    OUTBOX_STATUS_CLAIMED,
                    worker_id,
                    str(token),
                    lease_s,
                    now_s,
                    entry_id,
                    OUTBOX_STATUS_PENDING,
                ),
            )
            if affected != 1:
                return None
            claimed = self._fetchone(
                conn,
                f"SELECT {_ENTRY_COLUMNS} FROM {self._table} WHERE id = ?",
                (entry_id,),
            )
            if claimed is None:  # pragma: no cover - defensive
                return None
            return self._entry_from_row(claimed)

    # -- dispatch ------------------------------------------------------------------

    @staticmethod
    def _unknown(reason: str) -> RailDispatchResult:
        return RailDispatchResult(
            status=RailDispatchStatus.UNKNOWN,
            failure_code=reason,
            provider="",
            raw_provider_status=None,
        )

    def _build_instruction(self, entry: OutboxEntry) -> PaymentInstruction:
        payload = entry.payload
        if not isinstance(payload, dict):
            raise ValueError("outbox payload must be an object")
        return PaymentInstruction(
            transaction_id=str(entry.transaction_id),
            amount=_parse_amount(payload.get("amount")),
            currency=_require_text("currency", payload.get("currency")).strip().upper(),
            destination_id=_require_text("destination_id", payload.get("destination_id")),
        )

    def dispatch_entry(self, entry: OutboxEntry, worker_id: str) -> RailDispatchResult:
        """Perform the external dispatch for a claimed entry. Touches no database.

        Only the claimant may dispatch. Any adapter exception (timeouts,
        connection resets, unexpected runtime errors) or malformed adapter
        response maps strictly to ``RailDispatchStatus.UNKNOWN`` (fail-closed).
        """
        _require_text("worker_id", worker_id)
        if entry.status != OUTBOX_STATUS_CLAIMED or entry.claimed_by != worker_id:
            raise StaleWorkerError("entry is not claimed by this worker; refusing to dispatch")
        if entry.claim_token is None:
            raise StaleWorkerError("entry has no claim token; refusing to dispatch")

        try:
            instruction = self._build_instruction(entry)
        except Exception:
            logger.exception(
                "invalid outbox payload; failing closed entry_id=%s", entry.id
            )
            return self._unknown("INVALID_PAYLOAD")

        try:
            result = self._adapter.submit_payment(
                instruction, idempotency_key=entry.idempotency_key
            )
        except Exception as exc:
            logger.error(
                "rail dispatch raised %s; mapping to UNKNOWN entry_id=%s",
                type(exc).__name__,
                entry.id,
            )
            return self._unknown(f"ADAPTER_EXCEPTION:{type(exc).__name__}")

        if not isinstance(result, RailDispatchResult) or not isinstance(
            result.status, RailDispatchStatus
        ):
            logger.error("rail adapter returned a malformed result entry_id=%s", entry.id)
            return self._unknown("MALFORMED_ADAPTER_RESULT")
        return result

    # -- persist ---------------------------------------------------------------------

    @staticmethod
    def _targets(result: RailDispatchResult) -> Tuple[str, Optional[str]]:
        """Return (outbox status, execution state name) for a dispatch result."""
        if result.status is RailDispatchStatus.SUBMITTED:
            return OUTBOX_STATUS_DISPATCHED, "SUBMITTED"
        if result.status is RailDispatchStatus.FAILED:
            return OUTBOX_STATUS_DISPATCHED, "FAILED"
        return OUTBOX_STATUS_RECONCILIATION_REQUIRED, "UNKNOWN"

    def _resolve_engine_state(self, transaction_engine: Any, name: str) -> Any:
        """Resolve the engine's ``TransactionExecutionState`` member by name."""
        state_enum = getattr(transaction_engine, "STATE_ENUM", None)
        if state_enum is None:
            from app.transaction_engine import TransactionExecutionState

            state_enum = TransactionExecutionState
        return state_enum[name]

    def persist_dispatch_result(
        self,
        entry: OutboxEntry,
        worker_id: str,
        claim_token: UUID,
        result: RailDispatchResult,
        transaction_engine: Any = None,
    ) -> bool:
        """Persist a dispatch outcome under lease fencing.

        The outbox update only applies when
        ``id = entry.id AND status = 'CLAIMED' AND claim_token = claim_token
        AND claimed_by = worker_id``. A fencing violation returns ``False``
        (or raises ``StaleWorkerError`` when ``raise_on_stale=True``) and
        changes nothing.

        * ``SUBMITTED`` -> outbox ``DISPATCHED``; execution ``SUBMITTED``.
        * ``FAILED`` -> outbox ``DISPATCHED`` with ``failure_code``; execution ``FAILED``.
        * ``UNKNOWN`` -> outbox ``RECONCILIATION_REQUIRED``; execution ``UNKNOWN``.
          Never retried automatically.
        """
        _require_text("worker_id", worker_id)
        _require_uuid("claim_token", claim_token)
        if not isinstance(entry, OutboxEntry):
            raise TypeError("entry must be an OutboxEntry")
        if not isinstance(result, RailDispatchResult) or not isinstance(
            result.status, RailDispatchStatus
        ):
            raise TypeError("result must be a RailDispatchResult")

        now = self._now()
        now_s = _ts(now)
        outbox_status, engine_state_name = self._targets(result)
        dispatched_s = now_s if outbox_status == OUTBOX_STATUS_DISPATCHED else None

        with self._transaction() as conn:
            affected = self._write(
                conn,
                f"UPDATE {self._table} SET status = ?, updated_at = ?, "
                f"provider_reference = ?, failure_code = ?, provider = ?, "
                f"raw_provider_status = ?, dispatched_at = ? "
                f"WHERE id = ? AND status = ? AND claim_token = ? AND claimed_by = ?",
                (
                    outbox_status,
                    now_s,
                    result.provider_reference,
                    result.failure_code,
                    result.provider or None,
                    result.raw_provider_status,
                    dispatched_s,
                    str(entry.id),
                    OUTBOX_STATUS_CLAIMED,
                    str(claim_token),
                    worker_id,
                ),
            )
        if affected != 1:
            logger.warning(
                "fencing violation: stale worker cannot persist result entry_id=%s worker_id=%s",
                entry.id,
                worker_id,
            )
            if self._raise_on_stale:
                raise StaleWorkerError("claim lost; dispatch result was not persisted")
            return False

        if transaction_engine is not None and engine_state_name is not None:
            self._sync_execution(
                entry, transaction_engine, engine_state_name, result, outbox_status, now
            )
        return True

    def _sync_execution(
        self,
        entry: OutboxEntry,
        transaction_engine: Any,
        engine_state_name: str,
        result: RailDispatchResult,
        outbox_status: str,
        now: datetime,
    ) -> None:
        """Transition the execution after the outbox commit; fail closed on error."""
        try:
            target = self._resolve_engine_state(transaction_engine, engine_state_name)
            kwargs: Dict[str, Any] = {"now": now}
            if engine_state_name == "FAILED":
                kwargs["failure_reason"] = result.failure_code
            transaction_engine.transition_state(
                str(entry.transaction_id),
                entry.tenant_id,
                target,
                **kwargs,
            )
        except Exception as exc:
            logger.critical(
                "outbox updated but execution transition failed; flagging for reconciliation "
                "entry_id=%s transaction_id=%s target=%s",
                entry.id,
                entry.transaction_id,
                engine_state_name,
                exc_info=True,
            )
            if outbox_status != OUTBOX_STATUS_RECONCILIATION_REQUIRED:
                self._flag_reconciliation(entry.id, now)
            raise TransactionStateSyncError(
                f"execution transition to {engine_state_name} failed after outbox update"
            ) from exc

    def _flag_reconciliation(self, entry_id: UUID, now: datetime) -> None:
        try:
            with self._transaction() as conn:
                self._write(
                    conn,
                    f"UPDATE {self._table} SET status = ?, updated_at = ? "
                    f"WHERE id = ? AND status = ?",
                    (
                        OUTBOX_STATUS_RECONCILIATION_REQUIRED,
                        _ts(now),
                        str(entry_id),
                        OUTBOX_STATUS_DISPATCHED,
                    ),
                )
        except Exception:  # pragma: no cover - best effort, already logged CRITICAL
            logger.critical(
                "failed to flag outbox entry for reconciliation entry_id=%s",
                entry_id,
                exc_info=True,
            )

    # -- lease recovery ------------------------------------------------------------------

    def recover_expired_leases(
        self, now: datetime, transaction_engine: Any = None
    ) -> list[UUID]:
        """Move expired claims straight to ``RECONCILIATION_REQUIRED``.

        Applies to ``status = 'CLAIMED' AND lease_until < now``. Entries are
        never returned to ``PENDING``: the payment may already have reached the
        provider. The claim token is retained for forensics; because the status
        changes, a stale worker is fenced out. When ``transaction_engine`` is
        given, each recovered execution is moved to ``UNKNOWN`` on a best-effort
        basis after the outbox commit (failures are logged, never raised).
        """
        _require_aware("now", now)
        now_s = _ts(now)
        recovered: List[Tuple[UUID, UUID, str]] = []

        with self._transaction() as conn:
            rows = self._fetchall(
                conn,
                f"SELECT id, transaction_id, tenant_id FROM {self._table} "
                f"WHERE status = ? AND lease_until < ? ORDER BY lease_until, id"
                + self._skip_locked_clause,
                (OUTBOX_STATUS_CLAIMED, now_s),
            )
            for row in rows:
                affected = self._write(
                    conn,
                    f"UPDATE {self._table} SET status = ?, updated_at = ? "
                    f"WHERE id = ? AND status = ? AND lease_until < ?",
                    (
                        OUTBOX_STATUS_RECONCILIATION_REQUIRED,
                        now_s,
                        row[0],
                        OUTBOX_STATUS_CLAIMED,
                        now_s,
                    ),
                )
                if affected == 1:
                    recovered.append((UUID(row[0]), UUID(row[1]), row[2]))

        if recovered:
            logger.warning(
                "recovered %d expired outbox lease(s) into RECONCILIATION_REQUIRED",
                len(recovered),
            )

        if transaction_engine is not None:
            for entry_id, transaction_id, tenant_id in recovered:
                try:
                    target = self._resolve_engine_state(transaction_engine, "UNKNOWN")
                    transaction_engine.transition_state(
                        str(transaction_id), tenant_id, target, now=now
                    )
                except Exception:
                    logger.error(
                        "could not mark execution UNKNOWN after lease recovery "
                        "entry_id=%s transaction_id=%s",
                        entry_id,
                        transaction_id,
                        exc_info=True,
                    )
        return [entry_id for entry_id, _tx, _tenant in recovered]

    # -- orchestration convenience ----------------------------------------------------------

    def run_once(
        self,
        worker_id: str,
        lease_seconds: int = 30,
        transaction_engine: Any = None,
    ) -> Optional[RailDispatchResult]:
        """Claim, dispatch and persist a single entry. Returns ``None`` if nothing was due."""
        entry = self.claim_next_entry(worker_id, lease_seconds)
        if entry is None:
            return None
        assert entry.claim_token is not None
        result = self.dispatch_entry(entry, worker_id)
        self.persist_dispatch_result(
            entry, worker_id, entry.claim_token, result, transaction_engine
        )
        return result