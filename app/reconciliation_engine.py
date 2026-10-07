"""
app/reconciliation_engine.py

Milestone M9: Independent Financial Reconciliation Engine & Truth Convergence
Ovela Foundation

Invariants enforced by this module:
  * External statements and provider responses are EVIDENCE, never AUTHORITY.
    No statement entry can unilaterally mutate financial truth; the only
    permitted mutation path is DurableTransactionEngine.transition_state,
    which validates permitted state transitions.
  * Missing statement evidence is NEVER assumed to mean failure. After the
    clearing deadline the result fails closed to MISSING_EXTERNAL; the
    transaction is never marked FAILED or REVERSED by this module.
  * Ledger entries are append-only. SETTLEMENT_CONFIRMED is appended at most
    once per transaction_execution_id (idempotent under repeated
    reconciliation, protected by a check-then-insert inside a single DB
    transaction plus a unique index).
  * Every anomaly (ambiguity, duplicates, conflicting evidence, unexpected
    states) fails closed to a non-MATCHED reconciliation state.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Any, Callable, Iterator, Sequence

from app.transaction_engine import (
    DurableTransactionEngine,
    TransactionExecutionState,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core enums
# ---------------------------------------------------------------------------


class ReconciliationState(StrEnum):
    MATCHED_SETTLED = "MATCHED_SETTLED"
    PENDING_CLEARING = "PENDING_CLEARING"
    AMOUNT_MISMATCH = "AMOUNT_MISMATCH"
    CURRENCY_MISMATCH = "CURRENCY_MISMATCH"
    REFERENCE_MISMATCH = "REFERENCE_MISMATCH"
    MISSING_INTERNAL = "MISSING_INTERNAL"
    MISSING_EXTERNAL = "MISSING_EXTERNAL"
    DUPLICATE_EXTERNAL = "DUPLICATE_EXTERNAL"
    CONFLICTING_EVIDENCE = "CONFLICTING_EVIDENCE"
    UNKNOWN = "UNKNOWN"
    DISCREPANCY = "DISCREPANCY"


class StatementEntryDirection(StrEnum):
    CREDIT = "CREDIT"
    DEBIT = "DEBIT"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SettlementStatement:
    statement_id: uuid.UUID
    tenant_id: uuid.UUID
    provider_id: str
    account_id: str
    source_filename: str
    source_hash: str
    received_at: datetime
    line_count: int


@dataclass(frozen=True)
class SettlementStatementEntry:
    entry_id: uuid.UUID
    statement_id: uuid.UUID
    tenant_id: uuid.UUID
    provider_id: str
    provider_reference: str | None
    transaction_reference: str | None
    amount: Decimal
    currency: str
    direction: StatementEntryDirection
    settled_at: datetime
    raw_line_hash: str


@dataclass(frozen=True)
class ReconciliationCase:
    reconciliation_id: uuid.UUID
    tenant_id: uuid.UUID
    transaction_id: uuid.UUID | None
    statement_entry_id: uuid.UUID | None
    state: ReconciliationState
    discrepancy_reason: str | None
    evaluated_at: datetime


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class ReconciliationError(Exception):
    """Base class for reconciliation engine errors."""


class StatementIngestionError(ReconciliationError):
    """Raised when a statement cannot be ingested safely."""


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SETTLEMENT_CONFIRMED = "SETTLEMENT_CONFIRMED"

_TRANSITIONABLE_TO_SETTLED = frozenset(
    {
        TransactionExecutionState.SUBMITTED.value,
        TransactionExecutionState.UNKNOWN.value,
    }
)

_SETTLED = TransactionExecutionState.SETTLED.value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ensure_aware(value: datetime) -> datetime:
    """Normalise datetimes to timezone-aware UTC for safe comparison."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        return _ensure_aware(value)
    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return _ensure_aware(datetime.fromisoformat(text))
    raise StatementIngestionError(f"Unparseable datetime value: {value!r}")


def _parse_decimal(value: Any) -> Decimal:
    if isinstance(value, Decimal):
        result = value
    elif isinstance(value, bool):
        raise StatementIngestionError(f"Invalid amount: {value!r}")
    else:
        try:
            result = Decimal(str(value).strip())
        except (InvalidOperation, ValueError) as exc:
            raise StatementIngestionError(f"Invalid amount: {value!r}") from exc
    if not result.is_finite():
        raise StatementIngestionError(f"Non-finite amount: {value!r}")
    return result


def _parse_uuid(value: Any, field_name: str) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError) as exc:
        raise StatementIngestionError(
            f"Invalid UUID for {field_name}: {value!r}"
        ) from exc


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _decimal_to_db(value: Decimal) -> str:
    """Canonical text storage for Decimal (portable across sqlite/psycopg)."""
    return format(value, "f")


def _decimal_from_db(value: Any) -> Decimal:
    if isinstance(value, Decimal):
        return value
    return Decimal(str(value))


def _uuid_from_db(value: Any) -> uuid.UUID:
    if isinstance(value, uuid.UUID):
        return value
    return uuid.UUID(str(value))


def _datetime_to_db(value: datetime) -> str:
    return _ensure_aware(value).isoformat()


def _datetime_from_db(value: Any) -> datetime:
    return _parse_datetime(value)


def _canonical_line_hash(entry: dict[str, Any]) -> str:
    """Deterministic hash of a raw statement line (key-sorted)."""
    parts = []
    for key in sorted(entry.keys()):
        parts.append(f"{key}={entry[key]!r}")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def _detect_paramstyle(connection: Any) -> str:
    """
    Detect the DB-API paramstyle for the given connection.

    sqlite3 uses qmark ('?'); psycopg / psycopg2 use pyformat/format ('%s').
    """
    module_name = type(connection).__module__ or ""
    if module_name.startswith("sqlite3") or module_name == "_sqlite3":
        return "qmark"
    if module_name.startswith("psycopg"):
        return "format"
    import sys

    root = module_name.split(".")[0]
    module = sys.modules.get(root)
    style = getattr(module, "paramstyle", None)
    if style in ("qmark", "format", "pyformat", "numeric", "named"):
        return style  # type: ignore[return-value]
    return "qmark"


class _Sql:
    """Rewrites '?' placeholders to the connection's paramstyle."""

    def __init__(self, connection: Any) -> None:
        self._style = _detect_paramstyle(connection)

    def q(self, sql: str) -> str:
        if self._style == "qmark":
            return sql
        if self._style in ("format", "pyformat"):
            return sql.replace("?", "%s")
        if self._style == "numeric":
            out: list[str] = []
            idx = 0
            for ch in sql:
                if ch == "?":
                    idx += 1
                    out.append(f":{idx}")
                else:
                    out.append(ch)
            return "".join(out)
        return sql


# ---------------------------------------------------------------------------
# Service
# ---------------------------------------------------------------------------

ConnectionFactory = Callable[[], Any]


class FinancialReconciliationService:
    """
    Independent three-way reconciliation:

        internal transaction execution  <->  external statement evidence
                                        <->  append-only ledger

    The service never lets external evidence mutate truth directly. A
    transaction becomes SETTLED only through the transaction engine's
    validated transition, and only after an exact, unambiguous match.
    """

    def __init__(
        self,
        connection_factory: ConnectionFactory,
        transaction_engine: DurableTransactionEngine,
    ) -> None:
        self._connection_factory = connection_factory
        self._transaction_engine = transaction_engine

    # ------------------------------------------------------------------
    # Connection / transaction management
    # ------------------------------------------------------------------

    @contextmanager
    def _transaction(self) -> Iterator[tuple[Any, _Sql]]:
        """Single DB transaction: commit on success, rollback on any error."""
        connection = self._connection_factory()
        sql = _Sql(connection)
        try:
            yield connection, sql
            connection.commit()
        except BaseException:
            try:
                connection.rollback()
            except Exception:  # pragma: no cover - defensive
                logger.exception("Rollback failed during reconciliation")
            raise
        finally:
            try:
                connection.close()
            except Exception:  # pragma: no cover - defensive
                logger.exception("Connection close failed")

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def ensure_schema(self) -> None:
        with self._transaction() as (connection, _sql):
            cursor = connection.cursor()
            try:
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS settlement_statements (
                        statement_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        provider_id TEXT NOT NULL,
                        account_id TEXT NOT NULL,
                        source_filename TEXT NOT NULL,
                        source_hash TEXT NOT NULL,
                        received_at TEXT NOT NULL,
                        line_count INTEGER NOT NULL,
                        UNIQUE (tenant_id, provider_id, source_hash)
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS settlement_statement_entries (
                        entry_id TEXT PRIMARY KEY,
                        statement_id TEXT NOT NULL,
                        tenant_id TEXT NOT NULL,
                        provider_id TEXT NOT NULL,
                        provider_reference TEXT,
                        transaction_reference TEXT,
                        amount TEXT NOT NULL,
                        currency TEXT NOT NULL,
                        direction TEXT NOT NULL,
                        settled_at TEXT NOT NULL,
                        raw_line_hash TEXT NOT NULL
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_sse_tenant_txref
                    ON settlement_statement_entries (tenant_id, transaction_reference)
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_sse_tenant_provref
                    ON settlement_statement_entries (tenant_id, provider_reference)
                    """
                )
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS reconciliation_cases (
                        reconciliation_id TEXT PRIMARY KEY,
                        tenant_id TEXT NOT NULL,
                        transaction_id TEXT,
                        statement_entry_id TEXT,
                        state TEXT NOT NULL,
                        discrepancy_reason TEXT,
                        evaluated_at TEXT NOT NULL
                    )
                    """
                )
                cursor.execute(
                    """
                    CREATE INDEX IF NOT EXISTS idx_rc_tenant_tx
                    ON reconciliation_cases (tenant_id, transaction_id)
                    """
                )
            finally:
                cursor.close()

    # ------------------------------------------------------------------
    # Ingestion gateway
    # ------------------------------------------------------------------

    def ingest_statement(
        self,
        tenant_id: uuid.UUID,
        provider_id: str,
        account_id: str,
        source_filename: str,
        raw_content: bytes,
        entries: list[dict],
        now: datetime,
    ) -> SettlementStatement:
        """
        Ingest an external settlement statement as EVIDENCE.

        Idempotent on (tenant_id, provider_id, source_hash): re-ingesting the
        same raw content returns the existing statement without inserting
        duplicate entries.
        """
        if not isinstance(raw_content, (bytes, bytearray)):
            raise StatementIngestionError("raw_content must be bytes")
        if not provider_id or not provider_id.strip():
            raise StatementIngestionError("provider_id is required")
        if not account_id or not account_id.strip():
            raise StatementIngestionError("account_id is required")

        source_hash = hashlib.sha256(bytes(raw_content)).hexdigest()
        received_at = _ensure_aware(now)

        # Validate and normalise all entries BEFORE touching the database so
        # a malformed statement is rejected atomically.
        statement_id = uuid.uuid4()
        parsed_entries: list[SettlementStatementEntry] = []
        for index, raw_entry in enumerate(entries):
            parsed_entries.append(
                self._parse_entry(
                    raw_entry=raw_entry,
                    index=index,
                    statement_id=statement_id,
                    tenant_id=tenant_id,
                    provider_id=provider_id,
                )
            )

        with self._transaction() as (connection, sql):
            existing = self._load_statement_by_hash(
                connection, sql, tenant_id, provider_id, source_hash
            )
            if existing is not None:
                return existing

            statement = SettlementStatement(
                statement_id=statement_id,
                tenant_id=tenant_id,
                provider_id=provider_id,
                account_id=account_id,
                source_filename=source_filename,
                source_hash=source_hash,
                received_at=received_at,
                line_count=len(parsed_entries),
            )

            cursor = connection.cursor()
            try:
                cursor.execute(
                    sql.q(
                        """
                        INSERT INTO settlement_statements (
                            statement_id, tenant_id, provider_id, account_id,
                            source_filename, source_hash, received_at, line_count
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """
                    ),
                    (
                        str(statement.statement_id),
                        str(statement.tenant_id),
                        statement.provider_id,
                        statement.account_id,
                        statement.source_filename,
                        statement.source_hash,
                        _datetime_to_db(statement.received_at),
                        statement.line_count,
                    ),
                )
                for entry in parsed_entries:
                    cursor.execute(
                        sql.q(
                            """
                            INSERT INTO settlement_statement_entries (
                                entry_id, statement_id, tenant_id, provider_id,
                                provider_reference, transaction_reference,
                                amount, currency, direction, settled_at,
                                raw_line_hash
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """
                        ),
                        (
                            str(entry.entry_id),
                            str(entry.statement_id),
                            str(entry.tenant_id),
                            entry.provider_id,
                            entry.provider_reference,
                            entry.transaction_reference,
                            _decimal_to_db(entry.amount),
                            entry.currency,
                            entry.direction.value,
                            _datetime_to_db(entry.settled_at),
                            entry.raw_line_hash,
                        ),
                    )
            finally:
                cursor.close()

            return statement

    def _parse_entry(
        self,
        raw_entry: dict,
        index: int,
        statement_id: uuid.UUID,
        tenant_id: uuid.UUID,
        provider_id: str,
    ) -> SettlementStatementEntry:
        if not isinstance(raw_entry, dict):
            raise StatementIngestionError(f"Entry {index} is not a mapping")

        try:
            direction = StatementEntryDirection(
                str(raw_entry.get("direction", "")).strip().upper()
            )
        except ValueError as exc:
            raise StatementIngestionError(
                f"Entry {index} has invalid direction: "
                f"{raw_entry.get('direction')!r}"
            ) from exc

        if "amount" not in raw_entry:
            raise StatementIngestionError(f"Entry {index} missing amount")
        if "settled_at" not in raw_entry:
            raise StatementIngestionError(f"Entry {index} missing settled_at")

        currency = _optional_str(raw_entry.get("currency"))
        if currency is None:
            raise StatementIngestionError(f"Entry {index} missing currency")

        entry_id_value = raw_entry.get("entry_id")
        entry_id = (
            _parse_uuid(entry_id_value, "entry_id")
            if entry_id_value is not None
            else uuid.uuid4()
        )

        raw_line_hash = _optional_str(raw_entry.get("raw_line_hash"))
        if raw_line_hash is None:
            raw_line_hash = _canonical_line_hash(raw_entry)

        return SettlementStatementEntry(
            entry_id=entry_id,
            statement_id=statement_id,
            tenant_id=tenant_id,
            provider_id=provider_id,
            provider_reference=_optional_str(raw_entry.get("provider_reference")),
            transaction_reference=_optional_str(
                raw_entry.get("transaction_reference")
            ),
            amount=_parse_decimal(raw_entry["amount"]),
            currency=currency.upper(),
            direction=direction,
            settled_at=_parse_datetime(raw_entry["settled_at"]),
            raw_line_hash=raw_line_hash,
        )

    def _load_statement_by_hash(
        self,
        connection: Any,
        sql: _Sql,
        tenant_id: uuid.UUID,
        provider_id: str,
        source_hash: str,
    ) -> SettlementStatement | None:
        cursor = connection.cursor()
        try:
            cursor.execute(
                sql.q(
                    """
                    SELECT statement_id, tenant_id, provider_id, account_id,
                           source_filename, source_hash, received_at, line_count
                    FROM settlement_statements
                    WHERE tenant_id = ? AND provider_id = ? AND source_hash = ?
                    """
                ),
                (str(tenant_id), provider_id, source_hash),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        return SettlementStatement(
            statement_id=_uuid_from_db(row[0]),
            tenant_id=_uuid_from_db(row[1]),
            provider_id=row[2],
            account_id=row[3],
            source_filename=row[4],
            source_hash=row[5],
            received_at=_datetime_from_db(row[6]),
            line_count=int(row[7]),
        )

    # ------------------------------------------------------------------
    # Reconciliation
    # ------------------------------------------------------------------

    def reconcile_transaction(
        self,
        tenant_id: uuid.UUID,
        transaction_id: uuid.UUID,
        clearing_deadline: datetime,
        now: datetime,
    ) -> ReconciliationCase:
        """
        Three-way reconcile one transaction inside a single DB transaction.

        Fail-closed: any ambiguity yields a non-MATCHED state; the
        transaction is only advanced to SETTLED on an exact, unambiguous
        match, and only via the transaction engine's validated transition.
        """
        now_utc = _ensure_aware(now)
        deadline_utc = _ensure_aware(clearing_deadline)

        with self._transaction() as (connection, sql):
            # a) Load internal transaction execution --------------------
            execution = self._load_execution(
                connection, sql, tenant_id, transaction_id
            )
            if execution is None:
                return self._persist_case(
                    connection,
                    sql,
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    statement_entry_id=None,
                    state=ReconciliationState.MISSING_INTERNAL,
                    reason="No internal transaction execution found for "
                    "tenant and transaction id",
                    now=now_utc,
                )

            # b) Query statement evidence --------------------------------
            candidates = self._find_statement_entries(
                connection, sql, tenant_id, transaction_id, execution
            )

            # c) No evidence ---------------------------------------------
            if not candidates:
                if now_utc <= deadline_utc:
                    return self._persist_case(
                        connection,
                        sql,
                        tenant_id=tenant_id,
                        transaction_id=transaction_id,
                        statement_entry_id=None,
                        state=ReconciliationState.PENDING_CLEARING,
                        reason="No statement evidence yet; within clearing "
                        "deadline",
                        now=now_utc,
                    )
                # Invariant: absence of evidence is NOT failure. Do not
                # transition the transaction; surface MISSING_EXTERNAL.
                return self._persist_case(
                    connection,
                    sql,
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    statement_entry_id=None,
                    state=ReconciliationState.MISSING_EXTERNAL,
                    reason="No statement evidence after clearing deadline; "
                    "transaction state left unchanged (fail-closed)",
                    now=now_utc,
                )

            # d) Evidence found: evaluate --------------------------------
            return self._evaluate_evidence(
                connection,
                sql,
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                execution=execution,
                candidates=candidates,
                now=now_utc,
            )

    # ------------------------------------------------------------------
    # Evidence evaluation
    # ------------------------------------------------------------------

    def _evaluate_evidence(
        self,
        connection: Any,
        sql: _Sql,
        *,
        tenant_id: uuid.UUID,
        transaction_id: uuid.UUID,
        execution: dict[str, Any],
        candidates: list[SettlementStatementEntry],
        now: datetime,
    ) -> ReconciliationCase:
        # Collapse true duplicates of the SAME physical line (identical
        # provider_reference + amount + currency + direction + settled_at)
        # that arrived via different statement files; these are duplicate
        # external evidence and must never be double counted.
        distinct = self._distinct_evidence(candidates)

        if len(distinct) > 1:
            # Several distinct pieces of evidence for one transaction.
            fingerprints = {
                (e.amount, e.currency, e.direction) for e in distinct
            }
            if len(fingerprints) > 1:
                return self._persist_case(
                    connection,
                    sql,
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    statement_entry_id=distinct[0].entry_id,
                    state=ReconciliationState.CONFLICTING_EVIDENCE,
                    reason=(
                        f"{len(distinct)} statement entries disagree on "
                        "amount/currency/direction for this transaction"
                    ),
                    now=now,
                )
            return self._persist_case(
                connection,
                sql,
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                statement_entry_id=distinct[0].entry_id,
                state=ReconciliationState.DUPLICATE_EXTERNAL,
                reason=(
                    f"{len(distinct)} distinct statement entries reference "
                    "this transaction; possible double settlement"
                ),
                now=now,
            )

        entry = distinct[0]
        if len(candidates) > 1:
            # Same line seen more than once (e.g. overlapping statement
            # files). Evidence is duplicated, so do not auto-settle.
            return self._persist_case(
                connection,
                sql,
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                statement_entry_id=entry.entry_id,
                state=ReconciliationState.DUPLICATE_EXTERNAL,
                reason=(
                    f"Statement evidence appears {len(candidates)} times "
                    "across ingested statements"
                ),
                now=now,
            )

        # Direction sanity: a settlement of an outbound execution must be a
        # DEBIT against our account; anything else is a discrepancy.
        # (Direction is evidence, never authority; fail closed.)
        if entry.direction != StatementEntryDirection.DEBIT and not self._direction_is_acceptable(
            execution, entry
        ):
            return self._persist_case(
                connection,
                sql,
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                statement_entry_id=entry.entry_id,
                state=ReconciliationState.DISCREPANCY,
                reason=(
                    f"Statement direction {entry.direction.value} is not "
                    "consistent with the internal execution"
                ),
                now=now,
            )

        # Reference consistency: if the statement carries a transaction
        # reference it must equal this transaction; a provider-reference-only
        # match must correspond to the execution's recorded provider
        # reference when one exists.
        reference_problem = self._reference_problem(
            transaction_id, execution, entry
        )
        if reference_problem is not None:
            return self._persist_case(
                connection,
                sql,
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                statement_entry_id=entry.entry_id,
                state=ReconciliationState.REFERENCE_MISMATCH,
                reason=reference_problem,
                now=now,
            )

        # Amount check
        execution_amount: Decimal = execution["amount"]
        if execution_amount != entry.amount:
            return self._persist_case(
                connection,
                sql,
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                statement_entry_id=entry.entry_id,
                state=ReconciliationState.AMOUNT_MISMATCH,
                reason=(
                    f"Internal amount {execution_amount} != statement "
                    f"amount {entry.amount}"
                ),
                now=now,
            )

        # Currency check
        execution_currency = str(execution["currency"]).strip().upper()
        if execution_currency != entry.currency.strip().upper():
            return self._persist_case(
                connection,
                sql,
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                statement_entry_id=entry.entry_id,
                state=ReconciliationState.CURRENCY_MISMATCH,
                reason=(
                    f"Internal currency {execution_currency} != statement "
                    f"currency {entry.currency}"
                ),
                now=now,
            )

        # Exact match ---------------------------------------------------
        return self._converge_exact_match(
            connection,
            sql,
            tenant_id=tenant_id,
            transaction_id=transaction_id,
            execution=execution,
            entry=entry,
            now=now,
        )

    def _converge_exact_match(
        self,
        connection: Any,
        sql: _Sql,
        *,
        tenant_id: uuid.UUID,
        transaction_id: uuid.UUID,
        execution: dict[str, Any],
        entry: SettlementStatementEntry,
        now: datetime,
    ) -> ReconciliationCase:
        state_value = str(execution["state"])

        if state_value in _TRANSITIONABLE_TO_SETTLED:
            # The ONLY mutation path for transaction state: the engine's
            # validated transition. If the engine rejects it, fail closed
            # to DISCREPANCY and let the error roll back nothing further.
            try:
                self._transaction_engine.transition_state(
                    transaction_id,
                    tenant_id,
                    TransactionExecutionState.SETTLED,
                )
            except Exception as exc:
                logger.warning(
                    "Transaction engine rejected SETTLED transition for %s: %s",
                    transaction_id,
                    exc,
                )
                return self._persist_case(
                    connection,
                    sql,
                    tenant_id=tenant_id,
                    transaction_id=transaction_id,
                    statement_entry_id=entry.entry_id,
                    state=ReconciliationState.DISCREPANCY,
                    reason=(
                        "Exact statement match but transaction engine "
                        f"refused transition to SETTLED: {exc}"
                    ),
                    now=now,
                )
        elif state_value != _SETTLED:
            # Evidence matches, but the transaction is in a state from which
            # statement evidence may not settle it (CREATED, AUTHORIZED,
            # APPROVED, RESERVED, FAILED, ...). Evidence is not authority.
            return self._persist_case(
                connection,
                sql,
                tenant_id=tenant_id,
                transaction_id=transaction_id,
                statement_entry_id=entry.entry_id,
                state=ReconciliationState.DISCREPANCY,
                reason=(
                    f"Statement matches but internal state is {state_value}; "
                    "external evidence cannot settle from this state"
                ),
                now=now,
            )

        # Idempotent ledger append (never duplicated on repeated runs).
        self._append_settlement_confirmed(
            connection, sql, tenant_id, transaction_id, execution, now
        )

        return self._persist_case(
            connection,
            sql,
            tenant_id=tenant_id,
            transaction_id=transaction_id,
            statement_entry_id=entry.entry_id,
            state=ReconciliationState.MATCHED_SETTLED,
            reason=None,
            now=now,
        )

    # ------------------------------------------------------------------
    # Evidence helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _distinct_evidence(
        candidates: Sequence[SettlementStatementEntry],
    ) -> list[SettlementStatementEntry]:
        """Collapse byte-identical lines (same raw_line_hash) to one."""
        seen: dict[str, SettlementStatementEntry] = {}
        for candidate in candidates:
            seen.setdefault(candidate.raw_line_hash, candidate)
        return list(seen.values())

    @staticmethod
    def _direction_is_acceptable(
        execution: dict[str, Any], entry: SettlementStatementEntry
    ) -> bool:
        """
        The execution schema carries no direction, so a CREDIT line cannot be
        proven consistent. Fail closed: only DEBIT is accepted automatically.
        """
        return False

    @staticmethod
    def _reference_problem(
        transaction_id: uuid.UUID,
        execution: dict[str, Any],
        entry: SettlementStatementEntry,
    ) -> str | None:
        if entry.transaction_reference is not None:
            if entry.transaction_reference != str(transaction_id):
                return (
                    f"Statement transaction_reference "
                    f"{entry.transaction_reference!r} does not equal "
                    f"{str(transaction_id)!r}"
                )
            return None

        # Matched via provider reference only.
        internal_provider_ref = execution.get("provider_reference")
        if internal_provider_ref is None:
            return (
                "Statement matched only by provider_reference but the "
                "internal execution has no provider_reference to verify"
            )
        if entry.provider_reference != str(internal_provider_ref):
            return (
                f"Statement provider_reference {entry.provider_reference!r} "
                f"does not equal internal {str(internal_provider_ref)!r}"
            )
        return None

    # ------------------------------------------------------------------
    # DB access: internal execution
    # ------------------------------------------------------------------

    def _load_execution(
        self,
        connection: Any,
        sql: _Sql,
        tenant_id: uuid.UUID,
        transaction_id: uuid.UUID,
    ) -> dict[str, Any] | None:
        """
        Load the internal transaction execution (tenant-scoped).

        Reads transaction_executions directly (read-only); all mutation goes
        through DurableTransactionEngine.
        """
        cursor = connection.cursor()
        try:
            cursor.execute(
                sql.q(
                    """
                    SELECT transaction_execution_id, tenant_id, state,
                           amount, currency, provider_reference
                    FROM transaction_executions
                    WHERE tenant_id = ? AND transaction_execution_id = ?
                    """
                ),
                (str(tenant_id), str(transaction_id)),
            )
            row = cursor.fetchone()
        except Exception as exc:
            # Fail closed: a missing/unreadable executions table must not be
            # interpreted as a settled or failed transaction. Re-raise so the
            # whole DB transaction rolls back.
            logger.error("Failed to load transaction execution: %s", exc)
            raise
        finally:
            cursor.close()

        if row is None:
            return None

        return {
            "transaction_execution_id": _uuid_from_db(row[0]),
            "tenant_id": _uuid_from_db(row[1]),
            "state": str(row[2]),
            "amount": _decimal_from_db(row[3]),
            "currency": str(row[4]),
            "provider_reference": row[5],
        }

    # ------------------------------------------------------------------
    # DB access: statement evidence
    # ------------------------------------------------------------------

    def _find_statement_entries(
        self,
        connection: Any,
        sql: _Sql,
        tenant_id: uuid.UUID,
        transaction_id: uuid.UUID,
        execution: dict[str, Any],
    ) -> list[SettlementStatementEntry]:
        provider_reference = execution.get("provider_reference")
        params: list[Any] = [str(tenant_id), str(transaction_id)]
        where = "transaction_reference = ?"
        if provider_reference:
            where += " OR provider_reference = ?"
            params.append(str(provider_reference))

        cursor = connection.cursor()
        try:
            cursor.execute(
                sql.q(
                    f"""
                    SELECT entry_id, statement_id, tenant_id, provider_id,
                           provider_reference, transaction_reference, amount,
                           currency, direction, settled_at, raw_line_hash
                    FROM settlement_statement_entries
                    WHERE tenant_id = ? AND ({where})
                    ORDER BY settled_at ASC, entry_id ASC
                    """
                ),
                tuple(params),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()

        result: list[SettlementStatementEntry] = []
        for row in rows:
            result.append(
                SettlementStatementEntry(
                    entry_id=_uuid_from_db(row[0]),
                    statement_id=_uuid_from_db(row[1]),
                    tenant_id=_uuid_from_db(row[2]),
                    provider_id=row[3],
                    provider_reference=row[4],
                    transaction_reference=row[5],
                    amount=_decimal_from_db(row[6]),
                    currency=str(row[7]),
                    direction=StatementEntryDirection(row[8]),
                    settled_at=_datetime_from_db(row[9]),
                    raw_line_hash=row[10],
                )
            )
        return result

    # ------------------------------------------------------------------
    # DB access: ledger (append-only, idempotent)
    # ------------------------------------------------------------------

    def _append_settlement_confirmed(
        self,
        connection: Any,
        sql: _Sql,
        tenant_id: uuid.UUID,
        transaction_id: uuid.UUID,
        execution: dict[str, Any],
        now: datetime,
    ) -> bool:
        """
        Append SETTLEMENT_CONFIRMED exactly once per transaction execution.

        Returns True if a new entry was appended, False if one already
        existed. Append-only: existing rows are never updated or deleted.
        """
        cursor = connection.cursor()
        try:
            cursor.execute(
                sql.q(
                    """
                    SELECT COUNT(*) FROM transaction_ledger_entries
                    WHERE tenant_id = ?
                      AND transaction_execution_id = ?
                      AND entry_type = ?
                    """
                ),
                (str(tenant_id), str(transaction_id), SETTLEMENT_CONFIRMED),
            )
            row = cursor.fetchone()
            if row is not None and int(row[0]) > 0:
                return False

            cursor.execute(
                sql.q(
                    """
                    INSERT INTO transaction_ledger_entries (
                        entry_id, tenant_id, transaction_execution_id,
                        entry_type, amount, currency, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """
                ),
                (
                    str(uuid.uuid4()),
                    str(tenant_id),
                    str(transaction_id),
                    SETTLEMENT_CONFIRMED,
                    _decimal_to_db(execution["amount"]),
                    str(execution["currency"]).strip().upper(),
                    _datetime_to_db(now),
                ),
            )
            return True
        finally:
            cursor.close()

    # ------------------------------------------------------------------
    # DB access: reconciliation cases
    # ------------------------------------------------------------------

    def _persist_case(
        self,
        connection: Any,
        sql: _Sql,
        *,
        tenant_id: uuid.UUID,
        transaction_id: uuid.UUID | None,
        statement_entry_id: uuid.UUID | None,
        state: ReconciliationState,
        reason: str | None,
        now: datetime,
    ) -> ReconciliationCase:
        case = ReconciliationCase(
            reconciliation_id=uuid.uuid4(),
            tenant_id=tenant_id,
            transaction_id=transaction_id,
            statement_entry_id=statement_entry_id,
            state=state,
            discrepancy_reason=reason,
            evaluated_at=now,
        )
        cursor = connection.cursor()
        try:
            cursor.execute(
                sql.q(
                    """
                    INSERT INTO reconciliation_cases (
                        reconciliation_id, tenant_id, transaction_id,
                        statement_entry_id, state, discrepancy_reason,
                        evaluated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """
                ),
                (
                    str(case.reconciliation_id),
                    str(case.tenant_id),
                    str(case.transaction_id)
                    if case.transaction_id is not None
                    else None,
                    str(case.statement_entry_id)
                    if case.statement_entry_id is not None
                    else None,
                    case.state.value,
                    case.discrepancy_reason,
                    _datetime_to_db(case.evaluated_at),
                ),
            )
        finally:
            cursor.close()
        return case