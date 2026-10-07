"""
tests/test_reconciliation_engine.py

Milestone M9: tests for the Independent Financial Reconciliation Engine.

Backed by an in-memory sqlite3 database. The service closes its connection
after every DB transaction, so the fixture hands it a connection subclass whose
close() is a no-op; the fixture closes the real connection at teardown.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any

import pytest

from app.reconciliation_engine import (
    FinancialReconciliationService,
    ReconciliationCase,
    ReconciliationState,
    SettlementStatement,
)
from app.transaction_engine import TransactionExecutionState


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)
DEADLINE_FUTURE = NOW + timedelta(days=2)
DEADLINE_PAST = NOW - timedelta(days=1)

PROVIDER_ID = "provider-alpha"
ACCOUNT_ID = "acct-001"


# ---------------------------------------------------------------------------
# Test doubles and fixtures
# ---------------------------------------------------------------------------


class SharedMemoryConnection(sqlite3.Connection):
    """sqlite3 connection whose close() is a no-op so the in-memory DB survives
    the service's per-transaction close. Use force_close() at teardown."""

    def close(self) -> None:  # noqa: D102
        return None

    def force_close(self) -> None:
        sqlite3.Connection.close(self)


class FakeTransactionEngine:
    """Duck-typed stand-in for DurableTransactionEngine.

    Mirrors the interface used by the reconciliation service:
        transition_state(transaction_execution_id, tenant_id, target_state, ...)
    and validates permitted transitions against the same database, inside the
    caller's DB transaction (shared connection).
    """

    _PERMITTED = {
        (TransactionExecutionState.SUBMITTED.value, TransactionExecutionState.SETTLED.value),
        (TransactionExecutionState.UNKNOWN.value, TransactionExecutionState.SETTLED.value),
    }

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection
        self.calls: list[tuple[Any, Any, Any]] = []

    def transition_state(
        self,
        transaction_execution_id: uuid.UUID,
        tenant_id: uuid.UUID,
        target_state: TransactionExecutionState,
        **kwargs: Any,
    ) -> None:
        self.calls.append((transaction_execution_id, tenant_id, target_state))
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT state FROM transaction_executions "
                "WHERE tenant_id = ? AND transaction_execution_id = ?",
                (str(tenant_id), str(transaction_execution_id)),
            )
            row = cursor.fetchone()
            if row is None:
                raise LookupError("transaction execution not found")
            current = str(row[0])
            target = TransactionExecutionState(target_state).value
            if (current, target) not in self._PERMITTED:
                raise ValueError(f"illegal transition {current} -> {target}")
            cursor.execute(
                "UPDATE transaction_executions SET state = ? "
                "WHERE tenant_id = ? AND transaction_execution_id = ?",
                (target, str(tenant_id), str(transaction_execution_id)),
            )
        finally:
            cursor.close()


@dataclass
class Env:
    connection: SharedMemoryConnection
    engine: FakeTransactionEngine
    service: FinancialReconciliationService
    tenant_id: uuid.UUID


@pytest.fixture
def env() -> Env:
    connection = sqlite3.connect(":memory:", factory=SharedMemoryConnection)
    connection.execute(
        """
        CREATE TABLE transaction_executions (
            transaction_execution_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            state TEXT NOT NULL,
            amount TEXT NOT NULL,
            currency TEXT NOT NULL,
            provider_reference TEXT
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE transaction_ledger_entries (
            entry_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            transaction_execution_id TEXT NOT NULL,
            entry_type TEXT NOT NULL,
            amount TEXT NOT NULL,
            currency TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )
    connection.commit()

    engine = FakeTransactionEngine(connection)
    service = FinancialReconciliationService(lambda: connection, engine)  # type: ignore[arg-type]
    service.ensure_schema()

    try:
        yield Env(
            connection=connection,
            engine=engine,
            service=service,
            tenant_id=uuid.uuid4(),
        )
    finally:
        connection.force_close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def insert_execution(
    env: Env,
    state: TransactionExecutionState,
    amount: str = "100.00",
    currency: str = "USD",
    provider_reference: str | None = None,
    transaction_id: uuid.UUID | None = None,
) -> uuid.UUID:
    tx_id = transaction_id or uuid.uuid4()
    env.connection.execute(
        "INSERT INTO transaction_executions "
        "(transaction_execution_id, tenant_id, state, amount, currency, provider_reference) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            str(tx_id),
            str(env.tenant_id),
            state.value,
            amount,
            currency,
            provider_reference,
        ),
    )
    env.connection.commit()
    return tx_id


def make_entry(
    tx_id: uuid.UUID | None,
    amount: str = "100.00",
    currency: str = "USD",
    direction: str = "DEBIT",
    provider_reference: str | None = None,
) -> dict:
    return {
        "transaction_reference": str(tx_id) if tx_id is not None else None,
        "provider_reference": provider_reference,
        "amount": amount,
        "currency": currency,
        "direction": direction,
        "settled_at": "2026-10-06T10:00:00+00:00",
    }


def ingest(
    env: Env,
    entries: list[dict],
    raw_content: bytes = b"statement-file-1",
    filename: str = "stmt.csv",
    now: datetime = NOW,
) -> SettlementStatement:
    return env.service.ingest_statement(
        tenant_id=env.tenant_id,
        provider_id=PROVIDER_ID,
        account_id=ACCOUNT_ID,
        source_filename=filename,
        raw_content=raw_content,
        entries=entries,
        now=now,
    )


def count_rows(env: Env, table: str) -> int:
    row = env.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
    return int(row[0])


def ledger_count(env: Env, entry_type: str | None = None) -> int:
    if entry_type is None:
        return count_rows(env, "transaction_ledger_entries")
    row = env.connection.execute(
        "SELECT COUNT(*) FROM transaction_ledger_entries WHERE entry_type = ?",
        (entry_type,),
    ).fetchone()
    return int(row[0])


def execution_state(env: Env, tx_id: uuid.UUID) -> str:
    row = env.connection.execute(
        "SELECT state FROM transaction_executions "
        "WHERE tenant_id = ? AND transaction_execution_id = ?",
        (str(env.tenant_id), str(tx_id)),
    ).fetchone()
    assert row is not None
    return str(row[0])


def reconcile(
    env: Env,
    tx_id: uuid.UUID,
    deadline: datetime = DEADLINE_FUTURE,
    now: datetime = NOW,
) -> ReconciliationCase:
    return env.service.reconcile_transaction(
        tenant_id=env.tenant_id,
        transaction_id=tx_id,
        clearing_deadline=deadline,
        now=now,
    )


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


class TestSchema:
    def test_ensure_schema_is_idempotent(self, env: Env) -> None:
        env.service.ensure_schema()
        env.service.ensure_schema()

        tables = {
            row[0]
            for row in env.connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert "settlement_statements" in tables
        assert "settlement_statement_entries" in tables
        assert "reconciliation_cases" in tables


# ---------------------------------------------------------------------------
# 1. Statement ingestion idempotency
# ---------------------------------------------------------------------------


class TestStatementIngestionIdempotency:
    def test_identical_bytes_return_existing_statement_with_no_duplicate_lines(
        self, env: Env
    ) -> None:
        tx_id = uuid.uuid4()
        entries = [
            make_entry(tx_id, amount="100.00"),
            make_entry(uuid.uuid4(), amount="55.50"),
        ]
        raw = b"identical-file-bytes"

        first = ingest(env, entries, raw_content=raw, now=NOW)
        assert count_rows(env, "settlement_statements") == 1
        assert count_rows(env, "settlement_statement_entries") == 2

        second = ingest(
            env,
            entries,
            raw_content=raw,
            now=NOW + timedelta(hours=3),
        )

        assert second == first
        assert second.statement_id == first.statement_id
        assert second.received_at == first.received_at
        assert second.line_count == 2
        assert count_rows(env, "settlement_statements") == 1
        assert count_rows(env, "settlement_statement_entries") == 2

    def test_source_hash_is_sha256_of_raw_content(self, env: Env) -> None:
        import hashlib

        raw = b"hash-me"
        statement = ingest(env, [make_entry(uuid.uuid4())], raw_content=raw)
        assert statement.source_hash == hashlib.sha256(raw).hexdigest()

    def test_different_bytes_create_a_new_statement(self, env: Env) -> None:
        tx_id = uuid.uuid4()
        first = ingest(env, [make_entry(tx_id)], raw_content=b"file-a")
        second = ingest(env, [make_entry(tx_id)], raw_content=b"file-b")

        assert first.statement_id != second.statement_id
        assert first.source_hash != second.source_hash
        assert count_rows(env, "settlement_statements") == 2
        assert count_rows(env, "settlement_statement_entries") == 2

    def test_idempotency_is_scoped_to_tenant(self, env: Env) -> None:
        raw = b"shared-bytes"
        entries = [make_entry(uuid.uuid4())]
        first = ingest(env, entries, raw_content=raw)

        other_tenant = uuid.uuid4()
        second = env.service.ingest_statement(
            tenant_id=other_tenant,
            provider_id=PROVIDER_ID,
            account_id=ACCOUNT_ID,
            source_filename="stmt.csv",
            raw_content=raw,
            entries=entries,
            now=NOW,
        )

        assert second.statement_id != first.statement_id
        assert count_rows(env, "settlement_statements") == 2


# ---------------------------------------------------------------------------
# 2. Reconciliation convergence
# ---------------------------------------------------------------------------


class TestReconciliationConvergence:
    def test_submitted_with_matching_statement_converges_to_settled(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)
        ingest(env, [make_entry(tx_id)])

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.MATCHED_SETTLED
        assert case.discrepancy_reason is None
        assert case.tenant_id == env.tenant_id
        assert case.transaction_id == tx_id
        assert case.statement_entry_id is not None
        assert case.evaluated_at == NOW
        assert execution_state(env, tx_id) == TransactionExecutionState.SETTLED.value
        assert env.engine.calls == [
            (tx_id, env.tenant_id, TransactionExecutionState.SETTLED)
        ]
        assert ledger_count(env, "SETTLEMENT_CONFIRMED") == 1

    def test_unknown_with_matching_statement_converges_to_settled(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.UNKNOWN)
        ingest(env, [make_entry(tx_id)])

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.MATCHED_SETTLED
        assert execution_state(env, tx_id) == TransactionExecutionState.SETTLED.value
        assert len(env.engine.calls) == 1
        assert env.engine.calls[0][2] == TransactionExecutionState.SETTLED
        assert ledger_count(env, "SETTLEMENT_CONFIRMED") == 1

    def test_ledger_entry_carries_execution_amount_and_currency(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(
            env, TransactionExecutionState.SUBMITTED, amount="250.75", currency="USD"
        )
        ingest(env, [make_entry(tx_id, amount="250.75")])

        reconcile(env, tx_id)

        row = env.connection.execute(
            "SELECT tenant_id, transaction_execution_id, entry_type, amount, currency "
            "FROM transaction_ledger_entries"
        ).fetchone()
        assert row is not None
        assert row[0] == str(env.tenant_id)
        assert row[1] == str(tx_id)
        assert row[2] == "SETTLEMENT_CONFIRMED"
        assert Decimal(row[3]) == Decimal("250.75")
        assert row[4] == "USD"

    def test_numerically_equal_decimals_with_different_scale_match(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(
            env, TransactionExecutionState.SUBMITTED, amount="100.00"
        )
        ingest(env, [make_entry(tx_id, amount="100.0000")])

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.MATCHED_SETTLED

    def test_match_via_provider_reference_when_transaction_reference_absent(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(
            env,
            TransactionExecutionState.SUBMITTED,
            provider_reference="PROV-REF-1",
        )
        entry = make_entry(None, provider_reference="PROV-REF-1")
        ingest(env, [entry])

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.MATCHED_SETTLED
        assert execution_state(env, tx_id) == TransactionExecutionState.SETTLED.value

    def test_reconciliation_case_is_persisted(self, env: Env) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)
        ingest(env, [make_entry(tx_id)])

        case = reconcile(env, tx_id)

        row = env.connection.execute(
            "SELECT reconciliation_id, state, transaction_id FROM reconciliation_cases"
        ).fetchone()
        assert row is not None
        assert row[0] == str(case.reconciliation_id)
        assert row[1] == "MATCHED_SETTLED"
        assert row[2] == str(tx_id)


# ---------------------------------------------------------------------------
# 3. Mismatch rejections
# ---------------------------------------------------------------------------


class TestMismatchRejections:
    def test_amount_mismatch_produces_amount_mismatch_with_zero_ledger_writes(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(
            env, TransactionExecutionState.SUBMITTED, amount="100.00"
        )
        ingest(env, [make_entry(tx_id, amount="99.00")])

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.AMOUNT_MISMATCH
        assert case.discrepancy_reason is not None
        assert ledger_count(env) == 0
        assert env.engine.calls == []
        assert execution_state(env, tx_id) == TransactionExecutionState.SUBMITTED.value

    def test_currency_mismatch_produces_currency_mismatch_with_zero_ledger_writes(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(
            env, TransactionExecutionState.SUBMITTED, currency="USD"
        )
        ingest(env, [make_entry(tx_id, currency="EUR")])

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.CURRENCY_MISMATCH
        assert case.discrepancy_reason is not None
        assert ledger_count(env) == 0
        assert env.engine.calls == []
        assert execution_state(env, tx_id) == TransactionExecutionState.SUBMITTED.value

    def test_unknown_transaction_amount_mismatch_stays_unknown(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(
            env, TransactionExecutionState.UNKNOWN, amount="100.00"
        )
        ingest(env, [make_entry(tx_id, amount="100.01")])

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.AMOUNT_MISMATCH
        assert ledger_count(env) == 0
        assert execution_state(env, tx_id) == TransactionExecutionState.UNKNOWN.value

    def test_credit_direction_fails_closed_to_discrepancy(self, env: Env) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)
        ingest(env, [make_entry(tx_id, direction="CREDIT")])

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.DISCREPANCY
        assert ledger_count(env) == 0
        assert env.engine.calls == []
        assert execution_state(env, tx_id) == TransactionExecutionState.SUBMITTED.value

    def test_evidence_cannot_settle_from_non_settleable_state(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.CREATED)
        ingest(env, [make_entry(tx_id)])

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.DISCREPANCY
        assert ledger_count(env) == 0
        assert env.engine.calls == []
        assert execution_state(env, tx_id) == TransactionExecutionState.CREATED.value

    def test_statement_reference_for_other_transaction_is_reference_mismatch(
        self, env: Env
    ) -> None:
        # Matched by provider_reference, but the statement names a different
        # transaction: evidence conflicts with the internal record.
        tx_id = insert_execution(
            env,
            TransactionExecutionState.SUBMITTED,
            provider_reference="PROV-REF-9",
        )
        other_tx = uuid.uuid4()
        ingest(
            env,
            [make_entry(other_tx, provider_reference="PROV-REF-9")],
        )

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.REFERENCE_MISMATCH
        assert ledger_count(env) == 0
        assert env.engine.calls == []
        assert execution_state(env, tx_id) == TransactionExecutionState.SUBMITTED.value

    def test_same_line_in_two_statement_files_is_duplicate_external(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)
        entry = make_entry(tx_id)
        ingest(env, [dict(entry)], raw_content=b"overlap-file-1")
        ingest(env, [dict(entry)], raw_content=b"overlap-file-2")

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.DUPLICATE_EXTERNAL
        assert ledger_count(env) == 0
        assert env.engine.calls == []
        assert execution_state(env, tx_id) == TransactionExecutionState.SUBMITTED.value

    def test_disagreeing_entries_are_conflicting_evidence(self, env: Env) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)
        ingest(
            env,
            [make_entry(tx_id, amount="100.00"), make_entry(tx_id, amount="90.00")],
        )

        case = reconcile(env, tx_id)

        assert case.state == ReconciliationState.CONFLICTING_EVIDENCE
        assert ledger_count(env) == 0
        assert env.engine.calls == []
        assert execution_state(env, tx_id) == TransactionExecutionState.SUBMITTED.value


# ---------------------------------------------------------------------------
# 4. Missing evidence handling
# ---------------------------------------------------------------------------


class TestMissingEvidenceHandling:
    def test_missing_statement_within_clearing_window_is_pending_clearing(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)

        case = reconcile(env, tx_id, deadline=DEADLINE_FUTURE, now=NOW)

        assert case.state == ReconciliationState.PENDING_CLEARING
        assert case.statement_entry_id is None
        assert ledger_count(env) == 0
        assert env.engine.calls == []
        assert execution_state(env, tx_id) == TransactionExecutionState.SUBMITTED.value

    def test_missing_statement_exactly_at_deadline_is_still_pending(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)

        case = reconcile(env, tx_id, deadline=NOW, now=NOW)

        assert case.state == ReconciliationState.PENDING_CLEARING

    def test_missing_statement_after_clearing_window_is_missing_external_not_failed(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)

        case = reconcile(env, tx_id, deadline=DEADLINE_PAST, now=NOW)

        assert case.state == ReconciliationState.MISSING_EXTERNAL
        assert case.statement_entry_id is None
        assert case.discrepancy_reason is not None
        # Invariant: absence of evidence is never failure.
        state = execution_state(env, tx_id)
        assert state == TransactionExecutionState.SUBMITTED.value
        assert state != TransactionExecutionState.FAILED.value
        assert ledger_count(env) == 0
        assert env.engine.calls == []

    def test_unknown_transaction_missing_evidence_after_deadline_stays_unknown(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.UNKNOWN)

        case = reconcile(env, tx_id, deadline=DEADLINE_PAST, now=NOW)

        assert case.state == ReconciliationState.MISSING_EXTERNAL
        assert execution_state(env, tx_id) == TransactionExecutionState.UNKNOWN.value
        assert env.engine.calls == []

    def test_statement_entry_with_missing_internal_transaction_is_missing_internal(
        self, env: Env
    ) -> None:
        ghost_tx_id = uuid.uuid4()
        ingest(env, [make_entry(ghost_tx_id)])

        case = reconcile(env, ghost_tx_id)

        assert case.state == ReconciliationState.MISSING_INTERNAL
        assert case.transaction_id == ghost_tx_id
        assert case.statement_entry_id is None
        assert ledger_count(env) == 0
        assert env.engine.calls == []

    def test_other_tenant_transaction_is_not_visible(self, env: Env) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)
        ingest(env, [make_entry(tx_id)])

        other_tenant = uuid.uuid4()
        case = env.service.reconcile_transaction(
            tenant_id=other_tenant,
            transaction_id=tx_id,
            clearing_deadline=DEADLINE_FUTURE,
            now=NOW,
        )

        assert case.state == ReconciliationState.MISSING_INTERNAL
        assert case.tenant_id == other_tenant
        assert ledger_count(env) == 0
        assert execution_state(env, tx_id) == TransactionExecutionState.SUBMITTED.value


# ---------------------------------------------------------------------------
# 5. Ledger settlement idempotency
# ---------------------------------------------------------------------------


class TestLedgerSettlementIdempotency:
    def test_repeated_reconciliation_yields_exactly_one_settlement_confirmed(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)
        ingest(env, [make_entry(tx_id)])

        cases = [
            reconcile(env, tx_id, now=NOW + timedelta(minutes=i)) for i in range(4)
        ]

        assert all(c.state == ReconciliationState.MATCHED_SETTLED for c in cases)
        assert len({c.reconciliation_id for c in cases}) == 4
        assert ledger_count(env, "SETTLEMENT_CONFIRMED") == 1
        assert ledger_count(env) == 1
        assert execution_state(env, tx_id) == TransactionExecutionState.SETTLED.value
        # Only the first run needs to drive the transition.
        assert len(env.engine.calls) == 1

    def test_already_settled_transaction_reconciles_without_new_ledger_entry(
        self, env: Env
    ) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)
        ingest(env, [make_entry(tx_id)])

        first = reconcile(env, tx_id)
        second = reconcile(env, tx_id)
        third = reconcile(env, tx_id)

        assert first.state == ReconciliationState.MATCHED_SETTLED
        assert second.state == ReconciliationState.MATCHED_SETTLED
        assert third.state == ReconciliationState.MATCHED_SETTLED
        assert ledger_count(env, "SETTLEMENT_CONFIRMED") == 1

    def test_ledger_is_append_only_across_reconciliations(self, env: Env) -> None:
        tx_id = insert_execution(env, TransactionExecutionState.SUBMITTED)
        ingest(env, [make_entry(tx_id)])

        reconcile(env, tx_id)
        original = env.connection.execute(
            "SELECT entry_id, created_at FROM transaction_ledger_entries"
        ).fetchall()

        reconcile(env, tx_id, now=NOW + timedelta(hours=1))
        after = env.connection.execute(
            "SELECT entry_id, created_at FROM transaction_ledger_entries"
        ).fetchall()

        assert after == original

    def test_idempotency_holds_per_transaction(self, env: Env) -> None:
        tx_a = insert_execution(env, TransactionExecutionState.SUBMITTED)
        tx_b = insert_execution(env, TransactionExecutionState.UNKNOWN)
        ingest(env, [make_entry(tx_a), make_entry(tx_b)])

        for _ in range(3):
            reconcile(env, tx_a)
            reconcile(env, tx_b)

        assert ledger_count(env, "SETTLEMENT_CONFIRMED") == 2
        counts = dict(
            env.connection.execute(
                "SELECT transaction_execution_id, COUNT(*) "
                "FROM transaction_ledger_entries GROUP BY transaction_execution_id"
            ).fetchall()
        )
        assert counts == {str(tx_a): 1, str(tx_b): 1}