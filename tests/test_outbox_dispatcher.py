"""Tests for ``app/outbox_dispatcher.py`` (Milestone M7).

Every test runs against a real SQLite database created under pytest's
``tmp_path`` with tables built dynamically by ``ensure_schema()``, so no
external services are needed. A file-backed database is used instead of
``:memory:`` because the dispatcher opens one connection per DB operation, and
the concurrency tests need several connections to see the same data. Every
connection opened here is closed explicitly, so the suite is clean under
``python -W error -m pytest``.

Scenarios covered:

1. Atomic claim (status, fresh ``claim_token``, lease expiry, attempt count).
2. Single-claim concurrency (exactly one winner across racing workers).
3. Lease fencing (stale, mismatched or recovered claims cannot overwrite state).
4. Stable provider idempotency key across dispatches and re-claims.
5. Deterministic transitions (SUBMITTED / FAILED / UNKNOWN, fail-closed exception
   mapping, no automatic retry), against both a recording engine and the real
   M6 ``DurableTransactionEngine``.
6. Lease recovery watchdog (``CLAIMED`` -> ``RECONCILIATION_REQUIRED``, never
   ``PENDING``).
"""

from __future__ import annotations

import dataclasses
import logging
import sqlite3
import threading
from contextlib import closing
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import pytest

from app.outbox_dispatcher import (
    OUTBOX_STATUS_CLAIMED,
    OUTBOX_STATUS_DISPATCHED,
    OUTBOX_STATUS_PENDING,
    OUTBOX_STATUS_RECONCILIATION_REQUIRED,
    OUTBOX_STATUSES,
    OutboxConflictError,
    OutboxDispatcher,
    OutboxEntry,
    OutboxEntryNotFoundError,
    PaymentInstruction,
    RailDispatchResult,
    RailDispatchStatus,
    StaleWorkerError,
    TransactionStateSyncError,
)
from app.transaction_engine import (
    DurableTransactionEngine,
    InvalidStateTransitionError,
    TransactionExecutionState,
    TransactionNotFoundError,
)

S = TransactionExecutionState
NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
TENANT = "tenant-a"


# ---------------------------------------------------------------------------
# Test doubles and helpers
# ---------------------------------------------------------------------------


class FakeClock:
    """Mutable, timezone-aware clock."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: Any) -> None:
        self.now = self.now + timedelta(**kwargs)


def submitted(**overrides: Any) -> RailDispatchResult:
    fields: Dict[str, Any] = dict(
        status=RailDispatchStatus.SUBMITTED,
        provider_reference="prov-ref-1",
        provider="mockrail",
        raw_provider_status="ACCEPTED",
    )
    fields.update(overrides)
    return RailDispatchResult(**fields)


def failed(**overrides: Any) -> RailDispatchResult:
    fields: Dict[str, Any] = dict(
        status=RailDispatchStatus.FAILED,
        failure_code="INSUFFICIENT_FUNDS",
        provider="mockrail",
        raw_provider_status="REJECTED",
    )
    fields.update(overrides)
    return RailDispatchResult(**fields)


def unknown(**overrides: Any) -> RailDispatchResult:
    fields: Dict[str, Any] = dict(
        status=RailDispatchStatus.UNKNOWN,
        provider="mockrail",
        raw_provider_status="PENDING_REVIEW",
    )
    fields.update(overrides)
    return RailDispatchResult(**fields)


class ScriptedAdapter:
    """Adapter returning scripted outcomes; exceptions in the script are raised."""

    def __init__(self, *outcomes: Any) -> None:
        self.outcomes: List[Any] = list(outcomes)
        self.calls: List[Tuple[PaymentInstruction, str]] = []

    def submit_payment(
        self, instruction: PaymentInstruction, *, idempotency_key: str
    ) -> RailDispatchResult:
        self.calls.append((instruction, idempotency_key))
        outcome = self.outcomes.pop(0) if self.outcomes else submitted()
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class LockProbeAdapter:
    """Adapter proving the dispatcher holds no DB lock and has committed the claim."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.observed_statuses: Optional[List[str]] = None
        self.write_lock_acquirable: Optional[bool] = None

    def submit_payment(
        self, instruction: PaymentInstruction, *, idempotency_key: str
    ) -> RailDispatchResult:
        conn = sqlite3.connect(self.db_path, timeout=0.2)
        try:
            cur = conn.cursor()
            cur.execute("SELECT status FROM outbox_entries")
            self.observed_statuses = [row[0] for row in cur.fetchall()]
            cur.execute("BEGIN IMMEDIATE")  # raises OperationalError if a lock is held
            self.write_lock_acquirable = True
            conn.rollback()
            cur.close()
        finally:
            conn.close()
        return submitted()


class RecordingEngine:
    """Minimal stand-in for the M6 engine that records ``transition_state`` calls."""

    def __init__(self, fail: Optional[BaseException] = None) -> None:
        self.calls: List[Tuple[str, str, Any, Dict[str, Any]]] = []
        self.fail = fail

    def transition_state(
        self, transaction_execution_id: str, tenant_id: str, target_state: Any, **kwargs: Any
    ) -> None:
        self.calls.append((transaction_execution_id, tenant_id, target_state, kwargs))
        if self.fail is not None:
            raise self.fail


def fetch_row(db_path: str, entry_id: UUID) -> Dict[str, Any]:
    with closing(sqlite3.connect(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.execute("SELECT * FROM outbox_entries WHERE id = ?", (str(entry_id),))
        try:
            row = cur.fetchone()
        finally:
            cur.close()
    assert row is not None
    return dict(row)


def fetch_all(db_path: str, sql: str, params: Tuple[Any, ...] = ()) -> List[Tuple[Any, ...]]:
    with closing(sqlite3.connect(db_path)) as conn:
        cur = conn.cursor()
        try:
            cur.execute(sql, params)
            return cur.fetchall()
        finally:
            cur.close()


def execute_write(db_path: str, sql: str, params: Tuple[Any, ...] = ()) -> None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        try:
            cur.execute(sql, params)
        finally:
            cur.close()
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def count_rows(db_path: str, table: str = "outbox_entries", where: str = "") -> int:
    return int(fetch_all(db_path, f"SELECT COUNT(*) FROM {table} {where}")[0][0])


def requeue(db_path: str, entry_id: UUID) -> None:
    """Simulate an operator-driven requeue after reconciliation (the only way back to PENDING)."""
    execute_write(
        db_path,
        "UPDATE outbox_entries SET status = 'PENDING', claimed_by = NULL, claim_token = NULL, "
        "lease_until = NULL WHERE id = ?",
        (str(entry_id),),
    )


def enqueue(
    dispatcher: OutboxDispatcher,
    *,
    tenant_id: str = TENANT,
    transaction_id: Optional[UUID] = None,
    idempotency_key: Optional[str] = None,
    amount: Any = "250.00",
    currency: str = "usd",
    destination_id: str = "dest-1",
    available_at: Optional[datetime] = None,
    payload: Optional[Any] = None,
) -> OutboxEntry:
    tx = transaction_id if transaction_id is not None else uuid4()
    key = idempotency_key if idempotency_key is not None else f"idem-{uuid4().hex}"
    body = (
        payload
        if payload is not None
        else {
            "amount": amount,
            "currency": currency,
            "destination_id": destination_id,
            "action_id": "action-1",
        }
    )
    return dispatcher.enqueue_entry(tx, tenant_id, body, key, available_at=available_at)


def claim(dispatcher: OutboxDispatcher, worker_id: str = "worker-1", lease_seconds: int = 30) -> OutboxEntry:
    entry = dispatcher.claim_next_entry(worker_id, lease_seconds)
    assert entry is not None
    assert entry.claim_token is not None
    return entry


def seed_execution(
    db_path: str, transaction_id: UUID, tenant_id: str = TENANT, state: str = "RESERVED", version: int = 4
) -> None:
    """Insert an M6 execution row keyed by the outbox ``transaction_id``."""
    iso = NOW.isoformat()
    execute_write(
        db_path,
        "INSERT INTO transaction_executions (transaction_execution_id, tenant_id, "
        "payment_intent_id, action_id, idempotency_key, request_fingerprint, state, version, "
        "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            str(transaction_id),
            tenant_id,
            f"pi_{transaction_id}",
            f"action_{transaction_id}",
            f"idem_{transaction_id}",
            "fp",
            state,
            version,
            iso,
            iso,
        ),
    )


def make_entry(**overrides: Any) -> OutboxEntry:
    fields: Dict[str, Any] = dict(
        id=uuid4(),
        transaction_id=uuid4(),
        status=OUTBOX_STATUS_CLAIMED,
        payload={"amount": "10", "currency": "USD", "destination_id": "d"},
        idempotency_key="idem-manual",
        available_at=NOW,
        claimed_by="worker-1",
        claim_token=uuid4(),
        lease_until=NOW + timedelta(seconds=30),
        attempt_count=1,
        created_at=NOW,
        updated_at=NOW,
        tenant_id=TENANT,
    )
    fields.update(overrides)
    return OutboxEntry(**fields)


def run_concurrently(tasks: List[Callable[[], Any]]) -> List[Any]:
    """Run ``tasks`` in threads released together by a barrier; fail on any thread error."""
    barrier = threading.Barrier(len(tasks))
    results: List[Any] = [None] * len(tasks)
    errors: List[BaseException] = []

    def runner(index: int, task: Callable[[], Any]) -> None:
        try:
            barrier.wait(timeout=30)
            results[index] = task()
        except BaseException as exc:  # noqa: BLE001 - surfaced via assertion below
            errors.append(exc)

    threads = [
        threading.Thread(target=runner, args=(i, task), daemon=True) for i, task in enumerate(tasks)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert not any(thread.is_alive() for thread in threads), "worker thread did not finish"
    assert errors == []
    return results


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Any) -> str:
    return str(tmp_path / "outbox.db")


@pytest.fixture
def connect(db_path: str) -> Callable[[], sqlite3.Connection]:
    def _connect() -> sqlite3.Connection:
        return sqlite3.connect(db_path, timeout=30)

    return _connect


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(NOW)


@pytest.fixture
def adapter() -> ScriptedAdapter:
    return ScriptedAdapter()


@pytest.fixture
def dispatcher(
    connect: Callable[[], sqlite3.Connection], adapter: ScriptedAdapter, clock: FakeClock
) -> OutboxDispatcher:
    instance = OutboxDispatcher(connect, adapter, dialect="sqlite", clock=clock)
    instance.ensure_schema()
    return instance


@pytest.fixture
def tx_engine(connect: Callable[[], sqlite3.Connection], dispatcher: OutboxDispatcher) -> DurableTransactionEngine:
    engine = DurableTransactionEngine(connect, dialect="sqlite", clock=lambda: NOW)
    engine.ensure_schema()
    return engine


# ---------------------------------------------------------------------------
# Types and construction
# ---------------------------------------------------------------------------


def test_rail_dispatch_status_is_a_str_enum() -> None:
    assert {s.value for s in RailDispatchStatus} == {"SUBMITTED", "FAILED", "UNKNOWN"}
    assert RailDispatchStatus.SUBMITTED == "SUBMITTED"
    assert str(RailDispatchStatus.UNKNOWN) == "UNKNOWN"
    assert isinstance(RailDispatchStatus.FAILED, str)


def test_outbox_status_constants() -> None:
    assert OUTBOX_STATUSES == ("PENDING", "CLAIMED", "DISPATCHED", "RECONCILIATION_REQUIRED")
    assert OUTBOX_STATUS_PENDING == "PENDING"
    assert OUTBOX_STATUS_CLAIMED == "CLAIMED"
    assert OUTBOX_STATUS_DISPATCHED == "DISPATCHED"
    assert OUTBOX_STATUS_RECONCILIATION_REQUIRED == "RECONCILIATION_REQUIRED"


def test_value_objects_are_frozen_with_expected_defaults() -> None:
    instruction = PaymentInstruction(
        transaction_id="t", amount=Decimal("1"), currency="USD", destination_id="d"
    )
    result = RailDispatchResult(status=RailDispatchStatus.SUBMITTED)
    assert result.provider_reference is None
    assert result.failure_code is None
    assert result.provider == ""
    assert result.raw_provider_status is None
    with pytest.raises(FrozenInstanceError):
        instruction.amount = Decimal("2")  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        result.status = RailDispatchStatus.FAILED  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        make_entry().status = "PENDING"  # type: ignore[misc]


def test_constructor_rejects_bad_arguments(
    connect: Callable[[], sqlite3.Connection], adapter: ScriptedAdapter
) -> None:
    with pytest.raises(TypeError):
        OutboxDispatcher("not-callable", adapter)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        OutboxDispatcher(connect, object())  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        OutboxDispatcher(connect, None)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        OutboxDispatcher(connect, adapter, dialect="mysql")
    with pytest.raises(ValueError):
        OutboxDispatcher(connect, adapter, table_name="outbox; DROP TABLE x")


def test_ensure_schema_is_idempotent(dispatcher: OutboxDispatcher, db_path: str) -> None:
    dispatcher.ensure_schema()
    dispatcher.ensure_schema()
    names = {row[0] for row in fetch_all(db_path, "SELECT name FROM sqlite_master")}
    assert "outbox_entries" in names
    assert "idx_outbox_entries_claim" in names
    assert "idx_outbox_entries_lease" in names


# ---------------------------------------------------------------------------
# Enqueue
# ---------------------------------------------------------------------------


def test_enqueue_persists_a_pending_entry(dispatcher: OutboxDispatcher, db_path: str) -> None:
    tx = uuid4()
    entry = enqueue(dispatcher, transaction_id=tx, idempotency_key="idem-1")
    assert entry.status == OUTBOX_STATUS_PENDING
    assert entry.transaction_id == tx
    assert entry.idempotency_key == "idem-1"
    assert entry.attempt_count == 0
    assert entry.claimed_by is None
    assert entry.claim_token is None
    assert entry.lease_until is None
    assert entry.available_at == NOW
    assert entry.created_at == NOW
    row = fetch_row(db_path, entry.id)
    assert row["status"] == "PENDING"
    assert row["attempt_count"] == 0
    assert row["claim_token"] is None
    assert dispatcher.get_entry(entry.id) == entry
    assert dispatcher.get_entry(str(entry.id)) == entry  # type: ignore[arg-type]


def test_enqueue_is_idempotent_for_identical_requests(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    tx = uuid4()
    first = dispatcher.enqueue_entry(
        tx, TENANT, {"amount": "5", "currency": "USD", "destination_id": "d"}, "idem-x"
    )
    second = dispatcher.enqueue_entry(
        tx,
        TENANT,
        '{"destination_id":"d","currency":"USD","amount":"5"}',  # different key order, JSON text
        "idem-x",
    )
    assert second.id == first.id
    assert count_rows(db_path) == 1


def test_enqueue_conflicts_are_rejected(dispatcher: OutboxDispatcher, db_path: str) -> None:
    tx = uuid4()
    base = {"amount": "5", "currency": "USD", "destination_id": "d"}
    dispatcher.enqueue_entry(tx, TENANT, base, "idem-x")
    with pytest.raises(OutboxConflictError):
        dispatcher.enqueue_entry(tx, TENANT, {**base, "amount": "6"}, "idem-x")
    with pytest.raises(OutboxConflictError):
        dispatcher.enqueue_entry(uuid4(), TENANT, base, "idem-x")  # same key, new transaction
    with pytest.raises(OutboxConflictError):
        dispatcher.enqueue_entry(tx, TENANT, base, "idem-y")  # same transaction, new key
    assert count_rows(db_path) == 1


def test_enqueue_same_key_in_another_tenant_is_independent(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    tx = uuid4()
    a = enqueue(dispatcher, tenant_id="tenant-a", transaction_id=tx, idempotency_key="idem-x")
    b = enqueue(dispatcher, tenant_id="tenant-b", transaction_id=tx, idempotency_key="idem-x")
    assert a.id != b.id
    assert count_rows(db_path) == 2


def test_enqueue_validates_input(dispatcher: OutboxDispatcher, db_path: str) -> None:
    good = {"amount": "1", "currency": "USD", "destination_id": "d"}
    with pytest.raises(ValueError):
        dispatcher.enqueue_entry("not-a-uuid", TENANT, good, "k")
    with pytest.raises(ValueError):
        dispatcher.enqueue_entry(uuid4(), " ", good, "k")
    with pytest.raises(ValueError):
        dispatcher.enqueue_entry(uuid4(), TENANT, good, " ")
    with pytest.raises(ValueError):
        dispatcher.enqueue_entry(uuid4(), TENANT, "{not json", "k")
    with pytest.raises(ValueError):
        dispatcher.enqueue_entry(uuid4(), TENANT, "[1, 2]", "k")
    with pytest.raises(ValueError):
        dispatcher.enqueue_entry(uuid4(), TENANT, 42, "k")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        dispatcher.enqueue_entry(uuid4(), TENANT, good, "k", available_at=datetime(2030, 1, 1))
    assert count_rows(db_path) == 0


def test_concurrent_identical_enqueues_converge_on_one_entry(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    tx = uuid4()
    payload = {"amount": "9", "currency": "USD", "destination_id": "d"}
    tasks = [lambda: dispatcher.enqueue_entry(tx, TENANT, payload, "idem-race") for _ in range(6)]
    results = run_concurrently(tasks)
    assert len({entry.id for entry in results}) == 1
    assert count_rows(db_path) == 1


def test_get_entry_not_found(dispatcher: OutboxDispatcher) -> None:
    with pytest.raises(OutboxEntryNotFoundError):
        dispatcher.get_entry(uuid4())
    with pytest.raises(ValueError):
        dispatcher.get_entry("nope")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 1. Atomic claim
# ---------------------------------------------------------------------------


def test_claim_returns_claimed_entry_with_fresh_token_and_lease(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    pending = enqueue(dispatcher)
    claimed = dispatcher.claim_next_entry("worker-1", 30)

    assert claimed is not None
    assert claimed.id == pending.id
    assert claimed.status == OUTBOX_STATUS_CLAIMED
    assert claimed.claimed_by == "worker-1"
    assert isinstance(claimed.claim_token, UUID)
    assert claimed.claim_token.version == 4
    assert claimed.lease_until == NOW + timedelta(seconds=30)
    assert claimed.attempt_count == 1
    assert claimed.updated_at == NOW
    assert claimed.idempotency_key == pending.idempotency_key

    row = fetch_row(db_path, claimed.id)
    assert row["status"] == "CLAIMED"
    assert row["claimed_by"] == "worker-1"
    assert row["claim_token"] == str(claimed.claim_token)
    assert row["attempt_count"] == 1
    assert dispatcher.get_entry(claimed.id) == claimed


def test_claim_uses_default_and_custom_lease_seconds(dispatcher: OutboxDispatcher) -> None:
    enqueue(dispatcher)
    enqueue(dispatcher)
    default_lease = dispatcher.claim_next_entry("worker-1")
    custom_lease = dispatcher.claim_next_entry("worker-1", lease_seconds=90)
    assert default_lease is not None and custom_lease is not None
    assert default_lease.lease_until == NOW + timedelta(seconds=30)
    assert custom_lease.lease_until == NOW + timedelta(seconds=90)


def test_each_claim_gets_a_distinct_fresh_token(dispatcher: OutboxDispatcher) -> None:
    enqueue(dispatcher)
    enqueue(dispatcher)
    first = claim(dispatcher, "worker-1")
    second = claim(dispatcher, "worker-1")
    assert first.id != second.id
    assert first.claim_token != second.claim_token


def test_claim_returns_none_when_nothing_is_due(dispatcher: OutboxDispatcher, clock: FakeClock) -> None:
    assert dispatcher.claim_next_entry("worker-1") is None
    future = enqueue(dispatcher, available_at=NOW + timedelta(hours=1))
    assert dispatcher.claim_next_entry("worker-1") is None
    clock.advance(hours=1)
    claimed = dispatcher.claim_next_entry("worker-1")
    assert claimed is not None
    assert claimed.id == future.id


def test_claim_picks_oldest_available_entry_first(dispatcher: OutboxDispatcher) -> None:
    late = enqueue(dispatcher, available_at=NOW - timedelta(minutes=1))
    early = enqueue(dispatcher, available_at=NOW - timedelta(minutes=10))
    mid = enqueue(dispatcher, available_at=NOW - timedelta(minutes=5))
    order = [claim(dispatcher).id for _ in range(3)]
    assert order == [early.id, mid.id, late.id]


def test_claimed_entry_cannot_be_claimed_again(dispatcher: OutboxDispatcher) -> None:
    enqueue(dispatcher)
    claim(dispatcher, "worker-1")
    assert dispatcher.claim_next_entry("worker-2") is None


@pytest.mark.parametrize(
    "status", ["DISPATCHED", "RECONCILIATION_REQUIRED", "CLAIMED"]
)
def test_only_pending_entries_are_claimable(
    dispatcher: OutboxDispatcher, db_path: str, status: str
) -> None:
    entry = enqueue(dispatcher)
    execute_write(db_path, "UPDATE outbox_entries SET status = ? WHERE id = ?", (status, str(entry.id)))
    assert dispatcher.claim_next_entry("worker-1") is None
    assert fetch_row(db_path, entry.id)["attempt_count"] == 0


@pytest.mark.parametrize("bad_lease", [0, -1, True, "30", 1.5])
def test_claim_rejects_invalid_lease_seconds(dispatcher: OutboxDispatcher, bad_lease: Any) -> None:
    enqueue(dispatcher)
    with pytest.raises(ValueError):
        dispatcher.claim_next_entry("worker-1", bad_lease)


def test_claim_rejects_blank_worker_id(dispatcher: OutboxDispatcher, db_path: str) -> None:
    entry = enqueue(dispatcher)
    with pytest.raises(ValueError):
        dispatcher.claim_next_entry(" ")
    assert fetch_row(db_path, entry.id)["status"] == "PENDING"


def test_reclaim_after_requeue_increments_attempt_count(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    entry = enqueue(dispatcher)
    first = claim(dispatcher, "worker-1")
    requeue(db_path, entry.id)
    second = claim(dispatcher, "worker-2")
    assert (first.attempt_count, second.attempt_count) == (1, 2)
    assert first.claim_token != second.claim_token
    assert second.claimed_by == "worker-2"


# ---------------------------------------------------------------------------
# 2. Single-claim concurrency
# ---------------------------------------------------------------------------


def test_exactly_one_worker_wins_a_single_pending_row(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    entry = enqueue(dispatcher)
    workers = [f"worker-{i}" for i in range(8)]
    tasks = [lambda w=w: dispatcher.claim_next_entry(w, 30) for w in workers]
    results = run_concurrently(tasks)

    winners = [(w, r) for w, r in zip(workers, results) if r is not None]
    assert len(winners) == 1
    winner_id, winning_entry = winners[0]
    assert winning_entry.id == entry.id
    assert winning_entry.claimed_by == winner_id
    assert sum(1 for r in results if r is None) == len(workers) - 1

    row = fetch_row(db_path, entry.id)
    assert row["status"] == "CLAIMED"
    assert row["claimed_by"] == winner_id
    assert row["claim_token"] == str(winning_entry.claim_token)
    assert row["attempt_count"] == 1


def test_racing_workers_drain_many_rows_without_double_claims(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    entries = [enqueue(dispatcher) for _ in range(6)]

    def drain(worker_id: str) -> List[OutboxEntry]:
        claimed: List[OutboxEntry] = []
        while True:
            entry = dispatcher.claim_next_entry(worker_id, 30)
            if entry is None:
                return claimed
            claimed.append(entry)

    results = run_concurrently([lambda w=f"worker-{i}": drain(w) for i in range(4)])
    claimed_ids = [entry.id for batch in results for entry in batch]
    assert len(claimed_ids) == len(set(claimed_ids)) == 6
    assert set(claimed_ids) == {e.id for e in entries}
    tokens = [entry.claim_token for batch in results for entry in batch]
    assert len(set(tokens)) == 6
    for entry in entries:
        row = fetch_row(db_path, entry.id)
        assert row["status"] == "CLAIMED"
        assert row["attempt_count"] == 1


def test_sequential_second_claim_of_the_same_row_loses(dispatcher: OutboxDispatcher) -> None:
    enqueue(dispatcher)
    first = dispatcher.claim_next_entry("worker-1")
    second = dispatcher.claim_next_entry("worker-2")
    assert first is not None
    assert second is None


# ---------------------------------------------------------------------------
# 3. Lease fencing
# ---------------------------------------------------------------------------


def test_mismatched_claim_token_cannot_persist(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    engine = RecordingEngine()
    persisted = dispatcher.persist_dispatch_result(
        claimed, "worker-1", uuid4(), submitted(), engine
    )
    assert persisted is False
    row = fetch_row(db_path, claimed.id)
    assert row["status"] == "CLAIMED"
    assert row["provider_reference"] is None
    assert row["dispatched_at"] is None
    assert engine.calls == []


def test_mismatched_worker_id_cannot_persist(dispatcher: OutboxDispatcher, db_path: str) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    engine = RecordingEngine()
    assert (
        dispatcher.persist_dispatch_result(claimed, "worker-2", claimed.claim_token, submitted(), engine)  # type: ignore[arg-type]
        is False
    )
    row = fetch_row(db_path, claimed.id)
    assert row["status"] == "CLAIMED"
    assert row["claimed_by"] == "worker-1"
    assert engine.calls == []


def test_raise_on_stale_raises_and_changes_nothing(
    connect: Callable[[], sqlite3.Connection],
    adapter: ScriptedAdapter,
    clock: FakeClock,
    dispatcher: OutboxDispatcher,
    db_path: str,
) -> None:
    strict = OutboxDispatcher(connect, adapter, clock=clock, raise_on_stale=True)
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    engine = RecordingEngine()
    with pytest.raises(StaleWorkerError):
        strict.persist_dispatch_result(claimed, "worker-1", uuid4(), submitted(), engine)
    assert fetch_row(db_path, claimed.id)["status"] == "CLAIMED"
    assert engine.calls == []


def test_worker_whose_lease_was_recovered_cannot_persist(
    dispatcher: OutboxDispatcher, db_path: str, clock: FakeClock
) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    clock.advance(seconds=31)
    assert dispatcher.recover_expired_leases(clock.now) == [claimed.id]

    engine = RecordingEngine()
    persisted = dispatcher.persist_dispatch_result(
        claimed, "worker-1", claimed.claim_token, submitted(), engine  # type: ignore[arg-type]
    )
    assert persisted is False
    row = fetch_row(db_path, claimed.id)
    assert row["status"] == "RECONCILIATION_REQUIRED"
    assert row["provider_reference"] is None
    assert row["dispatched_at"] is None
    assert engine.calls == []


def test_stale_worker_is_fenced_out_by_a_newer_claim(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    entry = enqueue(dispatcher)
    first = claim(dispatcher, "worker-1")
    requeue(db_path, entry.id)
    second = claim(dispatcher, "worker-2")
    engine = RecordingEngine()

    assert (
        dispatcher.persist_dispatch_result(first, "worker-1", first.claim_token, failed(), engine)  # type: ignore[arg-type]
        is False
    )
    row = fetch_row(db_path, entry.id)
    assert row["status"] == "CLAIMED"
    assert row["claimed_by"] == "worker-2"
    assert row["claim_token"] == str(second.claim_token)
    assert row["failure_code"] is None
    assert engine.calls == []

    assert (
        dispatcher.persist_dispatch_result(second, "worker-2", second.claim_token, submitted(), engine)  # type: ignore[arg-type]
        is True
    )
    assert fetch_row(db_path, entry.id)["status"] == "DISPATCHED"
    assert len(engine.calls) == 1


def test_same_worker_id_with_old_token_is_fenced_by_token_alone(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    entry = enqueue(dispatcher)
    first = claim(dispatcher, "worker-1")
    requeue(db_path, entry.id)
    second = claim(dispatcher, "worker-1")
    assert first.claim_token != second.claim_token

    assert (
        dispatcher.persist_dispatch_result(first, "worker-1", first.claim_token, submitted())  # type: ignore[arg-type]
        is False
    )
    assert fetch_row(db_path, entry.id)["status"] == "CLAIMED"
    assert (
        dispatcher.persist_dispatch_result(second, "worker-1", second.claim_token, submitted())  # type: ignore[arg-type]
        is True
    )


def test_a_persisted_result_cannot_be_overwritten(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    token = claimed.claim_token
    assert dispatcher.persist_dispatch_result(claimed, "worker-1", token, submitted()) is True  # type: ignore[arg-type]
    assert dispatcher.persist_dispatch_result(claimed, "worker-1", token, failed()) is False  # type: ignore[arg-type]
    row = fetch_row(db_path, claimed.id)
    assert row["status"] == "DISPATCHED"
    assert row["provider_reference"] == "prov-ref-1"
    assert row["failure_code"] is None


def test_dispatch_refuses_when_the_worker_does_not_hold_the_claim(
    dispatcher: OutboxDispatcher, adapter: ScriptedAdapter
) -> None:
    pending = enqueue(dispatcher)
    with pytest.raises(StaleWorkerError):
        dispatcher.dispatch_entry(pending, "worker-1")  # never claimed

    claimed = claim(dispatcher, "worker-1")
    with pytest.raises(StaleWorkerError):
        dispatcher.dispatch_entry(claimed, "worker-2")  # someone else's claim
    with pytest.raises(StaleWorkerError):
        dispatcher.dispatch_entry(dataclasses.replace(claimed, claim_token=None), "worker-1")
    assert adapter.calls == []


def test_persist_validates_arguments(dispatcher: OutboxDispatcher) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    token = claimed.claim_token
    with pytest.raises(ValueError):
        dispatcher.persist_dispatch_result(claimed, " ", token, submitted())  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        dispatcher.persist_dispatch_result(claimed, "worker-1", "not-a-uuid", submitted())  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        dispatcher.persist_dispatch_result("entry", "worker-1", token, submitted())  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        dispatcher.persist_dispatch_result(claimed, "worker-1", token, "SUBMITTED")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        dispatcher.persist_dispatch_result(
            claimed, "worker-1", token, RailDispatchResult(status="SUBMITTED")  # type: ignore[arg-type]
        )
    assert dispatcher.get_entry(claimed.id).status == "CLAIMED"


# ---------------------------------------------------------------------------
# 4. Stable provider idempotency key
# ---------------------------------------------------------------------------


def test_dispatch_passes_the_immutable_key_and_a_canonical_instruction(
    dispatcher: OutboxDispatcher, adapter: ScriptedAdapter
) -> None:
    tx = uuid4()
    enqueue(dispatcher, transaction_id=tx, idempotency_key="idem-stable-1", currency="usd")
    claimed = claim(dispatcher, "worker-1")
    result = dispatcher.dispatch_entry(claimed, "worker-1")

    assert result.status is RailDispatchStatus.SUBMITTED
    assert len(adapter.calls) == 1
    instruction, key = adapter.calls[0]
    assert key == "idem-stable-1"
    assert instruction == PaymentInstruction(
        transaction_id=str(tx),
        amount=Decimal("250.00"),
        currency="USD",
        destination_id="dest-1",
    )


def test_idempotency_key_is_stable_across_dispatches_and_reclaims(
    dispatcher: OutboxDispatcher, adapter: ScriptedAdapter, db_path: str
) -> None:
    entry = enqueue(dispatcher, idempotency_key="idem-stable-2")
    first = claim(dispatcher, "worker-1")
    dispatcher.dispatch_entry(first, "worker-1")
    dispatcher.dispatch_entry(first, "worker-1")  # in-process redispatch reuses the key
    assert dispatcher.persist_dispatch_result(first, "worker-1", first.claim_token, submitted()) is True  # type: ignore[arg-type]

    requeue(db_path, entry.id)  # reconciliation-approved retry
    second = claim(dispatcher, "worker-2")
    dispatcher.dispatch_entry(second, "worker-2")

    assert [key for _instruction, key in adapter.calls] == ["idem-stable-2"] * 3
    assert first.idempotency_key == second.idempotency_key == "idem-stable-2"
    assert first.claim_token != second.claim_token
    assert "idem-stable-2" not in (str(first.claim_token), str(second.claim_token), str(entry.id))
    assert fetch_row(db_path, entry.id)["idempotency_key"] == "idem-stable-2"


def test_idempotency_key_is_unchanged_by_claim_and_persist(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    pending = enqueue(dispatcher, idempotency_key="idem-stable-3")
    claimed = claim(dispatcher, "worker-1")
    dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, failed())  # type: ignore[arg-type]
    assert pending.idempotency_key == claimed.idempotency_key == "idem-stable-3"
    assert fetch_row(db_path, pending.id)["idempotency_key"] == "idem-stable-3"


def test_distinct_entries_get_distinct_keys(dispatcher: OutboxDispatcher, adapter: ScriptedAdapter) -> None:
    enqueue(dispatcher, idempotency_key="idem-a")
    enqueue(dispatcher, idempotency_key="idem-b")
    for _ in range(2):
        claimed = claim(dispatcher)
        dispatcher.dispatch_entry(claimed, "worker-1")
    assert sorted(key for _i, key in adapter.calls) == ["idem-a", "idem-b"]


# ---------------------------------------------------------------------------
# 5. Deterministic transitions
# ---------------------------------------------------------------------------


def test_dispatch_entry_touches_no_database_state(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    before = fetch_row(db_path, claimed.id)
    dispatcher.dispatch_entry(claimed, "worker-1")
    assert fetch_row(db_path, claimed.id) == before


def test_submitted_result_marks_outbox_dispatched_and_execution_submitted(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    result = dispatcher.dispatch_entry(claimed, "worker-1")
    engine = RecordingEngine()

    assert dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, result, engine) is True  # type: ignore[arg-type]

    row = fetch_row(db_path, claimed.id)
    assert row["status"] == "DISPATCHED"
    assert row["provider_reference"] == "prov-ref-1"
    assert row["provider"] == "mockrail"
    assert row["raw_provider_status"] == "ACCEPTED"
    assert row["failure_code"] is None
    assert datetime.fromisoformat(row["dispatched_at"]) == NOW
    assert engine.calls == [(str(claimed.transaction_id), TENANT, S.SUBMITTED, {"now": NOW})]


def test_failed_result_marks_outbox_dispatched_with_code_and_execution_failed(
    dispatcher: OutboxDispatcher, adapter: ScriptedAdapter, db_path: str
) -> None:
    adapter.outcomes.append(failed())
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    result = dispatcher.dispatch_entry(claimed, "worker-1")
    assert result.status is RailDispatchStatus.FAILED
    engine = RecordingEngine()

    assert dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, result, engine) is True  # type: ignore[arg-type]

    row = fetch_row(db_path, claimed.id)
    assert row["status"] == "DISPATCHED"
    assert row["failure_code"] == "INSUFFICIENT_FUNDS"
    assert row["raw_provider_status"] == "REJECTED"
    assert datetime.fromisoformat(row["dispatched_at"]) == NOW
    assert engine.calls == [
        (
            str(claimed.transaction_id),
            TENANT,
            S.FAILED,
            {"now": NOW, "failure_reason": "INSUFFICIENT_FUNDS"},
        )
    ]


def test_unknown_result_requires_reconciliation_and_marks_execution_unknown(
    dispatcher: OutboxDispatcher, adapter: ScriptedAdapter, db_path: str
) -> None:
    adapter.outcomes.append(unknown())
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    result = dispatcher.dispatch_entry(claimed, "worker-1")
    assert result.status is RailDispatchStatus.UNKNOWN
    engine = RecordingEngine()

    assert dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, result, engine) is True  # type: ignore[arg-type]

    row = fetch_row(db_path, claimed.id)
    assert row["status"] == "RECONCILIATION_REQUIRED"
    assert row["dispatched_at"] is None
    assert row["raw_provider_status"] == "PENDING_REVIEW"
    assert engine.calls == [(str(claimed.transaction_id), TENANT, S.UNKNOWN, {"now": NOW})]


def test_persist_without_engine_only_updates_the_outbox(
    dispatcher: OutboxDispatcher, db_path: str
) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    assert dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, submitted()) is True  # type: ignore[arg-type]
    assert fetch_row(db_path, claimed.id)["status"] == "DISPATCHED"


def test_empty_provider_name_is_stored_as_null(dispatcher: OutboxDispatcher, db_path: str) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    result = RailDispatchResult(status=RailDispatchStatus.SUBMITTED, provider_reference="r")
    dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, result)  # type: ignore[arg-type]
    assert fetch_row(db_path, claimed.id)["provider"] is None


@pytest.mark.parametrize(
    "exc",
    [
        TimeoutError("read timed out"),
        ConnectionResetError("reset by peer"),
        ConnectionAbortedError("aborted"),
        BrokenPipeError("broken pipe"),
        OSError("network unreachable"),
        RuntimeError("unexpected"),
        ValueError("bad response"),
        Exception("generic"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_adapter_exceptions_map_to_unknown_without_automatic_retry(
    dispatcher: OutboxDispatcher,
    adapter: ScriptedAdapter,
    db_path: str,
    clock: FakeClock,
    exc: Exception,
) -> None:
    adapter.outcomes.append(exc)
    entry = enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")

    result = dispatcher.dispatch_entry(claimed, "worker-1")
    assert result.status is RailDispatchStatus.UNKNOWN
    assert result.failure_code == f"ADAPTER_EXCEPTION:{type(exc).__name__}"
    assert result.provider_reference is None
    assert len(adapter.calls) == 1  # dispatch_entry itself never retries

    engine = RecordingEngine()
    assert dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, result, engine) is True  # type: ignore[arg-type]
    row = fetch_row(db_path, entry.id)
    assert row["status"] == "RECONCILIATION_REQUIRED"
    assert row["failure_code"] == f"ADAPTER_EXCEPTION:{type(exc).__name__}"
    assert row["dispatched_at"] is None
    assert engine.calls == [(str(entry.transaction_id), TENANT, S.UNKNOWN, {"now": NOW})]

    # No automatic retry: nothing is claimable and recovery ignores the entry.
    assert dispatcher.run_once("worker-2") is None
    assert dispatcher.claim_next_entry("worker-2") is None
    clock.advance(hours=1)
    assert dispatcher.recover_expired_leases(clock.now) == []
    assert len(adapter.calls) == 1
    assert fetch_row(db_path, entry.id)["status"] == "RECONCILIATION_REQUIRED"


@pytest.mark.parametrize(
    "bad_result",
    [
        None,
        "SUBMITTED",
        {"status": "SUBMITTED"},
        RailDispatchResult(status="SUBMITTED"),  # type: ignore[arg-type]
    ],
    ids=["none", "str", "dict", "plain-str-status"],
)
def test_malformed_adapter_results_fail_closed_to_unknown(
    dispatcher: OutboxDispatcher, adapter: ScriptedAdapter, bad_result: Any
) -> None:
    adapter.outcomes.append(bad_result)
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    result = dispatcher.dispatch_entry(claimed, "worker-1")
    assert result.status is RailDispatchStatus.UNKNOWN
    assert result.failure_code == "MALFORMED_ADAPTER_RESULT"


@pytest.mark.parametrize(
    "payload",
    [
        {"amount": "abc", "currency": "USD", "destination_id": "d"},
        {"amount": "0", "currency": "USD", "destination_id": "d"},
        {"amount": "-5", "currency": "USD", "destination_id": "d"},
        {"amount": "NaN", "currency": "USD", "destination_id": "d"},
        {"amount": 12.5, "currency": "USD", "destination_id": "d"},
        {"currency": "USD", "destination_id": "d"},
        {"amount": "1", "destination_id": "d"},
        {"amount": "1", "currency": "USD"},
    ],
    ids=["non-numeric", "zero", "negative", "nan", "float", "no-amount", "no-currency", "no-destination"],
)
def test_invalid_payloads_fail_closed_without_calling_the_rail(
    dispatcher: OutboxDispatcher, adapter: ScriptedAdapter, payload: Dict[str, Any]
) -> None:
    enqueue(dispatcher, payload=payload)
    claimed = claim(dispatcher, "worker-1")
    result = dispatcher.dispatch_entry(claimed, "worker-1")
    assert result.status is RailDispatchStatus.UNKNOWN
    assert result.failure_code == "INVALID_PAYLOAD"
    assert adapter.calls == []


def test_run_once_executes_the_full_cycle(
    dispatcher: OutboxDispatcher, adapter: ScriptedAdapter, db_path: str
) -> None:
    assert dispatcher.run_once("worker-1") is None
    entry = enqueue(dispatcher, idempotency_key="idem-run")
    engine = RecordingEngine()

    result = dispatcher.run_once("worker-1", lease_seconds=45, transaction_engine=engine)

    assert result is not None and result.status is RailDispatchStatus.SUBMITTED
    assert [key for _i, key in adapter.calls] == ["idem-run"]
    row = fetch_row(db_path, entry.id)
    assert row["status"] == "DISPATCHED"
    assert row["attempt_count"] == 1
    assert [call[2] for call in engine.calls] == [S.SUBMITTED]
    assert dispatcher.run_once("worker-1") is None  # nothing left


def test_no_db_lock_is_held_and_claim_is_committed_during_network_dispatch(
    connect: Callable[[], sqlite3.Connection], clock: FakeClock, db_path: str
) -> None:
    probe = LockProbeAdapter(db_path)
    dispatcher = OutboxDispatcher(connect, probe, clock=clock)
    dispatcher.ensure_schema()
    entry = enqueue(dispatcher)

    result = dispatcher.run_once("worker-1")

    assert result is not None and result.status is RailDispatchStatus.SUBMITTED
    assert probe.write_lock_acquirable is True
    assert probe.observed_statuses == ["CLAIMED"]
    assert fetch_row(db_path, entry.id)["status"] == "DISPATCHED"


# -- integration with the real M6 DurableTransactionEngine -----------------------------


@pytest.mark.parametrize(
    "result,expected_state,expected_outbox",
    [
        (submitted(), S.SUBMITTED, "DISPATCHED"),
        (failed(), S.FAILED, "DISPATCHED"),
        (unknown(), S.UNKNOWN, "RECONCILIATION_REQUIRED"),
    ],
    ids=["submitted", "failed", "unknown"],
)
def test_real_engine_execution_follows_the_dispatch_result(
    dispatcher: OutboxDispatcher,
    tx_engine: DurableTransactionEngine,
    db_path: str,
    result: RailDispatchResult,
    expected_state: TransactionExecutionState,
    expected_outbox: str,
) -> None:
    entry = enqueue(dispatcher)
    seed_execution(db_path, entry.transaction_id)
    claimed = claim(dispatcher, "worker-1")

    assert dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, result, tx_engine) is True  # type: ignore[arg-type]

    assert fetch_row(db_path, entry.id)["status"] == expected_outbox
    execution = tx_engine.get_execution(str(entry.transaction_id), TENANT)
    assert execution.state is expected_state
    assert execution.version == 5
    if expected_state is S.FAILED:
        assert execution.failure_reason == "INSUFFICIENT_FUNDS"


def test_timeout_end_to_end_with_real_engine_lands_in_unknown(
    adapter: ScriptedAdapter,
    dispatcher: OutboxDispatcher,
    tx_engine: DurableTransactionEngine,
    db_path: str,
) -> None:
    adapter.outcomes.append(TimeoutError("provider timed out"))
    entry = enqueue(dispatcher)
    seed_execution(db_path, entry.transaction_id)

    result = dispatcher.run_once("worker-1", transaction_engine=tx_engine)

    assert result is not None and result.status is RailDispatchStatus.UNKNOWN
    assert fetch_row(db_path, entry.id)["status"] == "RECONCILIATION_REQUIRED"
    assert tx_engine.get_execution(str(entry.transaction_id), TENANT).state is S.UNKNOWN
    assert dispatcher.run_once("worker-2", transaction_engine=tx_engine) is None
    assert len(adapter.calls) == 1


@pytest.mark.parametrize(
    "result,expected_outbox",
    [(submitted(), "RECONCILIATION_REQUIRED"), (failed(), "RECONCILIATION_REQUIRED"), (unknown(), "RECONCILIATION_REQUIRED")],
    ids=["submitted", "failed", "unknown"],
)
def test_engine_failure_after_outbox_commit_flags_reconciliation_and_raises(
    dispatcher: OutboxDispatcher,
    db_path: str,
    caplog: pytest.LogCaptureFixture,
    result: RailDispatchResult,
    expected_outbox: str,
) -> None:
    entry = enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    engine = RecordingEngine(fail=RuntimeError("db down"))

    with caplog.at_level(logging.CRITICAL):
        with pytest.raises(TransactionStateSyncError) as excinfo:
            dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, result, engine)  # type: ignore[arg-type]

    assert isinstance(excinfo.value.__cause__, RuntimeError)
    row = fetch_row(db_path, entry.id)
    assert row["status"] == expected_outbox
    if result.status is RailDispatchStatus.SUBMITTED:
        assert row["provider_reference"] == "prov-ref-1"  # provider outcome is preserved
    assert any(record.levelno == logging.CRITICAL for record in caplog.records)


def test_illegal_execution_transition_surfaces_as_sync_error(
    dispatcher: OutboxDispatcher,
    tx_engine: DurableTransactionEngine,
    db_path: str,
) -> None:
    entry = enqueue(dispatcher)
    seed_execution(db_path, entry.transaction_id, state="CREATED", version=1)
    claimed = claim(dispatcher, "worker-1")

    with pytest.raises(TransactionStateSyncError) as excinfo:
        dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, submitted(), tx_engine)  # type: ignore[arg-type]

    assert isinstance(excinfo.value.__cause__, InvalidStateTransitionError)
    assert fetch_row(db_path, entry.id)["status"] == "RECONCILIATION_REQUIRED"
    execution = tx_engine.get_execution(str(entry.transaction_id), TENANT)
    assert execution.state is S.CREATED
    assert execution.version == 1


def test_missing_execution_surfaces_as_sync_error(
    dispatcher: OutboxDispatcher, tx_engine: DurableTransactionEngine, db_path: str
) -> None:
    entry = enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1")
    with pytest.raises(TransactionStateSyncError) as excinfo:
        dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, failed(), tx_engine)  # type: ignore[arg-type]
    assert isinstance(excinfo.value.__cause__, TransactionNotFoundError)
    assert fetch_row(db_path, entry.id)["status"] == "RECONCILIATION_REQUIRED"


# ---------------------------------------------------------------------------
# 6. Lease recovery watchdog
# ---------------------------------------------------------------------------


def test_expired_claim_goes_straight_to_reconciliation_not_pending(
    dispatcher: OutboxDispatcher, adapter: ScriptedAdapter, db_path: str, clock: FakeClock
) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1", lease_seconds=30)
    clock.advance(seconds=31)

    recovered = dispatcher.recover_expired_leases(clock.now)

    assert recovered == [claimed.id]
    row = fetch_row(db_path, claimed.id)
    assert row["status"] == "RECONCILIATION_REQUIRED"
    assert row["status"] != "PENDING"
    assert row["attempt_count"] == 1
    assert row["claimed_by"] == "worker-1"  # retained for forensics
    assert row["claim_token"] == str(claimed.claim_token)
    assert datetime.fromisoformat(row["updated_at"]) == clock.now

    # Never re-dispatched automatically.
    assert dispatcher.claim_next_entry("worker-2") is None
    assert dispatcher.run_once("worker-2") is None
    assert adapter.calls == []


def test_recovery_is_idempotent(dispatcher: OutboxDispatcher, clock: FakeClock) -> None:
    enqueue(dispatcher)
    claim(dispatcher)
    clock.advance(minutes=5)
    assert len(dispatcher.recover_expired_leases(clock.now)) == 1
    assert dispatcher.recover_expired_leases(clock.now) == []


def test_lease_boundary_is_strictly_less_than(dispatcher: OutboxDispatcher, db_path: str) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1", lease_seconds=30)
    lease_end = NOW + timedelta(seconds=30)

    assert dispatcher.recover_expired_leases(lease_end) == []
    assert fetch_row(db_path, claimed.id)["status"] == "CLAIMED"
    assert dispatcher.recover_expired_leases(lease_end + timedelta(microseconds=1)) == [claimed.id]


def test_unexpired_claims_are_left_alone(
    dispatcher: OutboxDispatcher, db_path: str, clock: FakeClock
) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher, "worker-1", lease_seconds=300)
    clock.advance(seconds=60)
    assert dispatcher.recover_expired_leases(clock.now) == []
    assert fetch_row(db_path, claimed.id)["status"] == "CLAIMED"


def test_recovery_only_touches_expired_claimed_rows(
    dispatcher: OutboxDispatcher, db_path: str, clock: FakeClock
) -> None:
    pending = enqueue(dispatcher)
    dispatched_entry = enqueue(dispatcher)
    reconcile_entry = enqueue(dispatcher)
    expired_entry = enqueue(dispatcher)

    # Drive each row into a distinct state through the public API.
    execute_write(
        db_path,
        "UPDATE outbox_entries SET available_at = ? WHERE id = ?",
        ("2999-01-01T00:00:00.000000+00:00", str(pending.id)),
    )
    first = claim(dispatcher, "worker-1", 30)
    dispatcher.persist_dispatch_result(first, "worker-1", first.claim_token, submitted())  # type: ignore[arg-type]
    second = claim(dispatcher, "worker-1", 30)
    dispatcher.persist_dispatch_result(second, "worker-1", second.claim_token, unknown())  # type: ignore[arg-type]
    third = claim(dispatcher, "worker-1", 30)
    assert {first.id, second.id, third.id} == {dispatched_entry.id, reconcile_entry.id, expired_entry.id}

    clock.advance(hours=1)
    assert dispatcher.recover_expired_leases(clock.now) == [third.id]

    assert fetch_row(db_path, pending.id)["status"] == "PENDING"
    assert fetch_row(db_path, first.id)["status"] == "DISPATCHED"
    assert fetch_row(db_path, second.id)["status"] == "RECONCILIATION_REQUIRED"
    assert fetch_row(db_path, third.id)["status"] == "RECONCILIATION_REQUIRED"


def test_recovery_returns_ids_ordered_by_lease_expiry(
    dispatcher: OutboxDispatcher, db_path: str, clock: FakeClock
) -> None:
    for _ in range(3):
        enqueue(dispatcher)
    c1 = claim(dispatcher, "worker-1", 30)  # lease ends NOW+30
    clock.advance(seconds=10)
    c2 = claim(dispatcher, "worker-1", 30)  # lease ends NOW+40
    c3 = claim(dispatcher, "worker-1", 300)  # lease ends NOW+310

    clock.now = NOW + timedelta(seconds=60)
    recovered = dispatcher.recover_expired_leases(clock.now)

    assert recovered == [c1.id, c2.id]
    assert all(isinstance(entry_id, UUID) for entry_id in recovered)
    assert fetch_row(db_path, c3.id)["status"] == "CLAIMED"


def test_recovery_marks_executions_unknown_via_engine(
    dispatcher: OutboxDispatcher, clock: FakeClock
) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher)
    clock.advance(minutes=2)
    engine = RecordingEngine()

    assert dispatcher.recover_expired_leases(clock.now, engine) == [claimed.id]
    assert engine.calls == [(str(claimed.transaction_id), TENANT, S.UNKNOWN, {"now": clock.now})]


def test_recovery_engine_failure_is_logged_not_raised(
    dispatcher: OutboxDispatcher, db_path: str, clock: FakeClock
) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher)
    clock.advance(minutes=2)
    engine = RecordingEngine(fail=RuntimeError("db down"))

    assert dispatcher.recover_expired_leases(clock.now, engine) == [claimed.id]
    assert fetch_row(db_path, claimed.id)["status"] == "RECONCILIATION_REQUIRED"


def test_recovery_with_real_engine_moves_execution_to_unknown(
    dispatcher: OutboxDispatcher,
    tx_engine: DurableTransactionEngine,
    db_path: str,
    clock: FakeClock,
) -> None:
    entry = enqueue(dispatcher)
    seed_execution(db_path, entry.transaction_id)
    claim(dispatcher)
    clock.advance(minutes=2)

    assert dispatcher.recover_expired_leases(clock.now, tx_engine) == [entry.id]
    assert tx_engine.get_execution(str(entry.transaction_id), TENANT).state is S.UNKNOWN


def test_recovery_requires_aware_now(dispatcher: OutboxDispatcher, db_path: str) -> None:
    enqueue(dispatcher)
    claimed = claim(dispatcher)
    with pytest.raises(ValueError):
        dispatcher.recover_expired_leases(datetime(2030, 1, 1, 13, 0, 0))
    assert fetch_row(db_path, claimed.id)["status"] == "CLAIMED"


# ---------------------------------------------------------------------------
# Postgres dialect (SQL shape only; no server required)
# ---------------------------------------------------------------------------


class _FakeCursor:
    def __init__(self, log: List[Tuple[str, Tuple[Any, ...]]]) -> None:
        self._log = log
        self.rowcount = 0

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        self._log.append((sql, tuple(params)))

    def fetchone(self) -> None:
        return None

    def fetchall(self) -> List[Any]:
        return []

    def close(self) -> None:
        return None


class _FakeConnection:
    def __init__(self, log: List[Tuple[str, Tuple[Any, ...]]]) -> None:
        self._log = log
        self.commits = 0
        self.rollbacks = 0
        self.closed = False

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._log)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        self.rollbacks += 1

    def close(self) -> None:
        self.closed = True


def _postgres_dispatcher(
    clock: FakeClock,
) -> Tuple[OutboxDispatcher, List[Tuple[str, Tuple[Any, ...]]], List[_FakeConnection]]:
    log: List[Tuple[str, Tuple[Any, ...]]] = []
    conns: List[_FakeConnection] = []

    def factory() -> _FakeConnection:
        conn = _FakeConnection(log)
        conns.append(conn)
        return conn

    return OutboxDispatcher(factory, ScriptedAdapter(), dialect="postgres", clock=clock), log, conns


def test_postgres_claim_uses_skip_locked_and_format_params(clock: FakeClock) -> None:
    dispatcher, log, conns = _postgres_dispatcher(clock)
    assert dispatcher.claim_next_entry("worker-1") is None
    assert len(log) == 1
    sql, params = log[0]
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "%s" in sql and "?" not in sql
    assert params[0] == "PENDING"
    assert [c.commits for c in conns] == [1]
    assert all(c.closed for c in conns)


def test_postgres_recovery_uses_skip_locked(clock: FakeClock) -> None:
    dispatcher, log, conns = _postgres_dispatcher(clock)
    assert dispatcher.recover_expired_leases(NOW) == []
    sql, params = log[0]
    assert "FOR UPDATE SKIP LOCKED" in sql
    assert "status = %s" in sql and "lease_until < %s" in sql
    assert params[0] == "CLAIMED"
    assert all(c.closed for c in conns)


def test_postgres_persist_applies_the_full_fencing_predicate(clock: FakeClock) -> None:
    dispatcher, log, conns = _postgres_dispatcher(clock)
    entry = make_entry()
    persisted = dispatcher.persist_dispatch_result(
        entry, "worker-1", entry.claim_token, submitted()  # type: ignore[arg-type]
    )
    assert persisted is False  # fake cursor reports rowcount 0 -> fencing violation
    sql, params = log[0]
    for fragment in ("WHERE id = %s", "status = %s", "claim_token = %s", "claimed_by = %s"):
        assert fragment in sql
    assert params[-4:] == (str(entry.id), "CLAIMED", str(entry.claim_token), "worker-1")
    assert all(c.closed for c in conns)


# ---------------------------------------------------------------------------
# Connection hygiene
# ---------------------------------------------------------------------------


def test_every_connection_is_closed_on_success_and_failure(
    db_path: str, clock: FakeClock, adapter: ScriptedAdapter
) -> None:
    opened: List["_Spy"] = []

    class _Spy:
        def __init__(self) -> None:
            self._conn = sqlite3.connect(db_path, timeout=30)
            self.closed = False
            opened.append(self)

        def cursor(self) -> sqlite3.Cursor:
            return self._conn.cursor()

        def commit(self) -> None:
            self._conn.commit()

        def rollback(self) -> None:
            self._conn.rollback()

        def close(self) -> None:
            self.closed = True
            self._conn.close()

    dispatcher = OutboxDispatcher(_Spy, adapter, dialect="sqlite", clock=clock)  # type: ignore[arg-type]
    dispatcher.ensure_schema()
    entry = enqueue(dispatcher, idempotency_key="idem-spy")
    claimed = claim(dispatcher, "worker-1")
    dispatcher.dispatch_entry(claimed, "worker-1")
    assert dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, submitted()) is True  # type: ignore[arg-type]
    assert dispatcher.persist_dispatch_result(claimed, "worker-1", claimed.claim_token, failed()) is False  # type: ignore[arg-type]
    with pytest.raises(OutboxConflictError):
        dispatcher.enqueue_entry(
            entry.transaction_id, TENANT, {"amount": "1", "currency": "USD", "destination_id": "d"}, "idem-spy"
        )
    with pytest.raises(OutboxEntryNotFoundError):
        dispatcher.get_entry(uuid4())
    assert dispatcher.recover_expired_leases(NOW + timedelta(days=1)) == []

    assert opened, "factory was never used"
    assert all(spy.closed for spy in opened)