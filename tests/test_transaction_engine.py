"""Tests for ``app/transaction_engine.py`` (Milestone M6).

All tests run against a real SQLite database file created under pytest's
``tmp_path``. Tables are created dynamically by ``engine.ensure_schema()``, so
there are no external services. Every connection opened here is closed
explicitly, so the suite is clean under ``python -W error -m pytest``.

Notes on approval consumption
-----------------------------
``ApprovalStore.consume`` does not receive a DB connection. The engine can
therefore only roll the approval back together with the reservation when the
store is enrolled in the engine's DB transaction. ``EnrolledApprovalStore``
below does exactly that by writing to ``approval_consumptions`` on the
connection the engine is currently using. ``PlainApprovalStore`` is a
non-enrolled in-memory store, used to pin down the documented fail-closed
behaviour: the DB rolls back, the approval stays consumed, and it can never be
consumed twice.
"""

from __future__ import annotations

import gc
import json
import logging
import sqlite3
import warnings
from contextlib import closing
from dataclasses import FrozenInstanceError, dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

import pytest

from app.approval_evidence import (
    ApprovalEvidenceConsumed,
    ApprovalEvidenceExpired,
    ApprovalEvidenceInvalid,
)
from app.transaction_engine import (
    ALLOWED_TRANSITIONS,
    TERMINAL_STATES,
    ConcurrentModificationError,
    DurableTransactionEngine,
    IdempotencyConflictError,
    InvalidStateTransitionError,
    PaymentIntent,
    TransactionExecution,
    TransactionExecutionState,
    TransactionNotFoundError,
    compute_request_fingerprint,
    validate_transition,
)

S = TransactionExecutionState
NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
ALL_STATES = list(TransactionExecutionState)

EXPECTED_TRANSITIONS: Dict[TransactionExecutionState, frozenset] = {
    S.CREATED: frozenset({S.AUTHORIZED, S.FAILED}),
    S.AUTHORIZED: frozenset({S.APPROVED, S.FAILED}),
    S.APPROVED: frozenset({S.RESERVED, S.FAILED}),
    S.RESERVED: frozenset({S.SUBMITTED, S.FAILED, S.UNKNOWN}),
    S.SUBMITTED: frozenset({S.SETTLED, S.FAILED, S.UNKNOWN}),
    S.UNKNOWN: frozenset({S.SETTLED, S.FAILED, S.SUBMITTED}),
    S.SETTLED: frozenset(),
    S.FAILED: frozenset(),
}

# Engine-level paths from CREATED to each state.
PATHS: Dict[TransactionExecutionState, List[TransactionExecutionState]] = {
    S.CREATED: [],
    S.AUTHORIZED: [S.AUTHORIZED],
    S.APPROVED: [S.AUTHORIZED, S.APPROVED],
    S.RESERVED: [S.AUTHORIZED, S.APPROVED, S.RESERVED],
    S.SUBMITTED: [S.AUTHORIZED, S.APPROVED, S.RESERVED, S.SUBMITTED],
    S.SETTLED: [S.AUTHORIZED, S.APPROVED, S.RESERVED, S.SUBMITTED, S.SETTLED],
    S.FAILED: [S.FAILED],
    S.UNKNOWN: [S.AUTHORIZED, S.APPROVED, S.RESERVED, S.UNKNOWN],
}

INTENT_DEFAULTS: Dict[str, Any] = dict(
    tenant_id="tenant-a",
    action_id="action-1",
    session_id="session-1",
    subject_id="subject-1",
    amount="250.00",
    currency="USD",
    destination_id="dest-1",
    idempotency_key="idem-1",
    security_context_id="secctx-1",
    approval_id="appr-1",
)


# ---------------------------------------------------------------------------
# Test doubles and helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FakeApprovalEvidence:
    """Duck-typed stand-in for ``ApprovalEvidence`` (the engine only reads attributes)."""

    approval_id: str
    tenant_id: str
    action_id: str
    session_id: str
    subject_id: str
    destination_id: str
    amount: Any
    currency: str
    expires_at: datetime
    approved_at: datetime
    trusted: bool = True

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def is_trusted(self) -> bool:
        return self.trusted


class ConnectionTracker:
    """Connection factory that remembers the most recently opened connection."""

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.current: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        self.current = conn
        return conn


class EnrolledApprovalStore:
    """Approval store that consumes inside the engine's own DB transaction."""

    def __init__(self, tracker: ConnectionTracker) -> None:
        self._tracker = tracker
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def consume(self, evidence: Any, now: datetime, tenant_id: Any = None, executor_id: Any = None) -> bool:
        self.calls.append((evidence.approval_id, {"tenant_id": tenant_id, "executor_id": executor_id}))
        conn = self._tracker.current
        assert conn is not None
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO approval_consumptions (approval_id, tenant_id, executor_id) "
                "VALUES (?, ?, ?)",
                (evidence.approval_id, tenant_id, executor_id),
            )
        except sqlite3.IntegrityError:
            return False
        finally:
            cur.close()
        return True

    def is_consumed(self, approval_id: str) -> bool:
        return count(
            self._tracker.db_path,
            "approval_consumptions",
            "WHERE approval_id = ?",
            (approval_id,),
        ) == 1


class PlainApprovalStore:
    """Non-enrolled in-memory store (cannot be rolled back with the DB)."""

    def __init__(self) -> None:
        self.consumed: set = set()
        self.calls: List[str] = []

    def consume(self, evidence: Any, now: datetime, tenant_id: Any = None, executor_id: Any = None) -> bool:
        self.calls.append(evidence.approval_id)
        if evidence.approval_id in self.consumed:
            return False
        self.consumed.add(evidence.approval_id)
        return True


class DenyingApprovalStore:
    """Store whose atomic consume always reports the approval as already consumed."""

    def __init__(self) -> None:
        self.calls: List[str] = []

    def consume(self, evidence: Any, now: datetime, tenant_id: Any = None, executor_id: Any = None) -> bool:
        self.calls.append(evidence.approval_id)
        return False


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


def count(db_path: str, table: str, where: str = "", params: Tuple[Any, ...] = ()) -> int:
    rows = fetch_all(db_path, f"SELECT COUNT(*) FROM {table} {where}", params)
    return int(rows[0][0])


def make_intent(engine: DurableTransactionEngine, **overrides: Any) -> PaymentIntent:
    params = dict(INTENT_DEFAULTS)
    params.update(overrides)
    return engine.create_or_get_intent(**params)


def make_evidence(intent: PaymentIntent, **overrides: Any) -> FakeApprovalEvidence:
    fields: Dict[str, Any] = dict(
        approval_id=intent.approval_id,
        tenant_id=intent.tenant_id,
        action_id=intent.action_id,
        session_id=intent.session_id,
        subject_id=intent.subject_id,
        destination_id=intent.destination_id,
        amount=intent.amount,
        currency=intent.currency,
        expires_at=NOW + timedelta(hours=1),
        approved_at=NOW - timedelta(minutes=5),
        trusted=True,
    )
    fields.update(overrides)
    return FakeApprovalEvidence(**fields)


def drive_to(
    engine: DurableTransactionEngine,
    store: Any,
    intent: PaymentIntent,
    state: TransactionExecutionState,
) -> TransactionExecution:
    """Walk an execution from CREATED to ``state`` using only public engine methods."""
    execution = engine.get_execution_for_intent(intent.payment_intent_id, intent.tenant_id)
    for step in PATHS[state]:
        if step is S.RESERVED:
            execution = engine.reserve_execution(
                intent.payment_intent_id,
                intent.tenant_id,
                make_evidence(intent),
                store,
                NOW,
                "executor-1",
            )
        else:
            execution = engine.transition_state(
                execution.transaction_execution_id,
                intent.tenant_id,
                step,
                now=NOW,
                reconciled=False,
            )
    return execution


def execution_for(engine: DurableTransactionEngine, intent: PaymentIntent) -> TransactionExecution:
    return engine.get_execution_for_intent(intent.payment_intent_id, intent.tenant_id)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Any) -> str:
    path = str(tmp_path / "engine.db")
    execute_write(
        path,
        "CREATE TABLE approval_consumptions ("
        "approval_id TEXT PRIMARY KEY, tenant_id TEXT, executor_id TEXT)",
    )
    return path


@pytest.fixture
def tracker(db_path: str) -> ConnectionTracker:
    return ConnectionTracker(db_path)


@pytest.fixture
def engine(tracker: ConnectionTracker) -> DurableTransactionEngine:
    eng = DurableTransactionEngine(tracker.connect, dialect="sqlite", clock=lambda: NOW)
    eng.ensure_schema()
    return eng


@pytest.fixture
def store(tracker: ConnectionTracker) -> EnrolledApprovalStore:
    return EnrolledApprovalStore(tracker)


# ---------------------------------------------------------------------------
# Engine construction / schema
# ---------------------------------------------------------------------------


def test_constructor_rejects_bad_arguments(tracker: ConnectionTracker) -> None:
    with pytest.raises(TypeError):
        DurableTransactionEngine("not-callable")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        DurableTransactionEngine(tracker.connect, dialect="mysql")


def test_ensure_schema_is_idempotent(engine: DurableTransactionEngine, db_path: str) -> None:
    engine.ensure_schema()
    engine.ensure_schema()
    tables = {
        row[0]
        for row in fetch_all(db_path, "SELECT name FROM sqlite_master WHERE type = 'table'")
    }
    assert {
        "payment_intents",
        "transaction_executions",
        "transaction_ledger_entries",
        "provider_outbox",
    } <= tables


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------


def test_fingerprint_is_deterministic_sha256_hex() -> None:
    args = ("tenant-a", "action-1", "pi_1", "250.00", "USD", "dest-1")
    first = compute_request_fingerprint(*args)
    second = compute_request_fingerprint(*args)
    assert first == second
    assert len(first) == 64
    assert all(c in "0123456789abcdef" for c in first)


def test_fingerprint_canonicalizes_amount_and_currency() -> None:
    base = compute_request_fingerprint("t", "a", "pi", "250.00", "USD", "d")
    assert compute_request_fingerprint("t", "a", "pi", "250", "usd", "d") == base
    assert compute_request_fingerprint("t", "a", "pi", Decimal("250.0"), "USD", "d") == base
    assert compute_request_fingerprint("t", "a", "pi", 250, " usd ", "d") == base


@pytest.mark.parametrize(
    "index,replacement",
    [
        (0, "t2"),
        (1, "a2"),
        (2, "pi2"),
        (3, "251.00"),
        (4, "EUR"),
        (5, "d2"),
    ],
)
def test_fingerprint_changes_with_every_field(index: int, replacement: str) -> None:
    args = ["t", "a", "pi", "250.00", "USD", "d"]
    base = compute_request_fingerprint(*args)
    args[index] = replacement
    assert compute_request_fingerprint(*args) != base


def test_fingerprint_has_no_field_boundary_ambiguity() -> None:
    one = compute_request_fingerprint("ab", "c", "pi", "1", "USD", "d")
    two = compute_request_fingerprint("a", "bc", "pi", "1", "USD", "d")
    assert one != two


@pytest.mark.parametrize("bad_amount", [0, -1, "abc", 1.5, True, "NaN", "Infinity"])
def test_fingerprint_rejects_invalid_amounts(bad_amount: Any) -> None:
    with pytest.raises(ValueError):
        compute_request_fingerprint("t", "a", "pi", bad_amount, "USD", "d")


# ---------------------------------------------------------------------------
# State machine definition
# ---------------------------------------------------------------------------


def test_transition_map_matches_specification() -> None:
    assert ALLOWED_TRANSITIONS == EXPECTED_TRANSITIONS
    assert TERMINAL_STATES == frozenset({S.SETTLED, S.FAILED})


@pytest.mark.parametrize("current", ALL_STATES, ids=lambda s: s.value)
@pytest.mark.parametrize("target", ALL_STATES, ids=lambda s: s.value)
def test_validate_transition_full_matrix(
    current: TransactionExecutionState, target: TransactionExecutionState
) -> None:
    allowed = target in EXPECTED_TRANSITIONS[current]
    if not allowed:
        with pytest.raises(InvalidStateTransitionError):
            validate_transition(current, target, reconciled=True)
        with pytest.raises(InvalidStateTransitionError):
            validate_transition(current, target)
    elif current is S.UNKNOWN:
        with pytest.raises(InvalidStateTransitionError):
            validate_transition(current, target)
        validate_transition(current, target, reconciled=True)
    else:
        validate_transition(current, target)


def test_validate_transition_rejects_non_enum_values() -> None:
    with pytest.raises(InvalidStateTransitionError):
        validate_transition("CREATED", "AUTHORIZED")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 1. Valid lifecycle
# ---------------------------------------------------------------------------


def test_full_lifecycle_created_to_settled(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    execution = execution_for(engine, intent)
    assert execution.state is S.CREATED
    assert execution.version == 1
    assert execution.payment_intent_id == intent.payment_intent_id
    assert execution.request_fingerprint == intent.request_fingerprint
    assert execution.idempotency_key == intent.idempotency_key
    assert execution.action_id == intent.action_id

    execution = engine.transition_state(
        execution.transaction_execution_id, "tenant-a", S.AUTHORIZED, now=NOW
    )
    assert (execution.state, execution.version) == (S.AUTHORIZED, 2)
    assert execution.authorized_at == NOW

    execution = engine.transition_state(
        execution.transaction_execution_id, "tenant-a", S.APPROVED, now=NOW
    )
    assert (execution.state, execution.version) == (S.APPROVED, 3)
    assert execution.approved_at == NOW

    execution = engine.reserve_execution(
        intent.payment_intent_id, "tenant-a", make_evidence(intent), store, NOW, "executor-1"
    )
    assert (execution.state, execution.version) == (S.RESERVED, 4)
    assert execution.reserved_at == NOW

    execution = engine.transition_state(
        execution.transaction_execution_id, "tenant-a", S.SUBMITTED, now=NOW
    )
    assert (execution.state, execution.version) == (S.SUBMITTED, 5)
    assert execution.submitted_at == NOW

    execution = engine.transition_state(
        execution.transaction_execution_id, "tenant-a", S.SETTLED, now=NOW
    )
    assert (execution.state, execution.version) == (S.SETTLED, 6)
    assert execution.settled_at == NOW

    persisted = engine.get_execution(execution.transaction_execution_id, "tenant-a")
    assert persisted == execution
    rows = fetch_all(db_path, "SELECT state, version FROM transaction_executions")
    assert rows == [("SETTLED", 6)]


@pytest.mark.parametrize("path_state", [S.CREATED, S.AUTHORIZED, S.APPROVED])
def test_any_pre_terminal_state_can_fail(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, path_state: TransactionExecutionState
) -> None:
    intent = make_intent(engine)
    execution = drive_to(engine, store, intent, path_state)
    failed = engine.transition_state(
        execution.transaction_execution_id,
        "tenant-a",
        S.FAILED,
        now=NOW,
        failure_reason="provider declined",
    )
    assert failed.state is S.FAILED
    assert failed.failed_at == NOW
    assert failed.failure_reason == "provider declined"
    assert failed.version == execution.version + 1


@pytest.mark.parametrize("path_state", [S.RESERVED, S.SUBMITTED])
def test_in_flight_states_can_become_unknown_then_reconcile(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, path_state: TransactionExecutionState
) -> None:
    intent = make_intent(engine)
    execution = drive_to(engine, store, intent, path_state)
    unknown = engine.transition_state(
        execution.transaction_execution_id, "tenant-a", S.UNKNOWN, now=NOW
    )
    assert unknown.state is S.UNKNOWN
    assert unknown.unknown_at == NOW


@pytest.mark.parametrize("target", [S.SETTLED, S.FAILED, S.SUBMITTED], ids=lambda s: s.value)
def test_unknown_resolves_only_after_reconciliation(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, target: TransactionExecutionState
) -> None:
    intent = make_intent(engine)
    execution = drive_to(engine, store, intent, S.UNKNOWN)

    before = engine.get_execution(execution.transaction_execution_id, "tenant-a")
    with pytest.raises(InvalidStateTransitionError):
        engine.transition_state(
            execution.transaction_execution_id, "tenant-a", target, now=NOW
        )
    assert engine.get_execution(execution.transaction_execution_id, "tenant-a") == before

    resolved = engine.transition_state(
        execution.transaction_execution_id, "tenant-a", target, now=NOW, reconciled=True
    )
    assert resolved.state is target
    assert resolved.version == before.version + 1


def test_unknown_reconciled_to_submitted_can_then_settle(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore
) -> None:
    intent = make_intent(engine)
    execution = drive_to(engine, store, intent, S.UNKNOWN)
    engine.transition_state(
        execution.transaction_execution_id, "tenant-a", S.SUBMITTED, now=NOW, reconciled=True
    )
    settled = engine.transition_state(
        execution.transaction_execution_id, "tenant-a", S.SETTLED, now=NOW
    )
    assert settled.state is S.SETTLED


# ---------------------------------------------------------------------------
# 2. Illegal transitions (zero side effects)
# ---------------------------------------------------------------------------


def test_created_to_settled_is_rejected_without_side_effects(
    engine: DurableTransactionEngine,
) -> None:
    intent = make_intent(engine)
    before = execution_for(engine, intent)
    with pytest.raises(InvalidStateTransitionError):
        engine.transition_state(before.transaction_execution_id, "tenant-a", S.SETTLED, now=NOW)
    assert execution_for(engine, intent) == before
    assert before.state is S.CREATED
    assert before.version == 1


def test_reserved_to_authorized_is_rejected_without_side_effects(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    before = drive_to(engine, store, intent, S.RESERVED)
    with pytest.raises(InvalidStateTransitionError):
        engine.transition_state(before.transaction_execution_id, "tenant-a", S.AUTHORIZED, now=NOW)
    assert execution_for(engine, intent) == before
    assert count(db_path, "transaction_ledger_entries") == 1
    assert count(db_path, "provider_outbox") == 1


@pytest.mark.parametrize(
    "start,target",
    [
        (S.CREATED, S.APPROVED),
        (S.CREATED, S.SUBMITTED),
        (S.CREATED, S.UNKNOWN),
        (S.AUTHORIZED, S.SETTLED),
        (S.AUTHORIZED, S.CREATED),
        (S.APPROVED, S.SUBMITTED),
        (S.APPROVED, S.AUTHORIZED),
        (S.SUBMITTED, S.RESERVED),
        (S.SUBMITTED, S.APPROVED),
    ],
    ids=lambda s: s.value,
)
def test_assorted_illegal_transitions_raise(
    engine: DurableTransactionEngine,
    store: EnrolledApprovalStore,
    start: TransactionExecutionState,
    target: TransactionExecutionState,
) -> None:
    intent = make_intent(engine)
    before = drive_to(engine, store, intent, start)
    with pytest.raises(InvalidStateTransitionError):
        engine.transition_state(before.transaction_execution_id, "tenant-a", target, now=NOW)
    assert execution_for(engine, intent) == before


@pytest.mark.parametrize("terminal", [S.SETTLED, S.FAILED], ids=lambda s: s.value)
@pytest.mark.parametrize("target", ALL_STATES, ids=lambda s: s.value)
def test_terminal_states_reject_every_mutation(
    engine: DurableTransactionEngine,
    store: EnrolledApprovalStore,
    terminal: TransactionExecutionState,
    target: TransactionExecutionState,
) -> None:
    intent = make_intent(engine)
    before = drive_to(engine, store, intent, terminal)
    assert before.state is terminal
    with pytest.raises(InvalidStateTransitionError):
        engine.transition_state(
            before.transaction_execution_id, "tenant-a", target, now=NOW, reconciled=True
        )
    assert execution_for(engine, intent) == before


def test_terminal_state_rejects_reservation(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    drive_to(engine, store, intent, S.FAILED)
    with pytest.raises(InvalidStateTransitionError):
        engine.reserve_execution(
            intent.payment_intent_id, "tenant-a", make_evidence(intent), store, NOW, "executor-1"
        )
    assert store.calls == []
    assert count(db_path, "transaction_ledger_entries") == 0
    assert count(db_path, "provider_outbox") == 0


def test_reserved_cannot_be_entered_through_transition_state(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore
) -> None:
    intent = make_intent(engine)
    before = drive_to(engine, store, intent, S.APPROVED)
    with pytest.raises(InvalidStateTransitionError):
        engine.transition_state(before.transaction_execution_id, "tenant-a", S.RESERVED, now=NOW)
    assert execution_for(engine, intent) == before


def test_created_is_never_a_valid_target(engine: DurableTransactionEngine) -> None:
    intent = make_intent(engine)
    before = execution_for(engine, intent)
    with pytest.raises(InvalidStateTransitionError):
        engine.transition_state(before.transaction_execution_id, "tenant-a", S.CREATED, now=NOW)


def test_non_enum_target_is_rejected(engine: DurableTransactionEngine) -> None:
    intent = make_intent(engine)
    before = execution_for(engine, intent)
    with pytest.raises(InvalidStateTransitionError):
        engine.transition_state(
            before.transaction_execution_id, "tenant-a", "AUTHORIZED", now=NOW  # type: ignore[arg-type]
        )


def test_expected_version_mismatch_raises_and_changes_nothing(
    engine: DurableTransactionEngine,
) -> None:
    intent = make_intent(engine)
    before = execution_for(engine, intent)
    with pytest.raises(ConcurrentModificationError):
        engine.transition_state(
            before.transaction_execution_id,
            "tenant-a",
            S.AUTHORIZED,
            now=NOW,
            expected_version=99,
        )
    assert execution_for(engine, intent) == before

    updated = engine.transition_state(
        before.transaction_execution_id,
        "tenant-a",
        S.AUTHORIZED,
        now=NOW,
        expected_version=1,
    )
    assert updated.version == 2


def test_transition_requires_aware_now(engine: DurableTransactionEngine) -> None:
    intent = make_intent(engine)
    before = execution_for(engine, intent)
    with pytest.raises(ValueError):
        engine.transition_state(
            before.transaction_execution_id,
            "tenant-a",
            S.AUTHORIZED,
            now=datetime(2030, 1, 1, 12, 0, 0),
        )
    assert execution_for(engine, intent) == before


def test_transition_is_tenant_scoped(engine: DurableTransactionEngine) -> None:
    intent = make_intent(engine)
    before = execution_for(engine, intent)
    with pytest.raises(TransactionNotFoundError):
        engine.transition_state(before.transaction_execution_id, "tenant-b", S.AUTHORIZED, now=NOW)
    assert execution_for(engine, intent) == before


def test_unknown_execution_is_not_found(engine: DurableTransactionEngine) -> None:
    with pytest.raises(TransactionNotFoundError):
        engine.transition_state("te_missing", "tenant-a", S.AUTHORIZED, now=NOW)
    with pytest.raises(TransactionNotFoundError):
        engine.get_execution("te_missing", "tenant-a")
    with pytest.raises(TransactionNotFoundError):
        engine.get_intent("pi_missing", "tenant-a")
    with pytest.raises(TransactionNotFoundError):
        engine.get_execution_for_intent("pi_missing", "tenant-a")


# ---------------------------------------------------------------------------
# 3. Idempotency
# ---------------------------------------------------------------------------


def test_create_intent_persists_intent_and_created_execution(
    engine: DurableTransactionEngine, db_path: str
) -> None:
    intent = make_intent(engine)
    assert isinstance(intent, PaymentIntent)
    assert intent.amount == Decimal("250")
    assert intent.currency == "USD"
    assert intent.created_at == NOW
    assert intent.approval_id == "appr-1"
    assert intent.request_fingerprint == compute_request_fingerprint(
        "tenant-a", "action-1", intent.payment_intent_id, "250.00", "USD", "dest-1"
    )
    assert engine.get_intent(intent.payment_intent_id, "tenant-a") == intent
    execution = execution_for(engine, intent)
    assert execution.state is S.CREATED
    assert count(db_path, "payment_intents") == 1
    assert count(db_path, "transaction_executions") == 1


def test_identical_parameters_return_existing_intent_and_execution(
    engine: DurableTransactionEngine, db_path: str
) -> None:
    first = make_intent(engine)
    first_execution = execution_for(engine, first)

    second = make_intent(engine)
    assert second == first
    assert second.payment_intent_id == first.payment_intent_id
    assert execution_for(engine, second) == first_execution
    assert count(db_path, "payment_intents") == 1
    assert count(db_path, "transaction_executions") == 1


def test_idempotent_replay_does_not_reset_progressed_execution(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore
) -> None:
    first = make_intent(engine)
    progressed = drive_to(engine, store, first, S.SUBMITTED)
    replay = make_intent(engine)
    assert replay == first
    assert execution_for(engine, replay) == progressed
    assert execution_for(engine, replay).state is S.SUBMITTED


def test_equivalent_amount_and_currency_representations_are_idempotent(
    engine: DurableTransactionEngine, db_path: str
) -> None:
    first = make_intent(engine, amount="250.00", currency="USD")
    for amount, currency in (("250", "usd"), (Decimal("250.0"), "USD"), (250, " Usd ")):
        again = make_intent(engine, amount=amount, currency=currency)
        assert again.payment_intent_id == first.payment_intent_id
    assert count(db_path, "payment_intents") == 1


@pytest.mark.parametrize(
    "override",
    [
        {"amount": "251.00"},
        {"currency": "EUR"},
        {"destination_id": "dest-evil"},
        {"action_id": "action-2"},
    ],
    ids=lambda o: next(iter(o)),
)
def test_modified_parameters_with_same_key_raise_conflict(
    engine: DurableTransactionEngine, db_path: str, override: Dict[str, Any]
) -> None:
    first = make_intent(engine)
    with pytest.raises(IdempotencyConflictError):
        make_intent(engine, **override)
    assert engine.get_intent(first.payment_intent_id, "tenant-a") == first
    assert count(db_path, "payment_intents") == 1
    assert count(db_path, "transaction_executions") == 1


def test_same_action_id_with_new_idempotency_key_conflicts(
    engine: DurableTransactionEngine, db_path: str
) -> None:
    make_intent(engine)
    with pytest.raises(IdempotencyConflictError):
        make_intent(engine, idempotency_key="idem-2")
    assert count(db_path, "payment_intents") == 1
    assert count(db_path, "transaction_executions") == 1


def test_same_key_in_different_tenants_is_independent(
    engine: DurableTransactionEngine, db_path: str
) -> None:
    a = make_intent(engine, tenant_id="tenant-a")
    b = make_intent(engine, tenant_id="tenant-b")
    assert a.payment_intent_id != b.payment_intent_id
    assert a.request_fingerprint != b.request_fingerprint
    assert count(db_path, "payment_intents") == 2
    with pytest.raises(TransactionNotFoundError):
        engine.get_intent(a.payment_intent_id, "tenant-b")


def test_distinct_requests_create_distinct_intents(
    engine: DurableTransactionEngine, db_path: str
) -> None:
    one = make_intent(engine)
    two = make_intent(engine, action_id="action-2", idempotency_key="idem-2")
    assert one.payment_intent_id != two.payment_intent_id
    assert count(db_path, "payment_intents") == 2
    assert count(db_path, "transaction_executions") == 2


@pytest.mark.parametrize("bad_amount", [0, -5, "abc", 12.5, True, "NaN"])
def test_invalid_amounts_are_rejected_before_any_write(
    engine: DurableTransactionEngine, db_path: str, bad_amount: Any
) -> None:
    with pytest.raises(ValueError):
        make_intent(engine, amount=bad_amount)
    assert count(db_path, "payment_intents") == 0
    assert count(db_path, "transaction_executions") == 0


@pytest.mark.parametrize(
    "field",
    [
        "tenant_id",
        "action_id",
        "session_id",
        "subject_id",
        "destination_id",
        "idempotency_key",
        "security_context_id",
        "currency",
    ],
)
def test_blank_required_fields_are_rejected(
    engine: DurableTransactionEngine, db_path: str, field: str
) -> None:
    with pytest.raises(ValueError):
        make_intent(engine, **{field: "  "})
    assert count(db_path, "payment_intents") == 0


def test_database_enforces_unique_constraints_directly(
    engine: DurableTransactionEngine, db_path: str
) -> None:
    intent = make_intent(engine)
    insert = (
        "INSERT INTO payment_intents (payment_intent_id, tenant_id, action_id, session_id, "
        "subject_id, amount, currency, destination_id, idempotency_key, request_fingerprint, "
        "security_context_id, approval_id, created_at) "
        "VALUES (?, ?, ?, 's', 'u', '1', 'USD', 'd', ?, 'fp', 'ctx', NULL, 'now')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        execute_write(db_path, insert, ("pi_x", intent.tenant_id, "other-action", intent.idempotency_key))
    with pytest.raises(sqlite3.IntegrityError):
        execute_write(db_path, insert, ("pi_y", intent.tenant_id, intent.action_id, "other-key"))
    assert count(db_path, "payment_intents") == 1


def test_models_are_immutable(engine: DurableTransactionEngine) -> None:
    intent = make_intent(engine)
    execution = execution_for(engine, intent)
    with pytest.raises(FrozenInstanceError):
        intent.amount = Decimal("1")  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        execution.state = S.SETTLED  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 4. Atomic reservation: success
# ---------------------------------------------------------------------------


def test_reservation_success_writes_ledger_outbox_state_and_consumes_approval(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    approved = drive_to(engine, store, intent, S.APPROVED)
    assert approved.state is S.APPROVED
    assert store.is_consumed("appr-1") is False

    reserved = engine.reserve_execution(
        intent.payment_intent_id, "tenant-a", make_evidence(intent), store, NOW, "executor-1"
    )

    # State advanced and persisted.
    assert reserved.state is S.RESERVED
    assert reserved.version == approved.version + 1
    assert reserved.reserved_at == NOW
    assert execution_for(engine, intent) == reserved

    # Approval consumed exactly once, with the correct arguments.
    assert store.is_consumed("appr-1") is True
    assert store.calls == [("appr-1", {"tenant_id": "tenant-a", "executor_id": "executor-1"})]

    # Ledger entry.
    ledger = fetch_all(
        db_path,
        "SELECT entry_type, amount, currency, destination_id, executor_id, tenant_id, "
        "payment_intent_id, transaction_execution_id FROM transaction_ledger_entries",
    )
    assert len(ledger) == 1
    entry_type, amount, currency, destination, executor, tenant, pi_id, te_id = ledger[0]
    assert entry_type == "RESERVATION"
    assert Decimal(amount) == Decimal("250.00")
    assert currency == "USD"
    assert destination == "dest-1"
    assert executor == "executor-1"
    assert tenant == "tenant-a"
    assert pi_id == intent.payment_intent_id
    assert te_id == reserved.transaction_execution_id

    # Outbox record.
    outbox = fetch_all(
        db_path,
        "SELECT status, attempts, idempotency_key, request_fingerprint, payload, "
        "transaction_execution_id, payment_intent_id, tenant_id FROM provider_outbox",
    )
    assert len(outbox) == 1
    status, attempts, idem, fingerprint, payload, te_id, pi_id, tenant = outbox[0]
    assert status == "PENDING"
    assert attempts == 0
    assert idem == intent.idempotency_key
    assert fingerprint == intent.request_fingerprint
    assert te_id == reserved.transaction_execution_id
    assert pi_id == intent.payment_intent_id
    assert tenant == "tenant-a"
    body = json.loads(payload)
    assert Decimal(body["amount"]) == Decimal("250.00")
    assert body["currency"] == "USD"
    assert body["destination_id"] == "dest-1"
    assert body["approval_id"] == "appr-1"
    assert body["executor_id"] == "executor-1"
    assert body["action_id"] == "action-1"
    assert body["idempotency_key"] == "idem-1"
    assert body["transaction_execution_id"] == reserved.transaction_execution_id


def test_second_reservation_is_rejected_and_does_not_burn_another_approval(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    drive_to(engine, store, intent, S.RESERVED)
    assert len(store.calls) == 1

    with pytest.raises(InvalidStateTransitionError):
        engine.reserve_execution(
            intent.payment_intent_id,
            "tenant-a",
            make_evidence(intent, approval_id="appr-1"),
            store,
            NOW,
            "executor-2",
        )
    assert len(store.calls) == 1
    assert count(db_path, "transaction_ledger_entries") == 1
    assert count(db_path, "provider_outbox") == 1
    assert execution_for(engine, intent).state is S.RESERVED


@pytest.mark.parametrize("state", [S.CREATED, S.AUTHORIZED], ids=lambda s: s.value)
def test_reservation_requires_approved_state_and_does_not_consume(
    engine: DurableTransactionEngine,
    store: EnrolledApprovalStore,
    db_path: str,
    state: TransactionExecutionState,
) -> None:
    intent = make_intent(engine)
    before = drive_to(engine, store, intent, state)
    with pytest.raises(InvalidStateTransitionError):
        engine.reserve_execution(
            intent.payment_intent_id, "tenant-a", make_evidence(intent), store, NOW, "executor-1"
        )
    assert store.calls == []
    assert store.is_consumed("appr-1") is False
    assert execution_for(engine, intent) == before
    assert count(db_path, "transaction_ledger_entries") == 0
    assert count(db_path, "provider_outbox") == 0


def test_reservation_is_tenant_scoped(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    before = drive_to(engine, store, intent, S.APPROVED)
    with pytest.raises(TransactionNotFoundError):
        engine.reserve_execution(
            intent.payment_intent_id,
            "tenant-b",
            make_evidence(intent, tenant_id="tenant-b"),
            store,
            NOW,
            "executor-1",
        )
    assert store.calls == []
    assert execution_for(engine, intent) == before
    assert count(db_path, "transaction_ledger_entries") == 0


def test_reservation_for_unknown_intent_is_not_found(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore
) -> None:
    intent = make_intent(engine)
    with pytest.raises(TransactionNotFoundError):
        engine.reserve_execution(
            "pi_missing", "tenant-a", make_evidence(intent), store, NOW, "executor-1"
        )
    assert store.calls == []


def test_reservation_input_validation(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    before = drive_to(engine, store, intent, S.APPROVED)
    evidence = make_evidence(intent)

    with pytest.raises(ValueError):
        engine.reserve_execution(
            intent.payment_intent_id, "tenant-a", evidence, store, datetime(2030, 1, 1), "executor-1"
        )
    with pytest.raises(ValueError):
        engine.reserve_execution(
            intent.payment_intent_id, "tenant-a", evidence, store, NOW, " "
        )
    with pytest.raises(ApprovalEvidenceInvalid):
        engine.reserve_execution(
            intent.payment_intent_id, "tenant-a", None, store, NOW, "executor-1"  # type: ignore[arg-type]
        )
    with pytest.raises(ApprovalEvidenceInvalid):
        engine.reserve_execution(
            intent.payment_intent_id, "tenant-a", evidence, None, NOW, "executor-1"  # type: ignore[arg-type]
        )
    assert store.calls == []
    assert execution_for(engine, intent) == before
    assert count(db_path, "transaction_ledger_entries") == 0


# ---------------------------------------------------------------------------
# Evidence verification (approval must not be consumed on any rejection)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "override",
    [
        {"tenant_id": "tenant-evil"},
        {"approval_id": "appr-other"},
        {"action_id": "action-evil"},
        {"session_id": "session-evil"},
        {"subject_id": "subject-evil"},
        {"destination_id": "dest-evil"},
        {"amount": "249.99"},
        {"amount": "0"},
        {"amount": 12.5},
        {"currency": "EUR"},
    ],
    ids=lambda o: next(iter(o)) + "=" + str(next(iter(o.values()))),
)
def test_evidence_binding_mismatch_rejected_without_consuming(
    engine: DurableTransactionEngine,
    store: EnrolledApprovalStore,
    db_path: str,
    override: Dict[str, Any],
) -> None:
    intent = make_intent(engine)
    before = drive_to(engine, store, intent, S.APPROVED)
    with pytest.raises(ApprovalEvidenceInvalid):
        engine.reserve_execution(
            intent.payment_intent_id,
            "tenant-a",
            make_evidence(intent, **override),
            store,
            NOW,
            "executor-1",
        )
    assert store.calls == []
    assert store.is_consumed("appr-1") is False
    assert execution_for(engine, intent) == before
    assert count(db_path, "transaction_ledger_entries") == 0
    assert count(db_path, "provider_outbox") == 0


def test_equivalent_amount_representation_in_evidence_is_accepted(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore
) -> None:
    intent = make_intent(engine)
    drive_to(engine, store, intent, S.APPROVED)
    reserved = engine.reserve_execution(
        intent.payment_intent_id,
        "tenant-a",
        make_evidence(intent, amount="250", currency="usd"),
        store,
        NOW,
        "executor-1",
    )
    assert reserved.state is S.RESERVED


def test_untrusted_evidence_is_rejected_without_consuming(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    before = drive_to(engine, store, intent, S.APPROVED)
    with pytest.raises(ApprovalEvidenceInvalid):
        engine.reserve_execution(
            intent.payment_intent_id,
            "tenant-a",
            make_evidence(intent, trusted=False),
            store,
            NOW,
            "executor-1",
        )
    assert store.calls == []
    assert execution_for(engine, intent) == before
    assert count(db_path, "transaction_ledger_entries") == 0


def test_expired_evidence_is_rejected_without_consuming(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    before = drive_to(engine, store, intent, S.APPROVED)
    with pytest.raises(ApprovalEvidenceExpired):
        engine.reserve_execution(
            intent.payment_intent_id,
            "tenant-a",
            make_evidence(intent),
            store,
            NOW + timedelta(hours=2),
            "executor-1",
        )
    assert store.calls == []
    assert execution_for(engine, intent) == before
    assert count(db_path, "transaction_ledger_entries") == 0
    assert count(db_path, "provider_outbox") == 0


def test_already_consumed_approval_rolls_back_and_raises(
    engine: DurableTransactionEngine, db_path: str
) -> None:
    denying = DenyingApprovalStore()
    intent = make_intent(engine)
    before = drive_to(engine, denying, intent, S.APPROVED)
    with pytest.raises(ApprovalEvidenceConsumed):
        engine.reserve_execution(
            intent.payment_intent_id, "tenant-a", make_evidence(intent), denying, NOW, "executor-1"
        )
    assert denying.calls == ["appr-1"]
    assert execution_for(engine, intent) == before
    assert execution_for(engine, intent).state is S.APPROVED
    assert count(db_path, "transaction_ledger_entries") == 0
    assert count(db_path, "provider_outbox") == 0


def test_replayed_approval_cannot_reserve_a_second_intent(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    first = make_intent(engine)
    drive_to(engine, store, first, S.RESERVED)

    second = make_intent(
        engine,
        action_id="action-2",
        idempotency_key="idem-2",
        approval_id="appr-1",  # same approval id replayed against a new intent
    )
    before = drive_to(engine, store, second, S.APPROVED) if False else None
    execution = execution_for(engine, second)
    execution = engine.transition_state(execution.transaction_execution_id, "tenant-a", S.AUTHORIZED, now=NOW)
    execution = engine.transition_state(execution.transaction_execution_id, "tenant-a", S.APPROVED, now=NOW)
    assert before is None

    with pytest.raises(ApprovalEvidenceConsumed):
        engine.reserve_execution(
            second.payment_intent_id,
            "tenant-a",
            make_evidence(second, approval_id="appr-1"),
            store,
            NOW,
            "executor-1",
        )
    assert execution_for(engine, second) == execution
    assert count(db_path, "transaction_ledger_entries") == 1
    assert count(db_path, "provider_outbox") == 1


# ---------------------------------------------------------------------------
# 5. Atomic reservation: rollback
# ---------------------------------------------------------------------------


def _insert_conflicting_ledger_row(db_path: str, execution: TransactionExecution) -> None:
    execute_write(
        db_path,
        "INSERT INTO transaction_ledger_entries (ledger_entry_id, tenant_id, "
        "transaction_execution_id, payment_intent_id, entry_type, amount, currency, "
        "destination_id, executor_id, created_at) VALUES (?, ?, ?, ?, 'RESERVATION', '1', "
        "'USD', 'd', 'x', 'now')",
        ("le_preplanted", execution.tenant_id, execution.transaction_execution_id,
         execution.payment_intent_id),
    )


def _insert_conflicting_outbox_row(db_path: str, execution: TransactionExecution) -> None:
    execute_write(
        db_path,
        "INSERT INTO provider_outbox (outbox_id, tenant_id, transaction_execution_id, "
        "payment_intent_id, idempotency_key, request_fingerprint, payload, status, attempts, "
        "created_at) VALUES (?, ?, ?, ?, 'k', 'fp', '{}', 'PENDING', 0, 'now')",
        ("ob_preplanted", execution.tenant_id, execution.transaction_execution_id,
         execution.payment_intent_id),
    )


def test_ledger_failure_rolls_back_everything_including_enrolled_approval(
    engine: DurableTransactionEngine,
    store: EnrolledApprovalStore,
    db_path: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    intent = make_intent(engine)
    approved = drive_to(engine, store, intent, S.APPROVED)
    _insert_conflicting_ledger_row(db_path, approved)

    with caplog.at_level(logging.CRITICAL):
        with pytest.raises(sqlite3.IntegrityError):
            engine.reserve_execution(
                intent.payment_intent_id,
                "tenant-a",
                make_evidence(intent),
                store,
                NOW,
                "executor-1",
            )

    # The approval consume was attempted but rolled back with the transaction.
    assert len(store.calls) == 1
    assert store.is_consumed("appr-1") is False
    assert count(db_path, "approval_consumptions") == 0

    # State untouched.
    after = execution_for(engine, intent)
    assert after == approved
    assert after.state is S.APPROVED
    assert after.reserved_at is None

    # Only the pre-planted ledger row exists; no outbox record was written.
    assert count(db_path, "transaction_ledger_entries") == 1
    assert count(db_path, "provider_outbox") == 0
    assert any(record.levelno == logging.CRITICAL for record in caplog.records)

    # Once the fault is cleared the same approval can still be used.
    execute_write(db_path, "DELETE FROM transaction_ledger_entries WHERE ledger_entry_id = 'le_preplanted'")
    reserved = engine.reserve_execution(
        intent.payment_intent_id, "tenant-a", make_evidence(intent), store, NOW, "executor-1"
    )
    assert reserved.state is S.RESERVED
    assert store.is_consumed("appr-1") is True
    assert count(db_path, "transaction_ledger_entries") == 1
    assert count(db_path, "provider_outbox") == 1


def test_outbox_failure_rolls_back_ledger_state_and_enrolled_approval(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    approved = drive_to(engine, store, intent, S.APPROVED)
    _insert_conflicting_outbox_row(db_path, approved)

    with pytest.raises(sqlite3.IntegrityError):
        engine.reserve_execution(
            intent.payment_intent_id, "tenant-a", make_evidence(intent), store, NOW, "executor-1"
        )

    assert store.is_consumed("appr-1") is False
    assert execution_for(engine, intent) == approved
    assert count(db_path, "transaction_ledger_entries") == 0  # ledger insert rolled back
    assert count(db_path, "provider_outbox") == 1  # only the pre-planted row
    rows = fetch_all(db_path, "SELECT state, version FROM transaction_executions")
    assert rows == [("APPROVED", approved.version)]


def test_unexpected_exception_in_approval_store_rolls_back_and_propagates(
    engine: DurableTransactionEngine, db_path: str
) -> None:
    class ExplodingStore:
        def consume(self, evidence: Any, now: datetime, tenant_id: Any = None, executor_id: Any = None) -> bool:
            raise RuntimeError("approval backend unavailable")

    intent = make_intent(engine)
    approved = drive_to(engine, PlainApprovalStore(), intent, S.APPROVED)
    with pytest.raises(RuntimeError, match="approval backend unavailable"):
        engine.reserve_execution(
            intent.payment_intent_id,
            "tenant-a",
            make_evidence(intent),
            ExplodingStore(),
            NOW,
            "executor-1",
        )
    assert execution_for(engine, intent) == approved
    assert count(db_path, "transaction_ledger_entries") == 0
    assert count(db_path, "provider_outbox") == 0


def test_non_enrolled_store_fails_closed_after_db_rollback(
    engine: DurableTransactionEngine, db_path: str, caplog: pytest.LogCaptureFixture
) -> None:
    """A store outside the DB transaction cannot be un-consumed; the engine fails closed."""
    plain = PlainApprovalStore()
    intent = make_intent(engine)
    approved = drive_to(engine, plain, intent, S.APPROVED)
    _insert_conflicting_ledger_row(db_path, approved)

    with caplog.at_level(logging.CRITICAL):
        with pytest.raises(sqlite3.IntegrityError):
            engine.reserve_execution(
                intent.payment_intent_id,
                "tenant-a",
                make_evidence(intent),
                plain,
                NOW,
                "executor-1",
            )

    # Database fully rolled back.
    assert execution_for(engine, intent) == approved
    assert count(db_path, "provider_outbox") == 0
    assert count(db_path, "transaction_ledger_entries") == 1  # pre-planted only

    # The approval stays consumed (fail-closed) and can never be consumed twice.
    assert "appr-1" in plain.consumed
    assert plain.consume(make_evidence(intent), NOW) is False
    assert any(record.levelno == logging.CRITICAL for record in caplog.records)


def test_failed_reservation_leaves_no_partial_rows_across_all_tables(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore, db_path: str
) -> None:
    intent = make_intent(engine)
    approved = drive_to(engine, store, intent, S.APPROVED)
    _insert_conflicting_outbox_row(db_path, approved)

    snapshot_before = {
        table: fetch_all(db_path, f"SELECT * FROM {table} ORDER BY 1")
        for table in (
            "payment_intents",
            "transaction_executions",
            "transaction_ledger_entries",
            "provider_outbox",
            "approval_consumptions",
        )
    }
    with pytest.raises(sqlite3.IntegrityError):
        engine.reserve_execution(
            intent.payment_intent_id, "tenant-a", make_evidence(intent), store, NOW, "executor-1"
        )
    snapshot_after = {
        table: fetch_all(db_path, f"SELECT * FROM {table} ORDER BY 1")
        for table in snapshot_before
    }
    assert snapshot_after == snapshot_before


# ---------------------------------------------------------------------------
# 6. Teardown hygiene
# ---------------------------------------------------------------------------


def test_full_flow_leaks_no_connections_or_warnings(
    engine: DurableTransactionEngine, store: EnrolledApprovalStore
) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        intent = make_intent(engine)
        drive_to(engine, store, intent, S.SETTLED)
        with pytest.raises(InvalidStateTransitionError):
            engine.transition_state(
                execution_for(engine, intent).transaction_execution_id,
                "tenant-a",
                S.FAILED,
                now=NOW,
            )
        gc.collect()


def test_engine_closes_connection_after_every_operation(db_path: str) -> None:
    opened: List["_Spy"] = []

    class _Spy:
        def __init__(self) -> None:
            self._conn = sqlite3.connect(db_path)
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

    engine = DurableTransactionEngine(_Spy, dialect="sqlite", clock=lambda: NOW)  # type: ignore[arg-type]
    engine.ensure_schema()
    intent = make_intent(engine)
    with pytest.raises(IdempotencyConflictError):
        make_intent(engine, amount="1")
    with pytest.raises(TransactionNotFoundError):
        engine.get_execution("te_missing", "tenant-a")
    engine.get_intent(intent.payment_intent_id, "tenant-a")

    assert opened, "factory was never used"
    assert all(spy.closed for spy in opened)