"""
tests/test_multitenancy.py

Milestone M10: adversarial test matrix for Multi-Tenancy as a First-Class
Security Boundary.

Backed by an in-memory sqlite3 database. The gateway closes its connection
after every DB transaction, so the fixture hands it a connection subclass whose
close() is a no-op; the fixture closes the real connection at teardown.

Webhook and approval-consumption scenarios are exercised through small
test-local harness functions that use only the public M10 primitives
(require_same_tenant, prevent_existence_oracle, TenantScopedGateway), so the
tests verify the security boundary itself rather than any particular handler.
"""

from __future__ import annotations

import pickle
import sqlite3
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable, Iterator

import pytest

from app.tenant_context import (
    IssuerCapability,
    TenantContext,
    TenantContextExpired,
    TenantContextInvalid,
    TenantIsolationError,
    TenantResourceNotFound,
    TenantScopedGateway,
    TrustedTenantContextIssuer,
    generate_rls_session_statement,
    prevent_existence_oracle,
    require_same_tenant,
)
from app.transaction_engine import TransactionExecutionState


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NOW = datetime(2026, 10, 7, 12, 0, 0, tzinfo=timezone.utc)
ISSUED = NOW - timedelta(minutes=10)
EXPIRES = NOW + timedelta(hours=1)

SUBMITTED = TransactionExecutionState.SUBMITTED.value
UNKNOWN = TransactionExecutionState.UNKNOWN.value
SETTLED = TransactionExecutionState.SETTLED.value
CREATED = TransactionExecutionState.CREATED.value

ALL_TABLES = [
    "transaction_approvals",
    "transaction_executions",
    "transaction_ledger_entries",
    "transaction_outbox",
    "webhook_events",
    "settlement_statements",
    "settlement_statement_entries",
    "reconciliation_cases",
]


# ---------------------------------------------------------------------------
# Test doubles
# ---------------------------------------------------------------------------


class SharedMemoryConnection(sqlite3.Connection):
    """sqlite3 connection whose close() is a no-op so the in-memory DB survives
    the gateway's per-transaction close. Use force_close() at teardown."""

    def close(self) -> None:  # noqa: D102
        return None

    def force_close(self) -> None:
        sqlite3.Connection.close(self)


class CountingFactory:
    """Connection factory that counts how many connections were requested."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection
        self.calls = 0

    def __call__(self) -> Any:
        self.calls += 1
        return self._connection


class _RecordingCursor:
    def __init__(self, connection: "FakePgConnection") -> None:
        self._connection = connection
        self.description = None
        self.rowcount = 0

    def execute(self, sql: str, params: Any = ()) -> None:
        self._connection.executed.append((sql, params))
        fail_on = self._connection.fail_on
        if fail_on is not None and fail_on in sql:
            raise RuntimeError("simulated database failure")

    def fetchone(self) -> None:
        return None

    def close(self) -> None:
        self._connection.cursors_closed += 1


class FakePgConnection:
    """Recording stand-in for a psycopg connection (paramstyle 'format')."""

    def __init__(self, fail_on: str | None = None) -> None:
        self.executed: list[tuple[str, Any]] = []
        self.committed = False
        self.rolled_back = False
        self.closed = False
        self.cursors_closed = 0
        self.fail_on = fail_on

    def cursor(self) -> _RecordingCursor:
        return _RecordingCursor(self)

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


# Make the gateway's paramstyle detection treat this class as psycopg.
FakePgConnection.__module__ = "psycopg.fake"


@dataclass
class Env:
    connection: SharedMemoryConnection
    factory: CountingFactory
    gateway: TenantScopedGateway
    capability: IssuerCapability
    issuer: TrustedTenantContextIssuer
    tenant_a: uuid.UUID
    tenant_b: uuid.UUID
    ctx_a: TenantContext
    ctx_b: TenantContext


SCHEMA = [
    """
    CREATE TABLE transaction_approvals (
        approval_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        transaction_execution_id TEXT,
        status TEXT NOT NULL,
        consumed INTEGER NOT NULL DEFAULT 0
    )
    """,
    """
    CREATE TABLE transaction_executions (
        transaction_execution_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        state TEXT NOT NULL,
        amount TEXT NOT NULL,
        currency TEXT NOT NULL,
        provider_reference TEXT,
        idempotency_key TEXT,
        UNIQUE (tenant_id, idempotency_key)
    )
    """,
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
    """,
    """
    CREATE TABLE transaction_outbox (
        outbox_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        transaction_execution_id TEXT,
        payload TEXT NOT NULL,
        status TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE webhook_events (
        event_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        payload TEXT NOT NULL,
        received_at TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE settlement_statements (
        statement_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        provider_id TEXT NOT NULL,
        line_count INTEGER NOT NULL
    )
    """,
    """
    CREATE TABLE settlement_statement_entries (
        entry_id TEXT PRIMARY KEY,
        statement_id TEXT NOT NULL,
        tenant_id TEXT NOT NULL,
        amount TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE reconciliation_cases (
        reconciliation_id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        transaction_id TEXT,
        statement_entry_id TEXT,
        state TEXT NOT NULL,
        discrepancy_reason TEXT,
        evaluated_at TEXT NOT NULL
    )
    """,
]


def _issue(
    issuer: TrustedTenantContextIssuer,
    capability: IssuerCapability,
    tenant_id: uuid.UUID,
    *,
    issued_at: datetime = ISSUED,
    expires_at: datetime = EXPIRES,
    roles: frozenset[str] = frozenset({"operator"}),
) -> TenantContext:
    return issuer.issue_context(
        capability,
        tenant_id=tenant_id,
        subject_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        issued_at=issued_at,
        expires_at=expires_at,
        roles=roles,
    )


@pytest.fixture
def env() -> Iterator[Env]:
    connection = sqlite3.connect(":memory:", factory=SharedMemoryConnection)
    for ddl in SCHEMA:
        connection.execute(ddl)
    connection.commit()

    factory = CountingFactory(connection)
    gateway = TenantScopedGateway(factory)

    capability = IssuerCapability.mint()
    issuer = TrustedTenantContextIssuer(capability)
    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    try:
        yield Env(
            connection=connection,
            factory=factory,
            gateway=gateway,
            capability=capability,
            issuer=issuer,
            tenant_a=tenant_a,
            tenant_b=tenant_b,
            ctx_a=_issue(issuer, capability, tenant_a),
            ctx_b=_issue(issuer, capability, tenant_b),
        )
    finally:
        connection.force_close()


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


def insert_execution(
    env: Env,
    tenant_id: uuid.UUID,
    state: str = SUBMITTED,
    amount: str = "100.00",
    currency: str = "USD",
    idempotency_key: str | None = None,
) -> uuid.UUID:
    execution_id = uuid.uuid4()
    env.connection.execute(
        "INSERT INTO transaction_executions "
        "(transaction_execution_id, tenant_id, state, amount, currency, "
        "provider_reference, idempotency_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            str(execution_id),
            str(tenant_id),
            state,
            amount,
            currency,
            None,
            idempotency_key,
        ),
    )
    env.connection.commit()
    return execution_id


def insert_approval(
    env: Env, tenant_id: uuid.UUID, execution_id: uuid.UUID | None = None
) -> uuid.UUID:
    approval_id = uuid.uuid4()
    env.connection.execute(
        "INSERT INTO transaction_approvals "
        "(approval_id, tenant_id, transaction_execution_id, status, consumed) "
        "VALUES (?, ?, ?, ?, 0)",
        (
            str(approval_id),
            str(tenant_id),
            str(execution_id) if execution_id else None,
            "APPROVED",
        ),
    )
    env.connection.commit()
    return approval_id


def insert_outbox(
    env: Env, tenant_id: uuid.UUID, execution_id: uuid.UUID | None = None
) -> uuid.UUID:
    outbox_id = uuid.uuid4()
    env.connection.execute(
        "INSERT INTO transaction_outbox "
        "(outbox_id, tenant_id, transaction_execution_id, payload, status) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            str(outbox_id),
            str(tenant_id),
            str(execution_id) if execution_id else None,
            '{"kind": "submit"}',
            "PENDING",
        ),
    )
    env.connection.commit()
    return outbox_id


def insert_webhook_event(env: Env, tenant_id: uuid.UUID) -> uuid.UUID:
    event_id = uuid.uuid4()
    env.connection.execute(
        "INSERT INTO webhook_events "
        "(event_id, tenant_id, provider_id, payload, received_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            str(event_id),
            str(tenant_id),
            "provider-alpha",
            '{"status": "settled"}',
            NOW.isoformat(),
        ),
    )
    env.connection.commit()
    return event_id


def insert_statement(
    env: Env,
    tenant_id: uuid.UUID,
    line_count: int,
    entry_count: int | None = None,
    entry_tenant_id: uuid.UUID | None = None,
) -> uuid.UUID:
    statement_id = uuid.uuid4()
    env.connection.execute(
        "INSERT INTO settlement_statements "
        "(statement_id, tenant_id, provider_id, line_count) VALUES (?, ?, ?, ?)",
        (str(statement_id), str(tenant_id), "provider-alpha", line_count),
    )
    count = line_count if entry_count is None else entry_count
    for _ in range(count):
        env.connection.execute(
            "INSERT INTO settlement_statement_entries "
            "(entry_id, statement_id, tenant_id, amount) VALUES (?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                str(statement_id),
                str(entry_tenant_id or tenant_id),
                "100.00",
            ),
        )
    env.connection.commit()
    return statement_id


def insert_ledger_entry(
    env: Env, tenant_id: uuid.UUID, execution_id: uuid.UUID
) -> uuid.UUID:
    entry_id = uuid.uuid4()
    env.connection.execute(
        "INSERT INTO transaction_ledger_entries "
        "(entry_id, tenant_id, transaction_execution_id, entry_type, amount, "
        "currency, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            str(entry_id),
            str(tenant_id),
            str(execution_id),
            "SETTLEMENT_CONFIRMED",
            "100.00",
            "USD",
            NOW.isoformat(),
        ),
    )
    env.connection.commit()
    return entry_id


def insert_reconciliation_case(
    env: Env, tenant_id: uuid.UUID, transaction_id: uuid.UUID
) -> uuid.UUID:
    case_id = uuid.uuid4()
    env.connection.execute(
        "INSERT INTO reconciliation_cases "
        "(reconciliation_id, tenant_id, transaction_id, statement_entry_id, "
        "state, discrepancy_reason, evaluated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            str(case_id),
            str(tenant_id),
            str(transaction_id),
            None,
            "MATCHED_SETTLED",
            None,
            NOW.isoformat(),
        ),
    )
    env.connection.commit()
    return case_id


def seed_all(env: Env, tenant_id: uuid.UUID) -> dict[str, uuid.UUID]:
    """Seed one row in every tenant-scoped table; return table -> row id."""
    execution_id = insert_execution(env, tenant_id)
    statement_id = insert_statement(env, tenant_id, line_count=1)
    entry_row = env.connection.execute(
        "SELECT entry_id FROM settlement_statement_entries "
        "WHERE tenant_id = ? AND statement_id = ?",
        (str(tenant_id), str(statement_id)),
    ).fetchone()
    return {
        "transaction_approvals": insert_approval(env, tenant_id, execution_id),
        "transaction_executions": execution_id,
        "transaction_ledger_entries": insert_ledger_entry(
            env, tenant_id, execution_id
        ),
        "transaction_outbox": insert_outbox(env, tenant_id, execution_id),
        "webhook_events": insert_webhook_event(env, tenant_id),
        "settlement_statements": statement_id,
        "settlement_statement_entries": uuid.UUID(entry_row[0]),
        "reconciliation_cases": insert_reconciliation_case(
            env, tenant_id, execution_id
        ),
    }


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------


def row_count(env: Env, table: str) -> int:
    return int(env.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def execution_state(env: Env, execution_id: uuid.UUID) -> str:
    row = env.connection.execute(
        "SELECT state FROM transaction_executions "
        "WHERE transaction_execution_id = ?",
        (str(execution_id),),
    ).fetchone()
    assert row is not None
    return str(row[0])


def lookup(
    env: Env,
    context: TenantContext,
    table: str,
    entity_id: uuid.UUID,
    now: datetime = NOW,
) -> Any:
    """Gateway lookup followed by the existence-oracle guard."""
    entity = env.gateway.scoped_query(context, table, entity_id, now)
    owner = uuid.UUID(entity["tenant_id"]) if entity is not None else None
    return prevent_existence_oracle(entity, context, owner, now)


def untrusted_context(tenant_id: uuid.UUID) -> TenantContext:
    """A structurally valid context that no trusted issuer minted."""
    return TenantContext(
        tenant_id=tenant_id,
        subject_id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        issued_at=ISSUED,
        expires_at=EXPIRES,
        context_id=uuid.uuid4(),
        roles=frozenset({"operator"}),
    )


def capture(callable_: Callable[[], Any]) -> BaseException:
    try:
        callable_()
    except BaseException as exc:  # noqa: BLE001 - deliberate: inspect any error
        return exc
    raise AssertionError("expected an exception but none was raised")


# ---------------------------------------------------------------------------
# Test-local harnesses built only on public M10 primitives
# ---------------------------------------------------------------------------


def consume_approval(
    env: Env, context: TenantContext, approval_id: uuid.UUID, now: datetime = NOW
) -> None:
    """Consume approval evidence; only the owning tenant may do so."""
    row = env.gateway.scoped_lock(context, "transaction_approvals", approval_id, now)
    owner = uuid.UUID(row["tenant_id"]) if row is not None else None
    prevent_existence_oracle(row, context, owner, now)
    env.connection.execute(
        "UPDATE transaction_approvals SET consumed = 1 "
        "WHERE tenant_id = ? AND approval_id = ?",
        (str(context.tenant_id), str(approval_id)),
    )
    env.connection.commit()


def receive_webhook(
    env: Env, context: TenantContext, payload: dict[str, Any], now: datetime = NOW
) -> uuid.UUID:
    """Webhook endpoint bound to the context's tenant."""
    claimed = payload.get("tenant_id")
    try:
        claimed_id = uuid.UUID(str(claimed))
    except (ValueError, AttributeError, TypeError):
        raise TenantIsolationError("Tenant boundary violation") from None
    require_same_tenant(context, claimed_id, now)
    event_id = uuid.uuid4()
    env.connection.execute(
        "INSERT INTO webhook_events "
        "(event_id, tenant_id, provider_id, payload, received_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            str(event_id),
            str(context.tenant_id),
            str(payload.get("provider_id", "provider-alpha")),
            str(payload),
            now.isoformat(),
        ),
    )
    env.connection.commit()
    return event_id


def find_execution_by_idempotency_key(
    env: Env, context: TenantContext, key: str
) -> str | None:
    row = env.connection.execute(
        "SELECT transaction_execution_id FROM transaction_executions "
        "WHERE tenant_id = ? AND idempotency_key = ?",
        (str(context.tenant_id), key),
    ).fetchone()
    return None if row is None else str(row[0])


# ---------------------------------------------------------------------------
# 0. Exception hierarchy and issuer
# ---------------------------------------------------------------------------


class TestExceptionHierarchy:
    def test_hierarchy(self) -> None:
        assert issubclass(TenantIsolationError, Exception)
        assert issubclass(TenantContextInvalid, TenantIsolationError)
        assert issubclass(TenantContextExpired, TenantIsolationError)
        assert issubclass(TenantResourceNotFound, TenantIsolationError)

    def test_resource_not_found_message_is_constant(self) -> None:
        first = TenantResourceNotFound()
        second = TenantResourceNotFound()
        assert str(first) == str(second) == "Resource not found"
        assert first.args == second.args


class TestIssuer:
    def test_issued_context_is_trusted(self, env: Env) -> None:
        assert env.ctx_a.is_trusted()
        env.ctx_a.require_trusted()
        assert env.ctx_a.tenant_id == env.tenant_a
        assert env.ctx_a.roles == frozenset({"operator"})

    def test_issuer_requires_a_capability_object(self) -> None:
        with pytest.raises(TenantContextInvalid):
            TrustedTenantContextIssuer(object())  # type: ignore[arg-type]

    def test_capability_cannot_be_constructed_directly(self) -> None:
        with pytest.raises(TypeError):
            IssuerCapability()

    def test_issue_with_wrong_capability_is_rejected(self, env: Env) -> None:
        other_capability = IssuerCapability.mint()
        with pytest.raises(TenantContextInvalid):
            env.issuer.issue_context(
                other_capability,
                tenant_id=env.tenant_a,
                subject_id=uuid.uuid4(),
                session_id=uuid.uuid4(),
                issued_at=ISSUED,
                expires_at=EXPIRES,
            )

    def test_issue_with_non_capability_is_rejected(self, env: Env) -> None:
        with pytest.raises(TenantContextInvalid):
            env.issuer.issue_context(
                "let-me-in",  # type: ignore[arg-type]
                tenant_id=env.tenant_a,
                subject_id=uuid.uuid4(),
                session_id=uuid.uuid4(),
                issued_at=ISSUED,
                expires_at=EXPIRES,
            )

    def test_each_issue_gets_a_unique_context_id(self, env: Env) -> None:
        first = _issue(env.issuer, env.capability, env.tenant_a)
        second = _issue(env.issuer, env.capability, env.tenant_a)
        assert first.context_id != second.context_id

    def test_marker_cannot_be_pickled(self, env: Env) -> None:
        with pytest.raises((TypeError, pickle.PicklingError)):
            pickle.dumps(env.ctx_a)


# ---------------------------------------------------------------------------
# 1. Context boundary
# ---------------------------------------------------------------------------

GatewayOp = Callable[[Env, Any], Any]

GATEWAY_OPS: list[tuple[str, GatewayOp]] = [
    (
        "scoped_query",
        lambda env, c: env.gateway.scoped_query(
            c, "transaction_executions", uuid.uuid4(), NOW
        ),
    ),
    (
        "scoped_lock",
        lambda env, c: env.gateway.scoped_lock(
            c, "transaction_executions", uuid.uuid4(), NOW
        ),
    ),
    (
        "scoped_transition",
        lambda env, c: env.gateway.scoped_transition(
            c, uuid.uuid4(), SETTLED, NOW
        ),
    ),
    (
        "scoped_reconcile",
        lambda env, c: env.gateway.scoped_reconcile(c, uuid.uuid4(), NOW),
    ),
    (
        "scoped_append_ledger_entry",
        lambda env, c: env.gateway.scoped_append_ledger_entry(
            c, uuid.uuid4(), "SETTLEMENT_CONFIRMED", Decimal("1.00"), "USD", NOW
        ),
    ),
]
GATEWAY_OP_IDS = [name for name, _ in GATEWAY_OPS]
GATEWAY_OP_FUNCS = [fn for _, fn in GATEWAY_OPS]


class TestContextBoundary:
    @pytest.mark.parametrize("op", GATEWAY_OP_FUNCS, ids=GATEWAY_OP_IDS)
    def test_missing_context_fails_closed_before_any_connection(
        self, env: Env, op: GatewayOp
    ) -> None:
        with pytest.raises(TenantContextInvalid):
            op(env, None)
        assert env.factory.calls == 0

    @pytest.mark.parametrize("op", GATEWAY_OP_FUNCS, ids=GATEWAY_OP_IDS)
    def test_wrong_type_context_fails_closed(self, env: Env, op: GatewayOp) -> None:
        with pytest.raises(TenantContextInvalid):
            op(env, "not-a-context")
        assert env.factory.calls == 0

    @pytest.mark.parametrize("op", GATEWAY_OP_FUNCS, ids=GATEWAY_OP_IDS)
    def test_untrusted_context_fails_closed_before_any_connection(
        self, env: Env, op: GatewayOp
    ) -> None:
        forged = untrusted_context(env.tenant_a)
        assert not forged.is_trusted()
        with pytest.raises(TenantContextInvalid):
            op(env, forged)
        assert env.factory.calls == 0

    @pytest.mark.parametrize("op", GATEWAY_OP_FUNCS, ids=GATEWAY_OP_IDS)
    def test_expired_context_fails_closed_before_any_connection(
        self, env: Env, op: GatewayOp
    ) -> None:
        expired = _issue(
            env.issuer,
            env.capability,
            env.tenant_a,
            issued_at=NOW - timedelta(hours=2),
            expires_at=NOW - timedelta(hours=1),
        )
        assert expired.is_trusted()
        with pytest.raises(TenantContextExpired):
            op(env, expired)
        assert env.factory.calls == 0

    def test_context_expiring_exactly_now_is_expired(self, env: Env) -> None:
        boundary = _issue(
            env.issuer,
            env.capability,
            env.tenant_a,
            issued_at=NOW - timedelta(hours=1),
            expires_at=NOW,
        )
        assert not boundary.is_valid_at(NOW)
        with pytest.raises(TenantContextExpired):
            boundary.require_valid_at(NOW)

    def test_context_not_yet_valid_fails_closed(self, env: Env) -> None:
        future = _issue(
            env.issuer,
            env.capability,
            env.tenant_a,
            issued_at=NOW + timedelta(minutes=5),
            expires_at=NOW + timedelta(hours=1),
        )
        assert not future.is_valid_at(NOW)
        with pytest.raises(TenantContextInvalid):
            future.require_valid_at(NOW)
        with pytest.raises(TenantContextInvalid):
            env.gateway.scoped_query(
                future, "transaction_executions", uuid.uuid4(), NOW
            )
        assert env.factory.calls == 0

    def test_validity_window_is_inclusive_of_issue_and_exclusive_of_expiry(
        self, env: Env
    ) -> None:
        ctx = env.ctx_a
        assert ctx.is_valid_at(ctx.issued_at)
        assert ctx.is_valid_at(NOW)
        assert not ctx.is_valid_at(ctx.expires_at)
        assert not ctx.is_valid_at(ctx.issued_at - timedelta(seconds=1))

    def test_naive_now_is_rejected(self, env: Env) -> None:
        naive_now = datetime(2026, 10, 7, 12, 0, 0)
        assert not env.ctx_a.is_valid_at(naive_now)
        with pytest.raises(TenantContextInvalid):
            env.ctx_a.require_valid_at(naive_now)
        with pytest.raises(TenantContextInvalid):
            env.gateway.scoped_query(
                env.ctx_a, "transaction_executions", uuid.uuid4(), naive_now
            )
        assert env.factory.calls == 0

    def test_naive_issued_at_is_rejected(self) -> None:
        with pytest.raises((TypeError, TenantContextInvalid)):
            TenantContext(
                tenant_id=uuid.uuid4(),
                subject_id=uuid.uuid4(),
                session_id=uuid.uuid4(),
                issued_at=datetime(2026, 10, 7, 11, 0, 0),
                expires_at=EXPIRES,
                context_id=uuid.uuid4(),
            )

    def test_naive_expires_at_is_rejected(self) -> None:
        with pytest.raises((TypeError, TenantContextInvalid)):
            TenantContext(
                tenant_id=uuid.uuid4(),
                subject_id=uuid.uuid4(),
                session_id=uuid.uuid4(),
                issued_at=ISSUED,
                expires_at=datetime(2026, 10, 7, 13, 0, 0),
                context_id=uuid.uuid4(),
            )

    def test_non_utc_offset_is_rejected(self) -> None:
        plus_five = timezone(timedelta(hours=5))
        with pytest.raises((TypeError, TenantContextInvalid)):
            TenantContext(
                tenant_id=uuid.uuid4(),
                subject_id=uuid.uuid4(),
                session_id=uuid.uuid4(),
                issued_at=ISSUED.astimezone(plus_five),
                expires_at=EXPIRES.astimezone(plus_five),
                context_id=uuid.uuid4(),
            )

    @pytest.mark.parametrize(
        "field_name", ["tenant_id", "subject_id", "session_id", "context_id"]
    )
    @pytest.mark.parametrize(
        "bad_value",
        ["not-a-uuid", "", None, 12345, uuid.UUID(int=0)],
        ids=["garbage", "empty", "none", "int", "nil-uuid"],
    )
    def test_invalid_uuids_are_rejected(self, field_name: str, bad_value: Any) -> None:
        kwargs: dict[str, Any] = {
            "tenant_id": uuid.uuid4(),
            "subject_id": uuid.uuid4(),
            "session_id": uuid.uuid4(),
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
            "context_id": uuid.uuid4(),
        }
        kwargs[field_name] = bad_value
        with pytest.raises((TypeError, TenantContextInvalid)):
            TenantContext(**kwargs)

    def test_issuer_rejects_invalid_tenant_uuid(self, env: Env) -> None:
        with pytest.raises((TypeError, TenantContextInvalid)):
            env.issuer.issue_context(
                env.capability,
                tenant_id="not-a-uuid",  # type: ignore[arg-type]
                subject_id=uuid.uuid4(),
                session_id=uuid.uuid4(),
                issued_at=ISSUED,
                expires_at=EXPIRES,
            )

    def test_expiry_must_be_after_issue(self) -> None:
        with pytest.raises(TenantContextInvalid):
            TenantContext(
                tenant_id=uuid.uuid4(),
                subject_id=uuid.uuid4(),
                session_id=uuid.uuid4(),
                issued_at=EXPIRES,
                expires_at=ISSUED,
                context_id=uuid.uuid4(),
            )
        with pytest.raises(TenantContextInvalid):
            TenantContext(
                tenant_id=uuid.uuid4(),
                subject_id=uuid.uuid4(),
                session_id=uuid.uuid4(),
                issued_at=ISSUED,
                expires_at=ISSUED,
                context_id=uuid.uuid4(),
            )

    def test_roles_must_be_frozenset_of_non_empty_strings(self) -> None:
        base: dict[str, Any] = {
            "tenant_id": uuid.uuid4(),
            "subject_id": uuid.uuid4(),
            "session_id": uuid.uuid4(),
            "issued_at": ISSUED,
            "expires_at": EXPIRES,
            "context_id": uuid.uuid4(),
        }
        with pytest.raises(TenantContextInvalid):
            TenantContext(roles=["admin"], **base)  # type: ignore[arg-type]
        with pytest.raises(TenantContextInvalid):
            TenantContext(roles=frozenset({""}), **base)
        with pytest.raises(TenantContextInvalid):
            TenantContext(roles=frozenset({1}), **base)  # type: ignore[arg-type]

    def test_context_is_immutable(self, env: Env) -> None:
        with pytest.raises(Exception):
            env.ctx_a.tenant_id = env.tenant_b  # type: ignore[misc]

    def test_hand_built_context_with_fake_marker_is_untrusted(self) -> None:
        forged = TenantContext(
            tenant_id=uuid.uuid4(),
            subject_id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            issued_at=ISSUED,
            expires_at=EXPIRES,
            context_id=uuid.uuid4(),
            _issuer_marker=object(),
        )
        assert not forged.is_trusted()
        with pytest.raises(TenantContextInvalid):
            forged.require_trusted()

    def test_tenant_swap_on_trusted_context_loses_trust(self, env: Env) -> None:
        escalated = replace(env.ctx_a, tenant_id=env.tenant_b)
        assert escalated.tenant_id == env.tenant_b
        assert not escalated.is_trusted()

    def test_role_escalation_on_trusted_context_loses_trust(self, env: Env) -> None:
        escalated = replace(env.ctx_a, roles=frozenset({"operator", "admin"}))
        assert not escalated.is_trusted()

    def test_lifetime_extension_on_trusted_context_loses_trust(
        self, env: Env
    ) -> None:
        extended = replace(env.ctx_a, expires_at=EXPIRES + timedelta(days=365))
        assert not extended.is_trusted()

    def test_tampered_context_cannot_reach_other_tenants_data(
        self, env: Env
    ) -> None:
        victim_execution = insert_execution(env, env.tenant_b)
        escalated = replace(env.ctx_a, tenant_id=env.tenant_b)
        with pytest.raises(TenantContextInvalid):
            env.gateway.scoped_query(
                escalated, "transaction_executions", victim_execution, NOW
            )
        assert env.gateway.scoped_transition(
            env.ctx_b, victim_execution, SETTLED, NOW
        )
        assert env.factory.calls == 1  # only the legitimate B transition connected

    def test_gateway_constructor_validation(self) -> None:
        with pytest.raises(TypeError):
            TenantScopedGateway("not-callable")  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            TenantScopedGateway(
                lambda: None, table_registry={"bad table; DROP": "id"}
            )
        with pytest.raises(ValueError):
            TenantScopedGateway(
                lambda: None, table_registry={"ok_table": "id; DROP"}
            )


# ---------------------------------------------------------------------------
# require_same_tenant / prevent_existence_oracle guards
# ---------------------------------------------------------------------------


class TestGuards:
    def test_require_same_tenant_allows_matching_tenant(self, env: Env) -> None:
        assert require_same_tenant(env.ctx_a, env.tenant_a, NOW) is None

    def test_require_same_tenant_rejects_other_tenant(self, env: Env) -> None:
        with pytest.raises(TenantIsolationError) as exc_info:
            require_same_tenant(env.ctx_a, env.tenant_b, NOW)
        assert type(exc_info.value) is TenantIsolationError
        assert str(env.tenant_b) not in str(exc_info.value)
        assert str(env.tenant_a) not in str(exc_info.value)

    def test_require_same_tenant_rejects_non_uuid_target(self, env: Env) -> None:
        with pytest.raises(TenantIsolationError):
            require_same_tenant(env.ctx_a, str(env.tenant_a), NOW)  # type: ignore[arg-type]
        with pytest.raises(TenantIsolationError):
            require_same_tenant(env.ctx_a, None, NOW)  # type: ignore[arg-type]

    def test_require_same_tenant_context_failures(self, env: Env) -> None:
        with pytest.raises(TenantContextInvalid):
            require_same_tenant(None, env.tenant_a, NOW)  # type: ignore[arg-type]
        with pytest.raises(TenantContextInvalid):
            require_same_tenant(untrusted_context(env.tenant_a), env.tenant_a, NOW)
        expired = _issue(
            env.issuer,
            env.capability,
            env.tenant_a,
            issued_at=NOW - timedelta(hours=2),
            expires_at=NOW - timedelta(hours=1),
        )
        with pytest.raises(TenantContextExpired):
            require_same_tenant(expired, env.tenant_a, NOW)

    def test_oracle_returns_entity_only_when_tenants_match(self, env: Env) -> None:
        entity = {"id": 1}
        assert (
            prevent_existence_oracle(entity, env.ctx_a, env.tenant_a, NOW) is entity
        )

    def test_oracle_collapses_every_denial_to_one_error(self, env: Env) -> None:
        entity = {"id": 1}
        errors = [
            capture(lambda: prevent_existence_oracle(None, env.ctx_a, None, NOW)),
            capture(
                lambda: prevent_existence_oracle(None, env.ctx_a, env.tenant_a, NOW)
            ),
            capture(
                lambda: prevent_existence_oracle(entity, env.ctx_a, env.tenant_b, NOW)
            ),
            capture(lambda: prevent_existence_oracle(entity, env.ctx_a, None, NOW)),
            capture(
                lambda: prevent_existence_oracle(
                    entity, env.ctx_a, str(env.tenant_a), NOW  # type: ignore[arg-type]
                )
            ),
        ]
        for error in errors:
            assert type(error) is TenantResourceNotFound
            assert error.args == errors[0].args
            assert str(error) == "Resource not found"

    def test_oracle_context_failures_are_reported_as_context_errors(
        self, env: Env
    ) -> None:
        entity = {"id": 1}
        with pytest.raises(TenantContextInvalid):
            prevent_existence_oracle(entity, None, env.tenant_a, NOW)  # type: ignore[arg-type]
        with pytest.raises(TenantContextInvalid):
            prevent_existence_oracle(
                entity, untrusted_context(env.tenant_a), env.tenant_a, NOW
            )
        expired = _issue(
            env.issuer,
            env.capability,
            env.tenant_a,
            issued_at=NOW - timedelta(hours=2),
            expires_at=NOW - timedelta(hours=1),
        )
        with pytest.raises(TenantContextExpired):
            prevent_existence_oracle(entity, expired, env.tenant_a, NOW)


# ---------------------------------------------------------------------------
# 2. Cross-tenant existence oracle prevention
# ---------------------------------------------------------------------------


class TestExistenceOraclePrevention:
    def test_nonexistent_resource_raises_not_found(self, env: Env) -> None:
        with pytest.raises(TenantResourceNotFound):
            lookup(env, env.ctx_a, "transaction_executions", uuid.uuid4())

    def test_other_tenants_resource_raises_not_found(self, env: Env) -> None:
        victim = insert_execution(env, env.tenant_b)
        with pytest.raises(TenantResourceNotFound):
            lookup(env, env.ctx_a, "transaction_executions", victim)

    def test_missing_and_foreign_are_indistinguishable(self, env: Env) -> None:
        victim = insert_execution(env, env.tenant_b)
        missing = uuid.uuid4()

        foreign_error = capture(
            lambda: lookup(env, env.ctx_a, "transaction_executions", victim)
        )
        missing_error = capture(
            lambda: lookup(env, env.ctx_a, "transaction_executions", missing)
        )

        assert type(foreign_error) is type(missing_error) is TenantResourceNotFound
        assert foreign_error.args == missing_error.args
        assert str(foreign_error) == str(missing_error)
        assert foreign_error.__dict__ == missing_error.__dict__
        # No identifier, tenant, or state leaks through the error text.
        for leaked in (str(victim), str(missing), str(env.tenant_a), str(env.tenant_b)):
            assert leaked not in str(foreign_error)
            assert leaked not in repr(foreign_error)

    def test_gateway_returns_none_for_foreign_and_missing_alike(
        self, env: Env
    ) -> None:
        victim = insert_execution(env, env.tenant_b)
        foreign = env.gateway.scoped_query(
            env.ctx_a, "transaction_executions", victim, NOW
        )
        missing = env.gateway.scoped_query(
            env.ctx_a, "transaction_executions", uuid.uuid4(), NOW
        )
        assert foreign is None
        assert missing is None
        assert foreign == missing

    def test_gateway_lock_returns_none_for_foreign_and_missing_alike(
        self, env: Env
    ) -> None:
        victim = insert_execution(env, env.tenant_b)
        assert (
            env.gateway.scoped_lock(env.ctx_a, "transaction_executions", victim, NOW)
            is None
        )
        assert (
            env.gateway.scoped_lock(
                env.ctx_a, "transaction_executions", uuid.uuid4(), NOW
            )
            is None
        )

    def test_owner_can_read_own_resource(self, env: Env) -> None:
        own = insert_execution(env, env.tenant_a, amount="42.50")
        row = lookup(env, env.ctx_a, "transaction_executions", own)
        assert row["tenant_id"] == str(env.tenant_a)
        assert row["transaction_execution_id"] == str(own)
        assert row["amount"] == "42.50"

    @pytest.mark.parametrize("table", ALL_TABLES)
    def test_every_table_hides_foreign_rows_identically(
        self, env: Env, table: str
    ) -> None:
        seeded_a = seed_all(env, env.tenant_a)
        seeded_b = seed_all(env, env.tenant_b)

        # Positive control: the owner sees own row.
        own = lookup(env, env.ctx_a, table, seeded_a[table])
        assert own["tenant_id"] == str(env.tenant_a)

        foreign_error = capture(lambda: lookup(env, env.ctx_a, table, seeded_b[table]))
        missing_error = capture(lambda: lookup(env, env.ctx_a, table, uuid.uuid4()))

        assert type(foreign_error) is type(missing_error) is TenantResourceNotFound
        assert foreign_error.args == missing_error.args

        # And symmetrically for tenant B.
        reverse = capture(lambda: lookup(env, env.ctx_b, table, seeded_a[table]))
        assert type(reverse) is TenantResourceNotFound

    def test_unregistered_table_is_refused(self, env: Env) -> None:
        for table in ("sqlite_master", "users", "x; DROP TABLE y", "", None):
            with pytest.raises(TenantIsolationError):
                env.gateway.scoped_query(
                    env.ctx_a, table, uuid.uuid4(), NOW  # type: ignore[arg-type]
                )

    def test_non_uuid_entity_id_is_refused(self, env: Env) -> None:
        victim = insert_execution(env, env.tenant_b)
        for bad in (str(victim), "' OR '1'='1", None, 7):
            with pytest.raises(TenantIsolationError):
                env.gateway.scoped_query(
                    env.ctx_a, "transaction_executions", bad, NOW  # type: ignore[arg-type]
                )


# ---------------------------------------------------------------------------
# 3. Adversarial cross-tenant resource attacks
# ---------------------------------------------------------------------------


class TestCrossTenantApprovalConsumption:
    def test_tenant_a_cannot_consume_tenant_b_approval(self, env: Env) -> None:
        b_execution = insert_execution(env, env.tenant_b)
        b_approval = insert_approval(env, env.tenant_b, b_execution)

        with pytest.raises(TenantIsolationError):
            consume_approval(env, env.ctx_a, b_approval)

        row = env.connection.execute(
            "SELECT consumed FROM transaction_approvals WHERE approval_id = ?",
            (str(b_approval),),
        ).fetchone()
        assert row[0] == 0

    def test_attack_is_indistinguishable_from_missing_approval(
        self, env: Env
    ) -> None:
        b_approval = insert_approval(env, env.tenant_b)
        foreign = capture(lambda: consume_approval(env, env.ctx_a, b_approval))
        missing = capture(lambda: consume_approval(env, env.ctx_a, uuid.uuid4()))
        assert type(foreign) is type(missing) is TenantResourceNotFound
        assert foreign.args == missing.args

    def test_tenant_b_can_consume_its_own_approval(self, env: Env) -> None:
        b_approval = insert_approval(env, env.tenant_b)
        consume_approval(env, env.ctx_b, b_approval)
        row = env.connection.execute(
            "SELECT consumed FROM transaction_approvals WHERE approval_id = ?",
            (str(b_approval),),
        ).fetchone()
        assert row[0] == 1

    def test_expired_context_cannot_consume_even_own_approval(
        self, env: Env
    ) -> None:
        a_approval = insert_approval(env, env.tenant_a)
        expired = _issue(
            env.issuer,
            env.capability,
            env.tenant_a,
            issued_at=NOW - timedelta(hours=2),
            expires_at=NOW - timedelta(hours=1),
        )
        with pytest.raises(TenantContextExpired):
            consume_approval(env, expired, a_approval)
        row = env.connection.execute(
            "SELECT consumed FROM transaction_approvals WHERE approval_id = ?",
            (str(a_approval),),
        ).fetchone()
        assert row[0] == 0


class TestCrossTenantTransition:
    def test_tenant_a_cannot_transition_tenant_b_execution(self, env: Env) -> None:
        victim = insert_execution(env, env.tenant_b, state=SUBMITTED)

        assert env.gateway.scoped_transition(env.ctx_a, victim, SETTLED, NOW) is False

        assert execution_state(env, victim) == SUBMITTED

    def test_foreign_transition_equals_missing_transition(self, env: Env) -> None:
        victim = insert_execution(env, env.tenant_b, state=SUBMITTED)
        foreign = env.gateway.scoped_transition(env.ctx_a, victim, SETTLED, NOW)
        missing = env.gateway.scoped_transition(
            env.ctx_a, uuid.uuid4(), SETTLED, NOW
        )
        assert foreign is missing is False

    def test_owner_can_transition_submitted_and_unknown_to_settled(
        self, env: Env
    ) -> None:
        submitted = insert_execution(env, env.tenant_a, state=SUBMITTED)
        unknown = insert_execution(env, env.tenant_a, state=UNKNOWN)

        assert env.gateway.scoped_transition(env.ctx_a, submitted, SETTLED, NOW)
        assert env.gateway.scoped_transition(env.ctx_a, unknown, SETTLED, NOW)

        assert execution_state(env, submitted) == SETTLED
        assert execution_state(env, unknown) == SETTLED

    def test_illegal_transitions_are_refused_and_change_nothing(
        self, env: Env
    ) -> None:
        created = insert_execution(env, env.tenant_a, state=CREATED)
        settled = insert_execution(env, env.tenant_a, state=SETTLED)

        assert not env.gateway.scoped_transition(env.ctx_a, created, SETTLED, NOW)
        assert not env.gateway.scoped_transition(env.ctx_a, settled, SUBMITTED, NOW)
        assert not env.gateway.scoped_transition(env.ctx_a, settled, SETTLED, NOW)

        assert execution_state(env, created) == CREATED
        assert execution_state(env, settled) == SETTLED

    def test_unknown_target_state_is_refused(self, env: Env) -> None:
        own = insert_execution(env, env.tenant_a, state=SUBMITTED)
        for bad in ("BOGUS", "", "settled; DROP TABLE x", None):
            assert not env.gateway.scoped_transition(
                env.ctx_a, own, bad, NOW  # type: ignore[arg-type]
            )
        assert execution_state(env, own) == SUBMITTED

    def test_transition_only_touches_the_targeted_row(self, env: Env) -> None:
        a_row = insert_execution(env, env.tenant_a, state=SUBMITTED)
        b_row = insert_execution(env, env.tenant_b, state=SUBMITTED)
        assert env.gateway.scoped_transition(env.ctx_a, a_row, SETTLED, NOW)
        assert execution_state(env, a_row) == SETTLED
        assert execution_state(env, b_row) == SUBMITTED

    def test_tenant_a_cannot_write_ledger_for_tenant_b_execution(
        self, env: Env
    ) -> None:
        victim = insert_execution(env, env.tenant_b)
        with pytest.raises(TenantResourceNotFound):
            env.gateway.scoped_append_ledger_entry(
                env.ctx_a,
                victim,
                "SETTLEMENT_CONFIRMED",
                Decimal("100.00"),
                "USD",
                NOW,
            )
        assert row_count(env, "transaction_ledger_entries") == 0

    def test_ledger_write_uses_tenant_from_verified_context(self, env: Env) -> None:
        own = insert_execution(env, env.tenant_a)
        entry_id = env.gateway.scoped_append_ledger_entry(
            env.ctx_a, own, "SETTLEMENT_CONFIRMED", Decimal("100.00"), "usd", NOW
        )
        row = env.connection.execute(
            "SELECT tenant_id, transaction_execution_id, entry_type, amount, "
            "currency FROM transaction_ledger_entries WHERE entry_id = ?",
            (str(entry_id),),
        ).fetchone()
        assert row == (
            str(env.tenant_a),
            str(own),
            "SETTLEMENT_CONFIRMED",
            "100.00",
            "USD",
        )

    def test_ledger_write_rejects_bad_inputs(self, env: Env) -> None:
        own = insert_execution(env, env.tenant_a)
        with pytest.raises(TenantIsolationError):
            env.gateway.scoped_append_ledger_entry(
                env.ctx_a, own, "", Decimal("1"), "USD", NOW
            )
        with pytest.raises(TenantIsolationError):
            env.gateway.scoped_append_ledger_entry(
                env.ctx_a, own, "X", 1.5, "USD", NOW  # type: ignore[arg-type]
            )
        with pytest.raises(TenantIsolationError):
            env.gateway.scoped_append_ledger_entry(
                env.ctx_a, own, "X", Decimal("NaN"), "USD", NOW
            )
        with pytest.raises(TenantIsolationError):
            env.gateway.scoped_append_ledger_entry(
                env.ctx_a, own, "X", Decimal("1"), "", NOW
            )
        assert row_count(env, "transaction_ledger_entries") == 0


class TestCrossTenantReconciliation:
    def test_tenant_a_cannot_reconcile_tenant_b_statement(self, env: Env) -> None:
        b_statement = insert_statement(env, env.tenant_b, line_count=2)

        assert env.gateway.scoped_reconcile(env.ctx_a, b_statement, NOW) is False

        assert row_count(env, "reconciliation_cases") == 0
        assert row_count(env, "transaction_ledger_entries") == 0

    def test_foreign_statement_equals_missing_statement(self, env: Env) -> None:
        b_statement = insert_statement(env, env.tenant_b, line_count=2)
        foreign = env.gateway.scoped_reconcile(env.ctx_a, b_statement, NOW)
        missing = env.gateway.scoped_reconcile(env.ctx_a, uuid.uuid4(), NOW)
        assert foreign is missing is False

    def test_owner_can_reconcile_complete_statement(self, env: Env) -> None:
        a_statement = insert_statement(env, env.tenant_a, line_count=3)
        b_statement = insert_statement(env, env.tenant_b, line_count=2)
        assert env.gateway.scoped_reconcile(env.ctx_a, a_statement, NOW) is True
        assert env.gateway.scoped_reconcile(env.ctx_b, b_statement, NOW) is True

    def test_incomplete_statement_fails_closed(self, env: Env) -> None:
        truncated = insert_statement(
            env, env.tenant_a, line_count=3, entry_count=2
        )
        assert env.gateway.scoped_reconcile(env.ctx_a, truncated, NOW) is False

    def test_foreign_entries_injected_into_statement_do_not_count(
        self, env: Env
    ) -> None:
        # Two declared lines, but both entries are stamped with tenant B.
        poisoned = insert_statement(
            env,
            env.tenant_a,
            line_count=2,
            entry_count=2,
            entry_tenant_id=env.tenant_b,
        )
        assert env.gateway.scoped_reconcile(env.ctx_a, poisoned, NOW) is False

    def test_reconcile_never_writes(self, env: Env) -> None:
        a_statement = insert_statement(env, env.tenant_a, line_count=2)
        env.gateway.scoped_reconcile(env.ctx_a, a_statement, NOW)
        assert row_count(env, "reconciliation_cases") == 0
        assert row_count(env, "transaction_ledger_entries") == 0

    def test_non_uuid_statement_id_is_refused(self, env: Env) -> None:
        with pytest.raises(TenantIsolationError):
            env.gateway.scoped_reconcile(env.ctx_a, "stmt-1", NOW)  # type: ignore[arg-type]


class TestCrossTenantOutbox:
    def test_tenant_a_cannot_access_tenant_b_outbox_entries(self, env: Env) -> None:
        b_execution = insert_execution(env, env.tenant_b)
        b_outbox = insert_outbox(env, env.tenant_b, b_execution)

        assert (
            env.gateway.scoped_query(env.ctx_a, "transaction_outbox", b_outbox, NOW)
            is None
        )
        assert (
            env.gateway.scoped_lock(env.ctx_a, "transaction_outbox", b_outbox, NOW)
            is None
        )
        with pytest.raises(TenantIsolationError):
            lookup(env, env.ctx_a, "transaction_outbox", b_outbox)

    def test_outbox_denial_matches_missing_entry(self, env: Env) -> None:
        b_outbox = insert_outbox(env, env.tenant_b)
        foreign = capture(
            lambda: lookup(env, env.ctx_a, "transaction_outbox", b_outbox)
        )
        missing = capture(
            lambda: lookup(env, env.ctx_a, "transaction_outbox", uuid.uuid4())
        )
        assert type(foreign) is type(missing) is TenantResourceNotFound
        assert foreign.args == missing.args

    def test_owner_reads_own_outbox_entry(self, env: Env) -> None:
        a_outbox = insert_outbox(env, env.tenant_a)
        row = lookup(env, env.ctx_a, "transaction_outbox", a_outbox)
        assert row["outbox_id"] == str(a_outbox)
        assert row["tenant_id"] == str(env.tenant_a)

    def test_outbox_row_is_untouched_by_attack(self, env: Env) -> None:
        b_outbox = insert_outbox(env, env.tenant_b)
        before = env.connection.execute(
            "SELECT * FROM transaction_outbox WHERE outbox_id = ?", (str(b_outbox),)
        ).fetchone()
        env.gateway.scoped_lock(env.ctx_a, "transaction_outbox", b_outbox, NOW)
        after = env.connection.execute(
            "SELECT * FROM transaction_outbox WHERE outbox_id = ?", (str(b_outbox),)
        ).fetchone()
        assert before == after


# ---------------------------------------------------------------------------
# 4. Webhook tenant substitution attack
# ---------------------------------------------------------------------------


class TestWebhookTenantSubstitution:
    def test_payload_claiming_other_tenant_is_rejected(self, env: Env) -> None:
        payload = {"tenant_id": str(env.tenant_b), "status": "settled"}

        with pytest.raises(TenantIsolationError) as exc_info:
            receive_webhook(env, env.ctx_a, payload)

        assert str(env.tenant_b) not in str(exc_info.value)
        assert str(env.tenant_a) not in str(exc_info.value)
        assert row_count(env, "webhook_events") == 0

    def test_matching_tenant_claim_is_accepted_and_stored_under_context_tenant(
        self, env: Env
    ) -> None:
        payload = {"tenant_id": str(env.tenant_a), "status": "settled"}
        event_id = receive_webhook(env, env.ctx_a, payload)

        row = env.connection.execute(
            "SELECT tenant_id FROM webhook_events WHERE event_id = ?",
            (str(event_id),),
        ).fetchone()
        assert row[0] == str(env.tenant_a)

    def test_uppercase_uuid_for_same_tenant_is_accepted(self, env: Env) -> None:
        payload = {"tenant_id": str(env.tenant_a).upper()}
        receive_webhook(env, env.ctx_a, payload)
        assert row_count(env, "webhook_events") == 1

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"tenant_id": None},
            {"tenant_id": ""},
            {"tenant_id": "not-a-uuid"},
            {"tenant_id": "00000000-0000-0000-0000-000000000000"},
            {"tenant_id": ["a", "b"]},
        ],
        ids=["absent", "null", "empty", "garbage", "nil-uuid", "list"],
    )
    def test_missing_or_malformed_tenant_claim_fails_closed(
        self, env: Env, payload: dict[str, Any]
    ) -> None:
        with pytest.raises(TenantIsolationError):
            receive_webhook(env, env.ctx_a, payload)
        assert row_count(env, "webhook_events") == 0

    def test_untrusted_context_cannot_receive_webhooks(self, env: Env) -> None:
        payload = {"tenant_id": str(env.tenant_a)}
        with pytest.raises(TenantContextInvalid):
            receive_webhook(env, untrusted_context(env.tenant_a), payload)
        assert row_count(env, "webhook_events") == 0

    def test_expired_context_cannot_receive_webhooks(self, env: Env) -> None:
        expired = _issue(
            env.issuer,
            env.capability,
            env.tenant_a,
            issued_at=NOW - timedelta(hours=2),
            expires_at=NOW - timedelta(hours=1),
        )
        with pytest.raises(TenantContextExpired):
            receive_webhook(env, expired, {"tenant_id": str(env.tenant_a)})
        assert row_count(env, "webhook_events") == 0

    def test_tenant_a_cannot_read_tenant_b_webhook_events(self, env: Env) -> None:
        b_event = insert_webhook_event(env, env.tenant_b)
        assert (
            env.gateway.scoped_query(env.ctx_a, "webhook_events", b_event, NOW)
            is None
        )
        with pytest.raises(TenantResourceNotFound):
            lookup(env, env.ctx_a, "webhook_events", b_event)

    def test_substitution_attempt_leaves_victim_state_untouched(
        self, env: Env
    ) -> None:
        victim = insert_execution(env, env.tenant_b, state=SUBMITTED)
        payload = {
            "tenant_id": str(env.tenant_b),
            "transaction_execution_id": str(victim),
            "status": "settled",
        }
        with pytest.raises(TenantIsolationError):
            receive_webhook(env, env.ctx_a, payload)
        assert execution_state(env, victim) == SUBMITTED
        assert row_count(env, "transaction_ledger_entries") == 0


# ---------------------------------------------------------------------------
# 5. Idempotency collision isolation
# ---------------------------------------------------------------------------


class TestIdempotencyCollisionIsolation:
    KEY = "KEY-123"

    def test_identical_key_in_two_tenants_does_not_collide(self, env: Env) -> None:
        exec_a = insert_execution(
            env, env.tenant_a, amount="10.00", idempotency_key=self.KEY
        )
        exec_b = insert_execution(
            env, env.tenant_b, amount="20.00", idempotency_key=self.KEY
        )

        assert exec_a != exec_b
        assert find_execution_by_idempotency_key(env, env.ctx_a, self.KEY) == str(
            exec_a
        )
        assert find_execution_by_idempotency_key(env, env.ctx_b, self.KEY) == str(
            exec_b
        )

        row_a = lookup(env, env.ctx_a, "transaction_executions", exec_a)
        row_b = lookup(env, env.ctx_b, "transaction_executions", exec_b)
        assert row_a["amount"] == "10.00"
        assert row_b["amount"] == "20.00"

    def test_same_key_within_one_tenant_still_collides(self, env: Env) -> None:
        insert_execution(env, env.tenant_a, idempotency_key=self.KEY)
        with pytest.raises(sqlite3.IntegrityError):
            insert_execution(env, env.tenant_a, idempotency_key=self.KEY)
        env.connection.rollback()
        assert row_count(env, "transaction_executions") == 1

    def test_tenants_operate_independently_under_shared_key(self, env: Env) -> None:
        exec_a = insert_execution(
            env, env.tenant_a, state=SUBMITTED, idempotency_key=self.KEY
        )
        exec_b = insert_execution(
            env, env.tenant_b, state=SUBMITTED, idempotency_key=self.KEY
        )

        assert env.gateway.scoped_transition(env.ctx_a, exec_a, SETTLED, NOW)

        assert execution_state(env, exec_a) == SETTLED
        assert execution_state(env, exec_b) == SUBMITTED

        assert env.gateway.scoped_transition(env.ctx_b, exec_b, SETTLED, NOW)
        assert execution_state(env, exec_b) == SETTLED

    def test_ledger_writes_under_shared_key_stay_per_tenant(self, env: Env) -> None:
        exec_a = insert_execution(env, env.tenant_a, idempotency_key=self.KEY)
        exec_b = insert_execution(env, env.tenant_b, idempotency_key=self.KEY)

        env.gateway.scoped_append_ledger_entry(
            env.ctx_a, exec_a, "SETTLEMENT_CONFIRMED", Decimal("10.00"), "USD", NOW
        )
        env.gateway.scoped_append_ledger_entry(
            env.ctx_b, exec_b, "SETTLEMENT_CONFIRMED", Decimal("20.00"), "USD", NOW
        )

        rows = dict(
            env.connection.execute(
                "SELECT tenant_id, amount FROM transaction_ledger_entries"
            ).fetchall()
        )
        assert rows == {str(env.tenant_a): "10.00", str(env.tenant_b): "20.00"}

    def test_key_lookup_never_resolves_to_other_tenants_execution(
        self, env: Env
    ) -> None:
        exec_b = insert_execution(env, env.tenant_b, idempotency_key=self.KEY)
        assert find_execution_by_idempotency_key(env, env.ctx_a, self.KEY) is None
        assert find_execution_by_idempotency_key(env, env.ctx_b, self.KEY) == str(
            exec_b
        )
        with pytest.raises(TenantResourceNotFound):
            lookup(env, env.ctx_a, "transaction_executions", exec_b)


# ---------------------------------------------------------------------------
# 6. RLS session command generation
# ---------------------------------------------------------------------------


class TestRlsSessionCommandGeneration:
    def test_generates_set_local_statement(self, env: Env) -> None:
        statement = generate_rls_session_statement(env.tenant_a)
        assert statement == f"SET LOCAL app.tenant_id = '{env.tenant_a}'"

    def test_gateway_method_matches_module_function(self, env: Env) -> None:
        assert env.gateway.generate_rls_session_statement(
            env.tenant_b
        ) == generate_rls_session_statement(env.tenant_b)

    def test_statement_uses_canonical_lowercase_uuid(self) -> None:
        tenant = uuid.UUID("AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE")
        assert (
            generate_rls_session_statement(tenant)
            == "SET LOCAL app.tenant_id = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'"
        )

    @pytest.mark.parametrize(
        "bad",
        [
            None,
            "",
            "   ",
            "not-a-uuid",
            "' ; DROP TABLE transaction_executions; --",
            str(uuid.uuid4()),
            0,
            uuid.UUID(int=0),
        ],
        ids=[
            "none",
            "empty",
            "blank",
            "garbage",
            "sql-injection",
            "uuid-as-string",
            "int",
            "nil-uuid",
        ],
    )
    def test_denies_null_empty_or_invalid_tenant_id(self, bad: Any) -> None:
        with pytest.raises(TenantIsolationError):
            generate_rls_session_statement(bad)

    def test_gateway_method_denies_null_tenant(self, env: Env) -> None:
        with pytest.raises(TenantIsolationError):
            env.gateway.generate_rls_session_statement(None)  # type: ignore[arg-type]
        with pytest.raises(TenantIsolationError):
            env.gateway.generate_rls_session_statement("")  # type: ignore[arg-type]

    def test_postgres_style_connection_binds_rls_before_any_query(
        self, env: Env
    ) -> None:
        fake = FakePgConnection()
        gateway = TenantScopedGateway(lambda: fake)
        target = uuid.uuid4()

        result = gateway.scoped_query(
            env.ctx_a, "transaction_executions", target, NOW
        )

        assert result is None
        assert len(fake.executed) == 2
        first_sql, _ = fake.executed[0]
        assert first_sql == f"SET LOCAL app.tenant_id = '{env.tenant_a}'"
        second_sql, second_params = fake.executed[1]
        assert "tenant_id = %s" in second_sql
        assert "?" not in second_sql
        assert tuple(second_params) == (str(env.tenant_a), str(target))
        assert fake.committed and not fake.rolled_back and fake.closed

    def test_rls_binds_context_tenant_never_a_foreign_one(self, env: Env) -> None:
        fake = FakePgConnection()
        gateway = TenantScopedGateway(lambda: fake)
        gateway.scoped_query(
            env.ctx_a, "transaction_executions", uuid.uuid4(), NOW
        )
        statements = [sql for sql, _ in fake.executed]
        assert all(str(env.tenant_b) not in sql for sql in statements)

    def test_postgres_style_lock_and_transition_use_for_update(
        self, env: Env
    ) -> None:
        lock_conn = FakePgConnection()
        TenantScopedGateway(lambda: lock_conn).scoped_lock(
            env.ctx_a, "transaction_executions", uuid.uuid4(), NOW
        )
        assert lock_conn.executed[0][0].startswith("SET LOCAL app.tenant_id")
        assert "FOR UPDATE" in lock_conn.executed[1][0]

        transition_conn = FakePgConnection()
        outcome = TenantScopedGateway(lambda: transition_conn).scoped_transition(
            env.ctx_a, uuid.uuid4(), SETTLED, NOW
        )
        assert outcome is False
        assert transition_conn.executed[0][0].startswith("SET LOCAL app.tenant_id")
        assert "FOR UPDATE" in transition_conn.executed[1][0]
        assert "tenant_id = %s" in transition_conn.executed[1][0]

    def test_rls_session_can_be_disabled_explicitly(self, env: Env) -> None:
        fake = FakePgConnection()
        gateway = TenantScopedGateway(lambda: fake, enable_rls_session=False)
        gateway.scoped_query(env.ctx_a, "transaction_executions", uuid.uuid4(), NOW)
        assert len(fake.executed) == 1
        assert not fake.executed[0][0].startswith("SET LOCAL")

    def test_sqlite_connection_does_not_receive_rls_statement(self, env: Env) -> None:
        traced: list[str] = []
        env.connection.set_trace_callback(traced.append)
        try:
            env.gateway.scoped_query(
                env.ctx_a, "transaction_executions", uuid.uuid4(), NOW
            )
        finally:
            env.connection.set_trace_callback(None)
        assert not any(s.upper().startswith("SET LOCAL") for s in traced)

    def test_database_failure_rolls_back_and_closes(self, env: Env) -> None:
        fake = FakePgConnection(fail_on="SELECT")
        gateway = TenantScopedGateway(lambda: fake)
        with pytest.raises(RuntimeError):
            gateway.scoped_query(
                env.ctx_a, "transaction_executions", uuid.uuid4(), NOW
            )
        assert fake.rolled_back
        assert not fake.committed
        assert fake.closed

    def test_rejected_context_never_opens_a_postgres_connection(
        self, env: Env
    ) -> None:
        opened = {"count": 0}

        def factory() -> FakePgConnection:
            opened["count"] += 1
            return FakePgConnection()

        gateway = TenantScopedGateway(factory)
        with pytest.raises(TenantContextInvalid):
            gateway.scoped_query(None, "transaction_executions", uuid.uuid4(), NOW)  # type: ignore[arg-type]
        with pytest.raises(TenantContextInvalid):
            gateway.scoped_query(
                untrusted_context(env.tenant_a),
                "transaction_executions",
                uuid.uuid4(),
                NOW,
            )
        assert opened["count"] == 0


# ---------------------------------------------------------------------------
# Query-level tenant forcing
# ---------------------------------------------------------------------------


class TestQueryLevelTenantForcing:
    def test_every_gateway_statement_is_forced_to_the_context_tenant(
        self, env: Env
    ) -> None:
        seeded_a = seed_all(env, env.tenant_a)
        seeded_b = seed_all(env, env.tenant_b)
        a_execution = insert_execution(env, env.tenant_a, state=SUBMITTED)
        b_tenant_literal = str(env.tenant_b)

        traced: list[str] = []
        env.connection.set_trace_callback(traced.append)
        try:
            env.gateway.scoped_query(
                env.ctx_a,
                "transaction_executions",
                seeded_a["transaction_executions"],
                NOW,
            )
            env.gateway.scoped_lock(
                env.ctx_a,
                "transaction_approvals",
                seeded_a["transaction_approvals"],
                NOW,
            )
            env.gateway.scoped_transition(env.ctx_a, a_execution, SETTLED, NOW)
            env.gateway.scoped_append_ledger_entry(
                env.ctx_a,
                seeded_a["transaction_executions"],
                "SETTLEMENT_CONFIRMED",
                Decimal("5.00"),
                "USD",
                NOW,
            )
            env.gateway.scoped_reconcile(
                env.ctx_a, seeded_a["settlement_statements"], NOW
            )
            # Attack traffic: B's identifiers presented under A's context.
            env.gateway.scoped_query(
                env.ctx_a,
                "transaction_executions",
                seeded_b["transaction_executions"],
                NOW,
            )
            env.gateway.scoped_transition(
                env.ctx_a, seeded_b["transaction_executions"], SETTLED, NOW
            )
            env.gateway.scoped_reconcile(
                env.ctx_a, seeded_b["settlement_statements"], NOW
            )
        finally:
            env.connection.set_trace_callback(None)

        data_statements = [
            s
            for s in traced
            if s.lstrip().upper().startswith(("SELECT", "UPDATE", "INSERT"))
        ]
        assert data_statements

        for statement in data_statements:
            assert "tenant_id" in statement
            assert b_tenant_literal not in statement
            if statement.lstrip().upper().startswith(("SELECT", "UPDATE")):
                assert (
                    "tenant_id = ?" in statement
                    or f"tenant_id = '{env.tenant_a}'" in statement
                )

    def test_attack_traffic_changes_nothing_in_victim_tenant(self, env: Env) -> None:
        seeded_b = seed_all(env, env.tenant_b)
        snapshot = {
            table: env.connection.execute(
                f"SELECT * FROM {table} ORDER BY 1"
            ).fetchall()
            for table in ALL_TABLES
        }

        for table, entity_id in seeded_b.items():
            env.gateway.scoped_query(env.ctx_a, table, entity_id, NOW)
            env.gateway.scoped_lock(env.ctx_a, table, entity_id, NOW)
        env.gateway.scoped_transition(
            env.ctx_a, seeded_b["transaction_executions"], SETTLED, NOW
        )
        env.gateway.scoped_reconcile(
            env.ctx_a, seeded_b["settlement_statements"], NOW
        )
        with pytest.raises(TenantResourceNotFound):
            env.gateway.scoped_append_ledger_entry(
                env.ctx_a,
                seeded_b["transaction_executions"],
                "SETTLEMENT_CONFIRMED",
                Decimal("1.00"),
                "USD",
                NOW,
            )

        after = {
            table: env.connection.execute(
                f"SELECT * FROM {table} ORDER BY 1"
            ).fetchall()
            for table in ALL_TABLES
        }
        assert after == snapshot