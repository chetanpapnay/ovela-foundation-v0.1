"""
DurableApprovalStore tests.

Backends
--------
- Default: a temporary SQLite database file (no setup, no network).
- OVELA_TEST_DATABASE_URL=postgresql://user:pass@host:5432/dbname uses a real
  PostgreSQL database (psycopg or psycopg2 required). Use a DEDICATED TEST
  DATABASE: the fixture creates the approval_evidence table if it is missing
  and deletes only the rows belonging to tenants created by each test.
- OVELA_TEST_DATABASE_URL=sqlite:///path/to/file.db uses that SQLite file.

Structure
---------
- TestDurableApprovalStore: database integration tests, marked ``durable``.
- TestFailClosedWithFakeDriver: no database; unmarked so they always run.
"""

from __future__ import annotations

import importlib
import os
import sqlite3
import warnings
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from threading import Barrier
from uuid import UUID, uuid4

import pytest

from app.approval_evidence import (
    ApprovalEvidence,
    ApprovalEvidenceExpired,
    ApprovalEvidenceInvalid,
    _issue_internal_approval_evidence,
)
from app.approval_store import ApprovalStoreError
from app.durable_approval_store import (
    CONSUME_SQL,
    DEFAULT_ISOLATION_STATEMENT,
    DurableApprovalStore,
    _render,
)

# Create the marker without tripping PytestUnknownMarkWarning under -W error.
# (If your pytest config uses --strict-markers, register "durable" there.)
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    durable = pytest.mark.durable

ENV_VAR = "OVELA_TEST_DATABASE_URL"

NOW = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)

_UNSET = object()

_SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS approval_evidence (
    approval_id    TEXT PRIMARY KEY,
    tenant_id      TEXT NOT NULL,
    action_id      TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    subject_id     TEXT NOT NULL,
    destination_id TEXT NOT NULL,
    amount         TEXT NOT NULL,
    currency       TEXT NOT NULL,
    approved_at    TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    consumed_at    TEXT NULL,
    consumed_by    TEXT NULL,
    version        INTEGER NOT NULL DEFAULT 0
)
"""

_POSTGRES_SCHEMA = """
CREATE TABLE IF NOT EXISTS approval_evidence (
    approval_id    VARCHAR(36)   PRIMARY KEY,
    tenant_id      VARCHAR(36)   NOT NULL,
    action_id      VARCHAR(36)   NOT NULL,
    session_id     VARCHAR(36)   NOT NULL,
    subject_id     VARCHAR(36)   NOT NULL,
    destination_id VARCHAR(256)  NOT NULL,
    amount         NUMERIC(38,10) NOT NULL,
    currency       CHAR(3)       NOT NULL,
    approved_at    TIMESTAMP     NOT NULL,
    expires_at     TIMESTAMP     NOT NULL,
    consumed_at    TIMESTAMP     NULL,
    consumed_by    VARCHAR(36)   NULL,
    version        INTEGER       NOT NULL DEFAULT 0
)
"""


# ---------------------------------------------------------------------------
# Test-only DB-API plumbing
# ---------------------------------------------------------------------------


def _adapt_value(value):
    """SQLite cannot bind Decimal/datetime natively: store canonical text."""
    if isinstance(value, Decimal):
        return str(value)

    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S.%f")

    return value


def _adapt_sqlite(params):
    if params is None:
        return None

    if isinstance(params, Mapping):
        return {key: _adapt_value(value) for key, value in params.items()}

    return tuple(_adapt_value(value) for value in params)


class _Cursor:
    """Cursor wrapper: adapts parameters/placeholders and journals rowcounts."""

    def __init__(self, inner, kind, journal):
        self._inner = inner
        self._kind = kind
        self._journal = journal

    @property
    def rowcount(self):
        return self._inner.rowcount

    def execute(self, sql, params=None):
        if self._kind == "postgres":
            sql = sql.replace("?", "%s")
        else:
            params = _adapt_sqlite(params)

        if params is None:
            result = self._inner.execute(sql)
        else:
            result = self._inner.execute(sql, params)

        self._journal.append((sql.split()[0].upper(), self._inner.rowcount))
        return result

    def fetchone(self):
        return self._inner.fetchone()

    def close(self):
        return self._inner.close()


class _Connection:
    def __init__(self, inner, kind, journal):
        self._inner = inner
        self._kind = kind
        self._journal = journal

    def cursor(self):
        return _Cursor(self._inner.cursor(), self._kind, self._journal)

    def commit(self):
        self._inner.commit()

    def rollback(self):
        self._inner.rollback()

    def close(self):
        self._inner.close()


def _postgres_driver():
    for name in ("psycopg", "psycopg2"):
        try:
            return importlib.import_module(name)
        except ImportError:
            continue

    return None


class _Backend:
    """One test database plus an observation journal."""

    def __init__(self, kind: str, target: str, schema: str, isolation):
        self.kind = kind
        self.target = target
        self.isolation = isolation
        self.journal: list[tuple[str, int]] = []
        self.opened = 0
        self._tenants: list[UUID] = []
        self._driver = _postgres_driver() if kind == "postgres" else None

        with closing(self.admin()) as conn:
            cursor = conn.cursor()
            cursor.execute(schema)
            conn.commit()
            cursor.close()

    def _raw(self):
        if self.kind == "sqlite":
            return sqlite3.connect(self.target, timeout=30)

        return self._driver.connect(self.target)

    def factory(self):
        """Connection factory handed to the store (observed)."""
        self.opened += 1
        return _Connection(self._raw(), self.kind, self.journal)

    def admin(self):
        """Unobserved connection for setup, assertions and cleanup."""
        return _Connection(self._raw(), self.kind, [])

    def new_tenant(self) -> UUID:
        tenant = uuid4()
        self._tenants.append(tenant)
        return tenant

    def row(self, approval_id: UUID):
        with closing(self.admin()) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT consumed_at, consumed_by, version "
                "FROM approval_evidence WHERE approval_id = ?",
                (str(approval_id),),
            )
            result = cursor.fetchone()
            cursor.close()

        return result

    def count(self, approval_id: UUID) -> int:
        with closing(self.admin()) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT COUNT(*) FROM approval_evidence WHERE approval_id = ?",
                (str(approval_id),),
            )
            result = cursor.fetchone()[0]
            cursor.close()

        return int(result)

    def raw_consume(
        self,
        approval_id: UUID,
        tenant_id: UUID,
        now: datetime,
        executor_id: UUID | None = None,
    ) -> int:
        """Run the store's real UPDATE directly and return its rowcount."""
        sql, args = _render(
            CONSUME_SQL,
            {
                "now": now.astimezone(timezone.utc).replace(tzinfo=None),
                "executor_id": None if executor_id is None else str(executor_id),
                "approval_id": str(approval_id),
                "tenant_id": str(tenant_id),
            },
            "qmark",
        )

        with closing(self.admin()) as conn:
            cursor = conn.cursor()
            cursor.execute(sql, args)
            rowcount = cursor.rowcount
            conn.commit()
            cursor.close()

        return rowcount

    def updates(self) -> list[int]:
        return [rc for verb, rc in self.journal if verb == "UPDATE"]

    def cleanup(self) -> None:
        if self.kind != "postgres":
            return

        with closing(self.admin()) as conn:
            cursor = conn.cursor()

            for tenant in self._tenants:
                cursor.execute(
                    "DELETE FROM approval_evidence WHERE tenant_id = ?",
                    (str(tenant),),
                )

            conn.commit()
            cursor.close()


@pytest.fixture
def backend(tmp_path):
    url = os.environ.get(ENV_VAR, "").strip()

    if not url:
        instance = _Backend(
            "sqlite",
            str(tmp_path / "approvals.sqlite3"),
            _SQLITE_SCHEMA,
            None,
        )
    elif url.lower().startswith("sqlite:///"):
        instance = _Backend("sqlite", url[len("sqlite:///"):], _SQLITE_SCHEMA, None)
    elif url.lower().startswith(("postgresql://", "postgres://")):
        if _postgres_driver() is None:
            pytest.skip("neither psycopg nor psycopg2 is installed")

        instance = _Backend(
            "postgres",
            url,
            _POSTGRES_SCHEMA,
            DEFAULT_ISOLATION_STATEMENT,
        )
    else:
        pytest.fail(
            f"{ENV_VAR} must start with postgresql://, postgres:// or sqlite:///"
        )

    try:
        yield instance
    finally:
        instance.cleanup()


@pytest.fixture
def store(backend):
    return DurableApprovalStore(
        backend.factory,
        paramstyle="qmark",
        isolation_statement=backend.isolation,
    )


def issue(
    backend: _Backend,
    *,
    tenant_id=_UNSET,
    approved_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> ApprovalEvidence:
    if tenant_id is _UNSET:
        tenant_id = backend.new_tenant()

    return _issue_internal_approval_evidence(
        action_id=uuid4(),
        session_id=uuid4(),
        subject_id=uuid4(),
        destination_id="merchant-1",
        amount=Decimal("100.00"),
        currency="INR",
        approved_at=approved_at or NOW - timedelta(seconds=60),
        expires_at=expires_at or NOW + timedelta(minutes=5),
        tenant_id=tenant_id,
    )


def untrusted_copy(evidence: ApprovalEvidence) -> ApprovalEvidence:
    return ApprovalEvidence(
        approval_id=evidence.approval_id,
        action_id=evidence.action_id,
        session_id=evidence.session_id,
        subject_id=evidence.subject_id,
        destination_id=evidence.destination_id,
        amount=evidence.amount,
        currency=evidence.currency,
        approved_at=evidence.approved_at,
        expires_at=evidence.expires_at,
        tenant_id=evidence.tenant_id,
    )


def race(stores, evidence, tenant_id, workers):
    barrier = Barrier(workers)
    executor_ids = [uuid4() for _ in range(workers)]

    def attempt(index):
        barrier.wait(timeout=30)
        executor_id = executor_ids[index]
        chosen = stores[index % len(stores)]
        return executor_id, chosen.consume(
            evidence, NOW, tenant_id=tenant_id, executor_id=executor_id
        )

    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(attempt, range(workers)))


# ---------------------------------------------------------------------------
# Database integration tests
# ---------------------------------------------------------------------------


@durable
class TestDurableApprovalStore:
    # -- registration -----------------------------------------------------

    def test_register_persists_an_unconsumed_row(self, backend, store):
        evidence = issue(backend)

        store.register(evidence)

        consumed_at, consumed_by, version = backend.row(evidence.approval_id)
        assert consumed_at is None
        assert consumed_by is None
        assert version == 0
        assert store.is_consumed(evidence.approval_id) is False

    def test_duplicate_registration_is_rejected_and_row_unchanged(
        self, backend, store
    ):
        evidence = issue(backend)
        store.register(evidence)

        with pytest.raises(ApprovalEvidenceInvalid):
            store.register(evidence)

        assert backend.count(evidence.approval_id) == 1
        assert backend.row(evidence.approval_id)[2] == 0

    def test_registration_rejects_tenantless_evidence_without_db_work(
        self, backend, store
    ):
        evidence = issue(backend, tenant_id=None)

        with pytest.raises(ApprovalEvidenceInvalid):
            store.register(evidence)

        assert backend.opened == 0
        assert backend.journal == []
        assert backend.count(evidence.approval_id) == 0

    def test_registration_rejects_untrusted_evidence_without_db_work(
        self, backend, store
    ):
        evidence = untrusted_copy(issue(backend))

        with pytest.raises(ApprovalEvidenceInvalid):
            store.register(evidence)

        assert backend.opened == 0
        assert backend.count(evidence.approval_id) == 0

    @pytest.mark.parametrize("value", [None, "evidence", object()])
    def test_registration_rejects_non_evidence(self, backend, store, value):
        with pytest.raises(ApprovalEvidenceInvalid):
            store.register(value)

        assert backend.opened == 0

    def test_concurrent_registration_has_exactly_one_winner(
        self, backend, store
    ):
        evidence = issue(backend)
        workers = 8
        barrier = Barrier(workers)

        def attempt(_):
            barrier.wait(timeout=30)

            try:
                store.register(evidence)
                return "ok"
            except (ApprovalEvidenceInvalid, ApprovalStoreError):
                return "rejected"

        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(attempt, range(workers)))

        assert results.count("ok") == 1
        assert results.count("rejected") == workers - 1
        assert backend.count(evidence.approval_id) == 1

    # -- tenant boundary --------------------------------------------------

    @pytest.mark.parametrize(
        "case",
        ["evidence_tenantless", "argument_tenantless", "both_tenantless"],
    )
    def test_tenantless_consumption_fails_closed_without_db_work(
        self, backend, store, case
    ):
        if case == "evidence_tenantless":
            evidence, tenant = issue(backend, tenant_id=None), uuid4()
        elif case == "argument_tenantless":
            evidence = issue(backend)
            tenant = None
        else:
            evidence, tenant = issue(backend, tenant_id=None), None

        with pytest.raises(ApprovalEvidenceInvalid):
            store.consume(evidence, NOW, tenant_id=tenant)

        assert backend.opened == 0
        assert backend.journal == []

    def test_cross_tenant_consumption_is_rejected_and_row_untouched(
        self, backend, store
    ):
        evidence = issue(backend)
        store.register(evidence)
        other_tenant = backend.new_tenant()

        with pytest.raises(ApprovalEvidenceInvalid):
            store.consume(evidence, NOW, tenant_id=other_tenant)

        assert backend.updates() == []
        assert backend.row(evidence.approval_id)[0] is None

    def test_tenant_argument_must_be_uuid(self, backend, store):
        evidence = issue(backend)

        with pytest.raises(TypeError):
            store.consume(evidence, NOW, tenant_id="tenant")  # type: ignore[arg-type]

    def test_sql_tenant_guard_rejects_substituted_tenant(self, backend, store):
        """Even trusted-looking evidence cannot consume another tenant's row."""
        evidence = issue(backend)
        store.register(evidence)
        attacker_tenant = backend.new_tenant()
        forged = replace(evidence, tenant_id=attacker_tenant)

        assert forged.is_trusted() is True
        assert store.consume(forged, NOW, tenant_id=attacker_tenant) is False
        assert backend.updates() == [0]
        assert backend.row(evidence.approval_id)[0] is None

        assert store.consume(evidence, NOW, tenant_id=evidence.tenant_id) is True

    def test_raw_update_with_wrong_tenant_matches_no_row(self, backend, store):
        evidence = issue(backend)
        store.register(evidence)

        rowcount = backend.raw_consume(
            evidence.approval_id, backend.new_tenant(), NOW
        )

        assert rowcount == 0
        assert backend.row(evidence.approval_id)[0] is None

    def test_tenants_are_independent(self, backend, store):
        first = issue(backend)
        second = issue(backend)
        store.register(first)
        store.register(second)

        assert store.consume(first, NOW, tenant_id=first.tenant_id) is True

        assert store.is_consumed(second.approval_id) is False
        assert store.consume(second, NOW, tenant_id=second.tenant_id) is True

    # -- atomic single use ------------------------------------------------

    def test_first_consume_rowcount_is_one_and_replay_is_zero(
        self, backend, store
    ):
        evidence = issue(backend)
        executor_id = uuid4()
        store.register(evidence)

        first = store.consume(
            evidence, NOW, tenant_id=evidence.tenant_id, executor_id=executor_id
        )
        after_first = backend.row(evidence.approval_id)
        replay = store.consume(
            evidence, NOW, tenant_id=evidence.tenant_id, executor_id=uuid4()
        )
        after_replay = backend.row(evidence.approval_id)

        assert first is True
        assert replay is False
        assert backend.updates() == [1, 0]

        assert after_first[0] is not None
        assert after_first[1] == str(executor_id)
        assert after_first[2] == 1
        assert after_replay == after_first
        assert store.is_consumed(evidence.approval_id) is True

    def test_consuming_unregistered_evidence_returns_false(self, backend, store):
        evidence = issue(backend)

        assert store.consume(evidence, NOW, tenant_id=evidence.tenant_id) is False
        assert backend.updates() == [0]

    def test_consume_without_executor_leaves_consumed_by_null(
        self, backend, store
    ):
        evidence = issue(backend)
        store.register(evidence)

        assert store.consume(evidence, NOW, tenant_id=evidence.tenant_id) is True

        consumed_at, consumed_by, version = backend.row(evidence.approval_id)
        assert consumed_at is not None
        assert consumed_by is None
        assert version == 1

    def test_executor_id_must_be_uuid(self, backend, store):
        evidence = issue(backend)

        with pytest.raises(TypeError):
            store.consume(
                evidence,
                NOW,
                tenant_id=evidence.tenant_id,
                executor_id="worker-1",  # type: ignore[arg-type]
            )

    def test_untrusted_evidence_cannot_be_consumed(self, backend, store):
        evidence = untrusted_copy(issue(backend))

        with pytest.raises(ApprovalEvidenceInvalid):
            store.consume(evidence, NOW, tenant_id=evidence.tenant_id)

        assert backend.updates() == []

    def test_is_consumed_requires_uuid_and_unknown_is_false(self, backend, store):
        with pytest.raises(TypeError):
            store.is_consumed("not-a-uuid")  # type: ignore[arg-type]

        assert store.is_consumed(uuid4()) is False

    # -- expiration -------------------------------------------------------

    @pytest.mark.parametrize("offset", [timedelta(0), timedelta(seconds=1)])
    def test_expired_evidence_is_rejected_before_the_database(
        self, backend, store, offset
    ):
        evidence = issue(backend)
        store.register(evidence)

        with pytest.raises(ApprovalEvidenceExpired):
            store.consume(
                evidence,
                evidence.expires_at + offset,
                tenant_id=evidence.tenant_id,
            )

        assert backend.updates() == []
        assert backend.row(evidence.approval_id)[0] is None

    def test_registered_already_expired_evidence_cannot_be_consumed(
        self, backend, store
    ):
        evidence = issue(
            backend,
            approved_at=NOW - timedelta(minutes=10),
            expires_at=NOW - timedelta(minutes=5),
        )
        store.register(evidence)

        with pytest.raises(ApprovalEvidenceExpired):
            store.consume(evidence, NOW, tenant_id=evidence.tenant_id)

        assert backend.row(evidence.approval_id)[0] is None

    @pytest.mark.parametrize("offset", [timedelta(0), timedelta(seconds=1)])
    def test_sql_expiry_guard_matches_no_row_when_not_before_expiry(
        self, backend, store, offset
    ):
        """expires_at > now is strict, enforced by the UPDATE itself."""
        evidence = issue(backend)
        store.register(evidence)

        rowcount = backend.raw_consume(
            evidence.approval_id,
            evidence.tenant_id,
            evidence.expires_at + offset,
        )

        assert rowcount == 0
        assert backend.row(evidence.approval_id)[0] is None

        assert store.consume(evidence, NOW, tenant_id=evidence.tenant_id) is True

    def test_future_dated_evidence_is_rejected(self, backend, store):
        evidence = issue(
            backend,
            approved_at=NOW + timedelta(hours=1),
            expires_at=NOW + timedelta(hours=2),
        )
        store.register(evidence)

        with pytest.raises(ApprovalEvidenceInvalid):
            store.consume(evidence, NOW, tenant_id=evidence.tenant_id)

        assert backend.updates() == []

    # -- concurrency ------------------------------------------------------

    def test_concurrent_consumers_exactly_one_succeeds(self, backend, store):
        evidence = issue(backend)
        store.register(evidence)
        workers = 16

        results = race([store], evidence, evidence.tenant_id, workers)

        winners = [executor for executor, won in results if won is True]
        losers = [executor for executor, won in results if won is False]

        assert len(winners) == 1
        assert len(losers) == workers - 1

        updates = backend.updates()
        assert updates.count(1) == 1
        assert updates.count(0) == workers - 1

        consumed_at, consumed_by, version = backend.row(evidence.approval_id)
        assert consumed_at is not None
        assert consumed_by == str(winners[0])
        assert version == 1

    def test_two_independent_store_instances_cannot_both_consume(self, backend):
        """Simulates two workers sharing one database."""
        stores = [
            DurableApprovalStore(
                backend.factory, isolation_statement=backend.isolation
            )
            for _ in range(2)
        ]
        evidence = issue(backend)
        stores[0].register(evidence)

        results = race(stores, evidence, evidence.tenant_id, 16)

        assert [won for _, won in results].count(True) == 1
        assert [won for _, won in results].count(False) == 15
        assert backend.row(evidence.approval_id)[2] == 1

    def test_each_approval_has_exactly_one_winner_under_load(self, backend, store):
        approvals = [issue(backend) for _ in range(6)]

        for evidence in approvals:
            store.register(evidence)

        attempts = [evidence for evidence in approvals for _ in range(4)]
        barrier = Barrier(len(attempts))

        def attempt(evidence):
            barrier.wait(timeout=30)
            return evidence.approval_id, store.consume(
                evidence, NOW, tenant_id=evidence.tenant_id, executor_id=uuid4()
            )

        with ThreadPoolExecutor(max_workers=len(attempts)) as pool:
            results = list(pool.map(attempt, attempts))

        for evidence in approvals:
            outcomes = [
                won for approval_id, won in results
                if approval_id == evidence.approval_id
            ]
            assert outcomes.count(True) == 1
            assert outcomes.count(False) == 3

    # -- parameter style --------------------------------------------------

    def test_named_paramstyle_works_on_sqlite(self, backend):
        if backend.kind != "sqlite":
            pytest.skip("named parameters are exercised on SQLite only")

        named_store = DurableApprovalStore(
            backend.factory, paramstyle="named", isolation_statement=None
        )
        evidence = issue(backend)

        named_store.register(evidence)

        assert named_store.consume(
            evidence, NOW, tenant_id=evidence.tenant_id
        ) is True
        assert named_store.consume(
            evidence, NOW, tenant_id=evidence.tenant_id
        ) is False


# ---------------------------------------------------------------------------
# Fail-closed behavior with a fake DB-API driver (no database, always runs)
# ---------------------------------------------------------------------------


class _FakeCursor:
    def __init__(self, connection):
        self._connection = connection
        self.rowcount = -1

    def execute(self, sql, params=None):
        self._connection.statements.append((sql, params))

        if self._connection.execute_error is not None and not sql.startswith("SET"):
            raise self._connection.execute_error

        self.rowcount = self._connection.rowcount

    def fetchone(self):
        return self._connection.row

    def close(self):
        self._connection.events.append("cursor_close")


class _FakeConnection:
    def __init__(
        self,
        rowcount=1,
        execute_error=None,
        commit_error=None,
        row=None,
    ):
        self.rowcount = rowcount
        self.execute_error = execute_error
        self.commit_error = commit_error
        self.row = row
        self.statements: list[tuple[str, object]] = []
        self.events: list[str] = []

    def cursor(self):
        return _FakeCursor(self)

    def commit(self):
        if self.commit_error is not None:
            raise self.commit_error

        self.events.append("commit")

    def rollback(self):
        self.events.append("rollback")

    def close(self):
        self.events.append("close")


def fake_evidence() -> ApprovalEvidence:
    return _issue_internal_approval_evidence(
        action_id=uuid4(),
        session_id=uuid4(),
        subject_id=uuid4(),
        destination_id="merchant-1",
        amount=Decimal("100.00"),
        currency="INR",
        approved_at=NOW - timedelta(seconds=60),
        expires_at=NOW + timedelta(minutes=5),
        tenant_id=uuid4(),
    )


class TestFailClosedWithFakeDriver:
    def test_consume_issues_read_committed_then_update_then_commits(self):
        connection = _FakeConnection(rowcount=1)
        store = DurableApprovalStore(lambda: connection)
        evidence = fake_evidence()
        executor_id = uuid4()

        assert store.consume(
            evidence, NOW, tenant_id=evidence.tenant_id, executor_id=executor_id
        ) is True

        isolation_sql, _ = connection.statements[0]
        update_sql, params = connection.statements[1]
        naive_now = NOW.replace(tzinfo=None)

        assert isolation_sql == DEFAULT_ISOLATION_STATEMENT
        assert "UPDATE approval_evidence" in update_sql
        assert "consumed_at IS NULL" in update_sql
        assert "expires_at >" in update_sql
        assert "version = version + 1" in update_sql
        assert params == (
            naive_now,
            str(executor_id),
            str(evidence.approval_id),
            str(evidence.tenant_id),
            naive_now,
        )
        assert connection.events == ["commit", "cursor_close", "close"]

    def test_rowcount_zero_returns_false(self):
        connection = _FakeConnection(rowcount=0)
        store = DurableApprovalStore(lambda: connection)
        evidence = fake_evidence()

        assert store.consume(evidence, NOW, tenant_id=evidence.tenant_id) is False

    @pytest.mark.parametrize("rowcount", [2, -1, 99])
    def test_unexpected_rowcount_fails_closed_and_rolls_back(self, rowcount):
        connection = _FakeConnection(rowcount=rowcount)
        store = DurableApprovalStore(lambda: connection)
        evidence = fake_evidence()

        with pytest.raises(ApprovalStoreError):
            store.consume(evidence, NOW, tenant_id=evidence.tenant_id)

        assert "rollback" in connection.events
        assert "commit" not in connection.events

    def test_driver_error_becomes_store_error_without_leaking_details(self):
        connection = _FakeConnection(
            execute_error=RuntimeError("password=hunter2 host=db.internal")
        )
        store = DurableApprovalStore(lambda: connection)
        evidence = fake_evidence()

        with pytest.raises(ApprovalStoreError) as caught:
            store.consume(evidence, NOW, tenant_id=evidence.tenant_id)

        assert "RuntimeError" in str(caught.value)
        assert "hunter2" not in str(caught.value)
        assert "rollback" in connection.events
        assert "commit" not in connection.events

    def test_commit_failure_rolls_back_and_fails_closed(self):
        connection = _FakeConnection(commit_error=RuntimeError("secret"))
        store = DurableApprovalStore(lambda: connection)
        evidence = fake_evidence()

        with pytest.raises(ApprovalStoreError) as caught:
            store.consume(evidence, NOW, tenant_id=evidence.tenant_id)

        assert "secret" not in str(caught.value)
        assert "rollback" in connection.events

    def test_connection_factory_failure_fails_closed(self):
        def broken():
            raise ConnectionError("database unreachable")

        store = DurableApprovalStore(broken)
        evidence = fake_evidence()

        with pytest.raises(ApprovalStoreError):
            store.consume(evidence, NOW, tenant_id=evidence.tenant_id)

    def test_factory_returning_nothing_fails_closed(self):
        store = DurableApprovalStore(lambda: None)
        evidence = fake_evidence()

        with pytest.raises(ApprovalStoreError):
            store.consume(evidence, NOW, tenant_id=evidence.tenant_id)

    def test_shared_connection_is_used_and_not_closed(self):
        connection = _FakeConnection(rowcount=1)
        store = DurableApprovalStore(connection)
        evidence = fake_evidence()

        assert store.consume(evidence, NOW, tenant_id=evidence.tenant_id) is True
        assert "close" not in connection.events

    def test_tenantless_input_never_opens_a_connection(self):
        opened = []

        def factory():
            opened.append(1)
            return _FakeConnection()

        store = DurableApprovalStore(factory)
        evidence = fake_evidence()

        with pytest.raises(ApprovalEvidenceInvalid):
            store.consume(evidence, NOW, tenant_id=None)

        assert opened == []

    def test_is_consumed_reads_the_consumed_at_column(self):
        consumed = DurableApprovalStore(
            lambda: _FakeConnection(row=(NOW,))
        )
        pending = DurableApprovalStore(lambda: _FakeConnection(row=(None,)))
        unknown = DurableApprovalStore(lambda: _FakeConnection(row=None))

        assert consumed.is_consumed(uuid4()) is True
        assert pending.is_consumed(uuid4()) is False
        assert unknown.is_consumed(uuid4()) is False

    def test_register_maps_rowcount_to_outcome(self):
        evidence = fake_evidence()

        DurableApprovalStore(lambda: _FakeConnection(rowcount=1)).register(evidence)

        with pytest.raises(ApprovalEvidenceInvalid):
            DurableApprovalStore(lambda: _FakeConnection(rowcount=0)).register(
                evidence
            )

    def test_constructor_validation(self):
        with pytest.raises(TypeError):
            DurableApprovalStore(42)  # type: ignore[arg-type]

        with pytest.raises(ValueError):
            DurableApprovalStore(lambda: None, paramstyle="pyformat")  # type: ignore[arg-type]

        with pytest.raises(TypeError):
            DurableApprovalStore(lambda: None, isolation_statement=5)  # type: ignore[arg-type]

        DurableApprovalStore(lambda: None, isolation_statement=None)

    @pytest.mark.parametrize(
        "statement",
        [
            "SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED",
            "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE",
            "SET TRANSACTION ISOLATION LEVEL READ COMMITTED; DROP TABLE approval_evidence",
        ],
    )
    def test_isolation_statement_cannot_be_weakened_or_chained(self, statement):
        with pytest.raises(ValueError):
            DurableApprovalStore(lambda: None, isolation_statement=statement)