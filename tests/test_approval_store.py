import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from threading import Barrier
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID, uuid4

import pytest

from app.approval_evidence import (
    ApprovalEvidenceConsumed,
    ApprovalEvidenceInvalid,
    ApprovalEvidenceRegistry,
    _issue_internal_approval_evidence,
)
from app.approval_store import (
    ENV_VAR,
    ApprovalConsumptionStore,
    ApprovalStoreError,
    InMemoryApprovalConsumptionStore,
    SqlServerApprovalConsumptionStore,
)


def _approval():
    now = datetime.now(timezone.utc)
    return _issue_internal_approval_evidence(
        action_id=uuid4(),
        session_id=uuid4(),
        subject_id=uuid4(),
        destination_id="merchant-1",
        amount=Decimal("100.00"),
        currency="INR",
        approved_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(minutes=5),
    )


class _FailingStore(ApprovalConsumptionStore):
    def try_consume(self, approval_id, expires_at):
        raise ApprovalStoreError("simulated outage")

    def is_consumed(self, approval_id):
        raise ApprovalStoreError("simulated outage")


class _AlwaysConsumedStore(ApprovalConsumptionStore):
    def try_consume(self, approval_id, expires_at):
        return False

    def is_consumed(self, approval_id):
        return True


class _NonBooleanStore(ApprovalConsumptionStore):
    def try_consume(self, approval_id, expires_at):
        return "yes"

    def is_consumed(self, approval_id):
        return False


def test_in_memory_store_allows_first_use_only():
    store = InMemoryApprovalConsumptionStore()
    approval_id = uuid4()
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)

    assert store.try_consume(approval_id, expires) is True
    assert store.try_consume(approval_id, expires) is False
    assert store.is_consumed(approval_id) is True


def test_in_memory_store_rejects_non_uuid():
    store = InMemoryApprovalConsumptionStore()

    with pytest.raises(TypeError):
        store.try_consume("not-a-uuid", datetime.now(timezone.utc))


def test_registry_with_store_rejects_second_consumption():
    registry = ApprovalEvidenceRegistry(InMemoryApprovalConsumptionStore())
    approval = _approval()
    now = datetime.now(timezone.utc)

    registry.consume(approval, now=now)

    with pytest.raises(ApprovalEvidenceConsumed):
        registry.consume(approval, now=now)


def test_two_registries_sharing_a_store_cannot_both_consume():
    shared = InMemoryApprovalConsumptionStore()
    first = ApprovalEvidenceRegistry(shared)
    second = ApprovalEvidenceRegistry(shared)
    approval = _approval()
    now = datetime.now(timezone.utc)

    first.consume(approval, now=now)

    with pytest.raises(ApprovalEvidenceConsumed):
        second.consume(approval, now=now)


def test_store_failure_fails_closed_and_does_not_mark_consumed():
    registry = ApprovalEvidenceRegistry(_FailingStore())
    approval = _approval()

    with pytest.raises(ApprovalEvidenceInvalid):
        registry.consume(approval, now=datetime.now(timezone.utc))

    assert approval.approval_id not in registry._consumed


def test_store_reporting_already_consumed_is_rejected():
    registry = ApprovalEvidenceRegistry(_AlwaysConsumedStore())
    approval = _approval()

    with pytest.raises(ApprovalEvidenceConsumed):
        registry.consume(approval, now=datetime.now(timezone.utc))


def test_non_boolean_store_answer_is_not_treated_as_first_use():
    registry = ApprovalEvidenceRegistry(_NonBooleanStore())
    approval = _approval()

    with pytest.raises(ApprovalEvidenceConsumed):
        registry.consume(approval, now=datetime.now(timezone.utc))


def test_registry_rejects_invalid_store_type():
    with pytest.raises(TypeError):
        ApprovalEvidenceRegistry(store=object())


def test_from_environment_without_variable_is_memory_only(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)

    registry = ApprovalEvidenceRegistry.from_environment()

    assert registry._store is None


def test_sql_store_requires_connection_string():
    with pytest.raises(ApprovalStoreError):
        SqlServerApprovalConsumptionStore("")


# ---------------------------------------------------------------------------
# SQL Server integration tests. Run only when OVELA_APPROVAL_DB_CONNECTION
# is set and the database has been created with scripts.setup_approval_db.
# ---------------------------------------------------------------------------

requires_sql = pytest.mark.skipif(
    not os.environ.get(ENV_VAR, "").strip(),
    reason=f"{ENV_VAR} is not set; SQL Server tests skipped",
)


@pytest.fixture
def sql_store():
    store = SqlServerApprovalConsumptionStore(os.environ[ENV_VAR])
    store.create_schema()
    return store


@requires_sql
def test_sql_first_use_succeeds_and_second_fails(sql_store):
    approval_id = uuid4()
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)

    assert sql_store.try_consume(approval_id, expires) is True
    assert sql_store.try_consume(approval_id, expires) is False
    assert sql_store.is_consumed(approval_id) is True


@requires_sql
def test_sql_unknown_approval_is_not_consumed(sql_store):
    assert sql_store.is_consumed(uuid4()) is False


@requires_sql
def test_sql_two_registries_cannot_both_consume(sql_store):
    first = ApprovalEvidenceRegistry(sql_store)
    second = ApprovalEvidenceRegistry(sql_store)
    approval = _approval()
    now = datetime.now(timezone.utc)

    first.consume(approval, now=now)

    with pytest.raises(ApprovalEvidenceConsumed):
        second.consume(approval, now=now)


@requires_sql
def test_sql_concurrent_consumption_has_exactly_one_winner(sql_store):
    approval_id = uuid4()
    expires = datetime.now(timezone.utc) + timedelta(minutes=5)
    workers = 16
    barrier = Barrier(workers)

    def attempt(_):
        barrier.wait()
        return sql_store.try_consume(approval_id, expires)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(attempt, range(workers)))

    assert results.count(True) == 1
    assert results.count(False) == workers - 1


@requires_sql
def test_sql_unreachable_server_fails_closed():
    store = SqlServerApprovalConsumptionStore(
        "DRIVER={ODBC Driver 18 for SQL Server};"
        "SERVER=localhost\\NO_SUCH_INSTANCE;DATABASE=OvelaApprovals;"
        "Trusted_Connection=yes;TrustServerCertificate=yes;"
    )
    registry = ApprovalEvidenceRegistry(store)
    approval = _approval()

    with pytest.raises(ApprovalEvidenceInvalid):
        registry.consume(approval, now=datetime.now(timezone.utc))

    assert approval.approval_id not in registry._consumed