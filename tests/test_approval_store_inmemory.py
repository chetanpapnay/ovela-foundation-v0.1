"""
In-memory approval store tests (no database, no network).

Covers:
- ApprovalStore protocol compliance (nominal and structural)
- registration, single-use consumption, replay rejection
- expiration, not-before and clock-skew handling
- tenant binding semantics
- isolation between approvals and between store instances
- concurrency inside one process
- backward compatibility of ApprovalEvidenceRegistry (M1-M4 contract)
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from threading import Barrier
from uuid import UUID, uuid4

import pytest

from app.approval_evidence import (
    ApprovalEvidence,
    ApprovalEvidenceConsumed,
    ApprovalEvidenceError,
    ApprovalEvidenceExpired,
    ApprovalEvidenceInvalid,
    ApprovalEvidenceRegistry,
    ApprovalStore,
    InMemoryApprovalStore,
    _issue_internal_approval_evidence,
)
from app.approval_store import (
    ApprovalConsumptionStore,
    ApprovalStoreError,
    InMemoryApprovalConsumptionStore,
)
from app.durable_approval_store import DurableApprovalStore

NOW = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)

TENANT_A = UUID(int=1)
TENANT_B = UUID(int=2)


def issue(
    *,
    tenant_id: UUID | None = None,
    approved_at: datetime | None = None,
    expires_at: datetime | None = None,
    amount: Decimal = Decimal("100.00"),
    currency: str = "INR",
    destination_id: str = "merchant-1",
) -> ApprovalEvidence:
    return _issue_internal_approval_evidence(
        action_id=uuid4(),
        session_id=uuid4(),
        subject_id=uuid4(),
        destination_id=destination_id,
        amount=amount,
        currency=currency,
        approved_at=approved_at or NOW - timedelta(seconds=60),
        expires_at=expires_at or NOW + timedelta(minutes=5),
        tenant_id=tenant_id,
    )


def untrusted_copy(evidence: ApprovalEvidence) -> ApprovalEvidence:
    """Structurally identical evidence WITHOUT the issuer marker."""
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


@pytest.fixture
def store() -> InMemoryApprovalStore:
    return InMemoryApprovalStore()


@pytest.fixture
def registry() -> ApprovalEvidenceRegistry:
    return ApprovalEvidenceRegistry()


# ---------------------------------------------------------------------------
# Protocol compliance
# ---------------------------------------------------------------------------


class _StructuralStore:
    """Conforms to ApprovalStore without inheriting from it."""

    def register(self, evidence):
        return None

    def consume(self, evidence, now, *, tenant_id=None, executor_id=None):
        return True

    def is_consumed(self, approval_id):
        return False


class _IncompleteStore:
    def register(self, evidence):
        return None


@pytest.mark.parametrize(
    "factory",
    [InMemoryApprovalStore, ApprovalEvidenceRegistry],
)
def test_implementations_satisfy_the_protocol(factory):
    assert isinstance(factory(), ApprovalStore)


def test_durable_store_class_declares_the_protocol():
    assert issubclass(DurableApprovalStore, ApprovalStore)
    assert isinstance(DurableApprovalStore(lambda: None), ApprovalStore)


def test_protocol_is_structural_for_conforming_classes():
    assert isinstance(_StructuralStore(), ApprovalStore)


def test_protocol_rejects_incomplete_classes():
    assert not isinstance(_IncompleteStore(), ApprovalStore)
    assert not isinstance(object(), ApprovalStore)


# ---------------------------------------------------------------------------
# Legacy evidence compatibility
# ---------------------------------------------------------------------------


def test_legacy_evidence_without_tenant_is_valid():
    evidence = issue()

    assert evidence.tenant_id is None
    assert evidence.is_trusted() is True


def test_legacy_positional_construction_still_works():
    now = NOW
    evidence = ApprovalEvidence(
        uuid4(),
        uuid4(),
        uuid4(),
        uuid4(),
        "merchant-1",
        Decimal("10.00"),
        "INR",
        now - timedelta(seconds=1),
        now + timedelta(minutes=1),
        None,
    )

    assert evidence.tenant_id is None
    assert evidence.is_trusted() is False


def test_tenant_id_must_be_uuid_or_none():
    with pytest.raises(TypeError):
        issue(tenant_id="not-a-uuid")  # type: ignore[arg-type]


def test_tenant_id_is_preserved_on_issued_evidence():
    assert issue(tenant_id=TENANT_A).tenant_id == TENANT_A


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------


def test_register_accepts_trusted_evidence(store):
    evidence = issue()

    store.register(evidence)

    assert store.is_consumed(evidence.approval_id) is False


def test_register_does_not_consume(store):
    evidence = issue()

    store.register(evidence)

    assert store.consume(evidence, NOW) is True


def test_register_rejects_duplicates(store):
    evidence = issue()
    store.register(evidence)

    with pytest.raises(ApprovalEvidenceInvalid):
        store.register(evidence)


def test_register_rejects_untrusted_evidence(store):
    with pytest.raises(ApprovalEvidenceInvalid):
        store.register(untrusted_copy(issue()))


@pytest.mark.parametrize("value", [None, "evidence", object(), 42])
def test_register_rejects_non_evidence(store, value):
    with pytest.raises(ApprovalEvidenceInvalid):
        store.register(value)


def test_consumption_does_not_require_prior_registration(store):
    """M1-M4 behavior: evidence may be consumed without register()."""
    assert store.consume(issue(), NOW) is True


# ---------------------------------------------------------------------------
# Single-use consumption and replay
# ---------------------------------------------------------------------------


def test_first_consume_succeeds_and_replay_returns_false(store):
    evidence = issue()

    assert store.consume(evidence, NOW) is True
    assert store.consume(evidence, NOW) is False
    assert store.consume(evidence, NOW) is False
    assert store.is_consumed(evidence.approval_id) is True


def test_unknown_approval_is_not_consumed(store):
    assert store.is_consumed(uuid4()) is False


def test_is_consumed_requires_uuid(store):
    with pytest.raises(TypeError):
        store.is_consumed("not-a-uuid")  # type: ignore[arg-type]


def test_executor_id_is_accepted(store):
    assert store.consume(issue(), NOW, executor_id=uuid4()) is True


# ---------------------------------------------------------------------------
# Validity window
# ---------------------------------------------------------------------------


def test_consumption_at_exact_expiry_is_rejected(store):
    evidence = issue()

    with pytest.raises(ApprovalEvidenceExpired):
        store.consume(evidence, evidence.expires_at)

    assert store.is_consumed(evidence.approval_id) is False


def test_consumption_after_expiry_is_rejected(store):
    evidence = issue()

    with pytest.raises(ApprovalEvidenceExpired):
        store.consume(evidence, evidence.expires_at + timedelta(seconds=1))


def test_just_before_expiry_is_accepted(store):
    evidence = issue()

    assert store.consume(
        evidence, evidence.expires_at - timedelta(microseconds=1)
    ) is True


def test_registered_but_expired_evidence_cannot_be_consumed(store):
    evidence = issue(
        approved_at=NOW - timedelta(minutes=10),
        expires_at=NOW - timedelta(minutes=5),
    )
    store.register(evidence)

    with pytest.raises(ApprovalEvidenceExpired):
        store.consume(evidence, NOW)

    assert store.is_consumed(evidence.approval_id) is False


def test_failed_expiry_check_does_not_burn_the_approval(store):
    evidence = issue()

    with pytest.raises(ApprovalEvidenceExpired):
        store.consume(evidence, evidence.expires_at)

    assert store.consume(evidence, NOW) is True


def test_future_dated_evidence_is_rejected(store):
    evidence = issue(
        approved_at=NOW + timedelta(hours=1),
        expires_at=NOW + timedelta(hours=2),
    )

    with pytest.raises(ApprovalEvidenceInvalid):
        store.consume(evidence, NOW)

    assert store.is_consumed(evidence.approval_id) is False


def test_small_clock_skew_is_tolerated(store):
    evidence = issue(
        approved_at=NOW + timedelta(seconds=3),
        expires_at=NOW + timedelta(minutes=5),
    )

    assert store.consume(evidence, NOW) is True


def test_naive_now_is_rejected(store):
    with pytest.raises(ApprovalEvidenceInvalid):
        store.consume(issue(), datetime(2030, 1, 1, 12, 0))


def test_non_datetime_now_is_rejected(store):
    with pytest.raises(TypeError):
        store.consume(issue(), "now")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


def test_untrusted_evidence_cannot_be_consumed(store):
    evidence = untrusted_copy(issue())

    with pytest.raises(ApprovalEvidenceInvalid):
        store.consume(evidence, NOW)

    assert store.is_consumed(evidence.approval_id) is False


@pytest.mark.parametrize("value", [None, "evidence", object()])
def test_non_evidence_cannot_be_consumed(store, value):
    with pytest.raises(ApprovalEvidenceInvalid):
        store.consume(value, NOW)


# ---------------------------------------------------------------------------
# Tenant binding
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("evidence_tenant", "consume_tenant", "allowed"),
    [
        (None, None, True),
        (TENANT_A, TENANT_A, True),
        (TENANT_A, None, False),
        (None, TENANT_A, False),
        (TENANT_A, TENANT_B, False),
    ],
)
def test_tenant_binding_matrix(store, evidence_tenant, consume_tenant, allowed):
    evidence = issue(tenant_id=evidence_tenant)

    if allowed:
        assert store.consume(evidence, NOW, tenant_id=consume_tenant) is True
    else:
        with pytest.raises(ApprovalEvidenceInvalid):
            store.consume(evidence, NOW, tenant_id=consume_tenant)

        assert store.is_consumed(evidence.approval_id) is False


def test_wrong_tenant_attempt_does_not_burn_the_approval(store):
    evidence = issue(tenant_id=TENANT_A)

    with pytest.raises(ApprovalEvidenceInvalid):
        store.consume(evidence, NOW, tenant_id=TENANT_B)

    assert store.consume(evidence, NOW, tenant_id=TENANT_A) is True


def test_tenant_id_argument_must_be_uuid(store):
    with pytest.raises(TypeError):
        store.consume(
            issue(tenant_id=TENANT_A),
            NOW,
            tenant_id="tenant-a",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Isolation
# ---------------------------------------------------------------------------


def test_consuming_one_approval_does_not_affect_another(store):
    first = issue()
    second = issue()

    assert store.consume(first, NOW) is True

    assert store.is_consumed(second.approval_id) is False
    assert store.consume(second, NOW) is True


def test_separate_store_instances_do_not_share_state():
    """Process-local by design: durable sharing is the durable store's job."""
    evidence = issue()
    first = InMemoryApprovalStore()
    second = InMemoryApprovalStore()

    assert first.consume(evidence, NOW) is True
    assert second.is_consumed(evidence.approval_id) is False
    assert second.consume(evidence, NOW) is True


# ---------------------------------------------------------------------------
# Concurrency (single process)
# ---------------------------------------------------------------------------


def test_concurrent_consumption_has_exactly_one_winner(store):
    evidence = issue()
    workers = 32
    barrier = Barrier(workers)

    def attempt(_):
        barrier.wait(timeout=30)
        return store.consume(evidence, NOW)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(attempt, range(workers)))

    assert results.count(True) == 1
    assert results.count(False) == workers - 1


def test_concurrent_registry_consumption_has_exactly_one_winner(registry):
    evidence = issue()
    workers = 32
    barrier = Barrier(workers)

    def attempt(_):
        barrier.wait(timeout=30)

        try:
            registry.consume(evidence, now=NOW)
            return "ok"
        except ApprovalEvidenceConsumed:
            return "consumed"

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(attempt, range(workers)))

    assert results.count("ok") == 1
    assert results.count("consumed") == workers - 1


# ---------------------------------------------------------------------------
# ApprovalEvidenceRegistry backward compatibility
# ---------------------------------------------------------------------------


def test_registry_is_an_in_memory_store():
    assert issubclass(ApprovalEvidenceRegistry, InMemoryApprovalStore)
    assert isinstance(ApprovalEvidenceRegistry(), ApprovalStore)


def test_registry_constructor_signatures_are_preserved():
    ApprovalEvidenceRegistry()
    ApprovalEvidenceRegistry(None)
    ApprovalEvidenceRegistry(store=InMemoryApprovalConsumptionStore())


def test_registry_rejects_invalid_store_type():
    with pytest.raises(TypeError):
        ApprovalEvidenceRegistry(store=object())  # type: ignore[arg-type]


def test_registry_consume_returns_none_and_raises_on_reuse(registry):
    evidence = issue()

    assert registry.consume(evidence, now=NOW) is None

    with pytest.raises(ApprovalEvidenceConsumed):
        registry.consume(evidence, now=NOW)

    assert registry.is_consumed(evidence.approval_id) is True


def test_registry_accepts_now_positionally(registry):
    evidence = issue()

    registry.consume(evidence, NOW)

    with pytest.raises(ApprovalEvidenceConsumed):
        registry.consume(evidence, NOW)


def test_registry_requires_now(registry):
    with pytest.raises(TypeError):
        registry.consume(issue())  # type: ignore[call-arg]


def test_registry_exception_hierarchy_is_preserved():
    assert issubclass(ApprovalEvidenceConsumed, ApprovalEvidenceError)
    assert issubclass(ApprovalEvidenceExpired, ApprovalEvidenceError)
    assert issubclass(ApprovalEvidenceInvalid, ApprovalEvidenceError)
    assert issubclass(ApprovalEvidenceError, ValueError)


def test_registry_rejects_expired_untrusted_and_non_evidence(registry):
    expired = issue()

    with pytest.raises(ApprovalEvidenceExpired):
        registry.consume(expired, now=expired.expires_at)

    with pytest.raises(ApprovalEvidenceInvalid):
        registry.consume(untrusted_copy(issue()), now=NOW)

    with pytest.raises(ApprovalEvidenceInvalid):
        registry.consume("evidence", now=NOW)  # type: ignore[arg-type]


def test_registry_failed_validation_does_not_burn_the_approval(registry):
    evidence = issue()

    with pytest.raises(ApprovalEvidenceExpired):
        registry.consume(evidence, now=evidence.expires_at)

    assert registry.is_consumed(evidence.approval_id) is False
    registry.consume(evidence, now=NOW)


def test_registry_supports_tenant_binding(registry):
    evidence = issue(tenant_id=TENANT_A)

    with pytest.raises(ApprovalEvidenceInvalid):
        registry.consume(evidence, now=NOW, tenant_id=TENANT_B)

    registry.consume(evidence, now=NOW, tenant_id=TENANT_A)


def test_registry_supports_register_and_executor_id(registry):
    evidence = issue()

    registry.register(evidence)
    registry.consume(evidence, now=NOW, executor_id=uuid4())

    assert registry.is_consumed(evidence.approval_id) is True


def test_registry_is_consumed_requires_uuid(registry):
    with pytest.raises(TypeError):
        registry.is_consumed("not-a-uuid")  # type: ignore[arg-type]


def test_registries_sharing_a_legacy_store_cannot_both_consume():
    shared = InMemoryApprovalConsumptionStore()
    first = ApprovalEvidenceRegistry(shared)
    second = ApprovalEvidenceRegistry(shared)
    evidence = issue()

    first.consume(evidence, now=NOW)

    with pytest.raises(ApprovalEvidenceConsumed):
        second.consume(evidence, now=NOW)

    assert second.is_consumed(evidence.approval_id) is True


class _OutageStore(ApprovalConsumptionStore):
    def try_consume(self, approval_id, expires_at):
        raise ApprovalStoreError("simulated outage")

    def is_consumed(self, approval_id):
        return False


def test_registry_fails_closed_when_legacy_store_is_down():
    registry = ApprovalEvidenceRegistry(_OutageStore())
    evidence = issue()

    with pytest.raises(ApprovalEvidenceInvalid):
        registry.consume(evidence, now=NOW)

    assert registry.is_consumed(evidence.approval_id) is False

    with pytest.raises(ApprovalEvidenceInvalid):
        registry.consume(evidence, now=NOW)


def test_registry_from_environment_without_variable_is_memory_only(monkeypatch):
    monkeypatch.delenv("OVELA_APPROVAL_DB_CONNECTION", raising=False)

    registry = ApprovalEvidenceRegistry.from_environment()
    evidence = issue()

    registry.consume(evidence, now=NOW)

    with pytest.raises(ApprovalEvidenceConsumed):
        registry.consume(evidence, now=NOW)