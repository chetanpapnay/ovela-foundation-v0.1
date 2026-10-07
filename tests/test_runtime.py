from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from app.runtime import (
    ActionType,
    ApprovalRequired,
    AuthRequest,
    Decision,
    ExecutionState,
    OvelaRuntime,
    PaymentExecuteRequest,
    PaymentProposeRequest,
    TenantBoundaryViolation,
)


@pytest.fixture
def runtime() -> OvelaRuntime:
    instance = OvelaRuntime()
    try:
        yield instance
    finally:
        instance.close()


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def authenticate(
    runtime: OvelaRuntime,
    tenant_id: UUID,
    subject_id: UUID,
    now: datetime,
):
    return runtime.authenticate_session(
        AuthRequest(
            tenant_id=tenant_id,
            subject_id=subject_id,
            device_key_thumbprint="device-key-001",
            password="test-password",
        ),
        now,
    )


def payment_proposal(
    amount: Decimal,
    destination_id: str = "merchant-001",
) -> PaymentProposeRequest:
    return PaymentProposeRequest(
        action_type=ActionType.PAYMENT_INITIATE,
        amount=amount,
        currency="INR",
        destination_id=destination_id,
        metadata={"source": "test"},
    )


def payment_execution(
    request_id: UUID,
    amount: Decimal,
    approval_evidence_id: UUID | None = None,
    destination_id: str = "merchant-001",
) -> PaymentExecuteRequest:
    return PaymentExecuteRequest(
        request_id=request_id,
        action_type=ActionType.PAYMENT_INITIATE,
        amount=amount,
        currency="INR",
        destination_id=destination_id,
        approval_evidence_id=approval_evidence_id,
    )


def test_standard_payment_flow_completes_and_audit_chain_is_valid(
    runtime: OvelaRuntime,
):
    tenant_id = uuid4()
    subject_id = uuid4()
    now = utc_now()

    authentication = authenticate(
        runtime=runtime,
        tenant_id=tenant_id,
        subject_id=subject_id,
        now=now,
    )

    proposal = runtime.propose_payment(
        session_id=authentication.session_id,
        req=payment_proposal(Decimal("1000.00")),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=1),
    )

    assert proposal.decision is Decision.PERMIT
    assert proposal.approval_required is False
    assert proposal.reason

    execution = runtime.execute_payment(
        session_id=authentication.session_id,
        req=payment_execution(
            request_id=proposal.request_id,
            amount=Decimal("1000.00"),
        ),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=2),
    )

    assert execution.transaction_id is not None
    assert execution.outbox_id is not None
    assert execution.state is ExecutionState.SUBMITTED
    assert execution.audit_sequence >= 0

    settled = runtime.ingest_rail_webhook(
        tenant_id=tenant_id,
        transaction_id=execution.transaction_id,
        status="SETTLED",
        now=now + timedelta(seconds=3),
    )

    assert settled is True

    verification = runtime.verify_audit_chain(tenant_id)

    assert verification.valid is True
    assert verification.tenant_id == tenant_id
    assert verification.records_verified >= 4
    assert verification.head_sequence is not None
    assert verification.first_failure is None


def test_high_value_dual_approval_flow_requires_and_accepts_approval(
    runtime: OvelaRuntime,
):
    tenant_id = uuid4()
    subject_id = uuid4()
    now = utc_now()
    spending_limit = Decimal("5000.00")
    amount = Decimal("25000.00")

    authentication = authenticate(
        runtime=runtime,
        tenant_id=tenant_id,
        subject_id=subject_id,
        now=now,
    )

    proposal = runtime.propose_payment(
        session_id=authentication.session_id,
        req=payment_proposal(amount),
        spending_limit=spending_limit,
        now=now + timedelta(seconds=1),
    )

    assert proposal.decision is Decision.REQUIRE_APPROVAL
    assert proposal.approval_required is True

    with pytest.raises(ApprovalRequired):
        runtime.execute_payment(
            session_id=authentication.session_id,
            req=payment_execution(
                request_id=proposal.request_id,
                amount=amount,
            ),
            spending_limit=spending_limit,
            now=now + timedelta(seconds=2),
        )

    approval_evidence_id = uuid4()

    execution = runtime.execute_payment(
        session_id=authentication.session_id,
        req=payment_execution(
            request_id=proposal.request_id,
            amount=amount,
            approval_evidence_id=approval_evidence_id,
        ),
        spending_limit=spending_limit,
        now=now + timedelta(seconds=3),
    )

    assert execution.state is ExecutionState.SUBMITTED

    settled = runtime.ingest_rail_webhook(
        tenant_id=tenant_id,
        transaction_id=execution.transaction_id,
        status="SETTLED",
        now=now + timedelta(seconds=4),
    )

    assert settled is True

    verification = runtime.verify_audit_chain(tenant_id)

    assert verification.valid is True
    assert verification.records_verified >= 4
    assert verification.first_failure is None


def test_rail_timeout_enters_unknown_and_statement_reconciliation_settles(
    runtime: OvelaRuntime,
):
    tenant_id = uuid4()
    subject_id = uuid4()
    now = utc_now()

    authentication = authenticate(
        runtime=runtime,
        tenant_id=tenant_id,
        subject_id=subject_id,
        now=now,
    )

    proposal = runtime.propose_payment(
        session_id=authentication.session_id,
        req=payment_proposal(Decimal("1500.00")),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=1),
    )

    execution = runtime.execute_payment(
        session_id=authentication.session_id,
        req=payment_execution(
            request_id=proposal.request_id,
            amount=Decimal("1500.00"),
        ),
        spending_limit=Decimal("5000.00"),
        simulate_rail_timeout=True,
        now=now + timedelta(seconds=2),
    )

    assert execution.state is ExecutionState.UNKNOWN

    reconciled = runtime.reconcile_statement(
        tenant_id=tenant_id,
        transaction_id=execution.transaction_id,
        matched=True,
        now=now + timedelta(seconds=3),
    )

    assert reconciled is True

    verification = runtime.verify_audit_chain(tenant_id)

    assert verification.valid is True
    assert verification.records_verified >= 5
    assert verification.first_failure is None


def test_forensic_audit_veracity_detects_previous_hash_tampering(
    runtime: OvelaRuntime,
):
    tenant_id = uuid4()
    subject_id = uuid4()
    now = utc_now()

    authentication = authenticate(
        runtime=runtime,
        tenant_id=tenant_id,
        subject_id=subject_id,
        now=now,
    )

    proposal = runtime.propose_payment(
        session_id=authentication.session_id,
        req=payment_proposal(Decimal("2000.00")),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=1),
    )

    execution = runtime.execute_payment(
        session_id=authentication.session_id,
        req=payment_execution(
            request_id=proposal.request_id,
            amount=Decimal("2000.00"),
        ),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=2),
    )

    runtime.ingest_rail_webhook(
        tenant_id=tenant_id,
        transaction_id=execution.transaction_id,
        status="SETTLED",
        now=now + timedelta(seconds=3),
    )

    before_tamper = runtime.verify_audit_chain(tenant_id)

    assert before_tamper.valid is True
    assert before_tamper.head_sequence is not None
    assert before_tamper.records_verified >= 4

    target_sequence = 1
    connection = runtime._connect()

    try:
        row = connection.execute(
            """
            SELECT prev_record_hash
            FROM audit_events
            WHERE tenant_id = ?
              AND sequence_number = ?
            """,
            (str(tenant_id), target_sequence),
        ).fetchone()

        assert row is not None

        original_previous_hash = bytes(row["prev_record_hash"])
        tampered_previous_hash = bytes(
            value ^ 0xFF for value in original_previous_hash
        )

        connection.execute(
            """
            UPDATE audit_events
            SET prev_record_hash = ?
            WHERE tenant_id = ?
              AND sequence_number = ?
            """,
            (
                tampered_previous_hash,
                str(tenant_id),
                target_sequence,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    after_tamper = runtime.verify_audit_chain(tenant_id)

    assert after_tamper.valid is False
    assert after_tamper.records_verified == target_sequence
    assert after_tamper.head_sequence == before_tamper.head_sequence
    assert after_tamper.first_failure is not None
    assert str(target_sequence) in after_tamper.first_failure
    assert "previous hash mismatch" in after_tamper.first_failure


def test_forensic_audit_veracity_detects_event_type_tampering(
    runtime: OvelaRuntime,
):
    tenant_id = uuid4()
    subject_id = uuid4()
    now = utc_now()

    authentication = authenticate(
        runtime=runtime,
        tenant_id=tenant_id,
        subject_id=subject_id,
        now=now,
    )

    proposal = runtime.propose_payment(
        session_id=authentication.session_id,
        req=payment_proposal(Decimal("2200.00")),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=1),
    )

    execution = runtime.execute_payment(
        session_id=authentication.session_id,
        req=payment_execution(
            request_id=proposal.request_id,
            amount=Decimal("2200.00"),
        ),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=2),
    )

    runtime.ingest_rail_webhook(
        tenant_id=tenant_id,
        transaction_id=execution.transaction_id,
        status="SETTLED",
        now=now + timedelta(seconds=3),
    )

    before_tamper = runtime.verify_audit_chain(tenant_id)

    assert before_tamper.valid is True
    assert before_tamper.head_sequence is not None

    target_sequence = 2
    connection = runtime._connect()

    try:
        row = connection.execute(
            """
            SELECT event_type
            FROM audit_events
            WHERE tenant_id = ?
              AND sequence_number = ?
            """,
            (str(tenant_id), target_sequence),
        ).fetchone()

        assert row is not None

        connection.execute(
            """
            UPDATE audit_events
            SET event_type = ?
            WHERE tenant_id = ?
              AND sequence_number = ?
            """,
            (
                "TAMPERED_EVENT",
                str(tenant_id),
                target_sequence,
            ),
        )
        connection.commit()
    finally:
        connection.close()

    after_tamper = runtime.verify_audit_chain(tenant_id)

    assert after_tamper.valid is False
    assert after_tamper.records_verified == target_sequence
    assert after_tamper.head_sequence == before_tamper.head_sequence
    assert after_tamper.first_failure is not None
    assert str(target_sequence) in after_tamper.first_failure
    assert "record hash mismatch" in after_tamper.first_failure


def test_cross_tenant_execution_is_rejected_without_state_or_outbox_changes(
    runtime: OvelaRuntime,
):
    tenant_a = uuid4()
    tenant_b = uuid4()
    subject_a = uuid4()
    subject_b = uuid4()
    now = utc_now()

    authentication_a = authenticate(
        runtime=runtime,
        tenant_id=tenant_a,
        subject_id=subject_a,
        now=now,
    )

    authentication_b = authenticate(
        runtime=runtime,
        tenant_id=tenant_b,
        subject_id=subject_b,
        now=now + timedelta(seconds=1),
    )

    proposal_b = runtime.propose_payment(
        session_id=authentication_b.session_id,
        req=payment_proposal(
            Decimal("3000.00"),
            destination_id="tenant-b-merchant",
        ),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=2),
    )

    connection = runtime._connect()

    try:
        before_transactions = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM transactions
            WHERE tenant_id = ?
            """,
            (str(tenant_b),),
        ).fetchone()

        before_outbox = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM outbox
            WHERE tenant_id = ?
            """,
            (str(tenant_b),),
        ).fetchone()

        before_audit = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM audit_events
            WHERE tenant_id = ?
            """,
            (str(tenant_b),),
        ).fetchone()

        assert before_transactions is not None
        assert before_outbox is not None
        assert before_audit is not None

        with pytest.raises(TenantBoundaryViolation):
            runtime.execute_payment(
                session_id=authentication_a.session_id,
                req=payment_execution(
                    request_id=proposal_b.request_id,
                    amount=Decimal("3000.00"),
                    destination_id="tenant-b-merchant",
                ),
                spending_limit=Decimal("5000.00"),
                now=now + timedelta(seconds=3),
            )

        after_transactions = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM transactions
            WHERE tenant_id = ?
            """,
            (str(tenant_b),),
        ).fetchone()

        after_outbox = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM outbox
            WHERE tenant_id = ?
            """,
            (str(tenant_b),),
        ).fetchone()

        after_audit = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM audit_events
            WHERE tenant_id = ?
            """,
            (str(tenant_b),),
        ).fetchone()

        assert after_transactions is not None
        assert after_outbox is not None
        assert after_audit is not None

        assert after_transactions["count"] == before_transactions["count"]
        assert after_outbox["count"] == before_outbox["count"]
        assert after_audit["count"] == before_audit["count"]
    finally:
        connection.close()


def test_cross_tenant_execution_does_not_create_transaction_for_tenant_a(
    runtime: OvelaRuntime,
):
    tenant_a = uuid4()
    tenant_b = uuid4()
    subject_a = uuid4()
    subject_b = uuid4()
    now = utc_now()

    authentication_a = authenticate(
        runtime=runtime,
        tenant_id=tenant_a,
        subject_id=subject_a,
        now=now,
    )

    authentication_b = authenticate(
        runtime=runtime,
        tenant_id=tenant_b,
        subject_id=subject_b,
        now=now + timedelta(seconds=1),
    )

    proposal_b = runtime.propose_payment(
        session_id=authentication_b.session_id,
        req=payment_proposal(Decimal("4000.00")),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=2),
    )

    connection = runtime._connect()

    try:
        before_tenant_a_transactions = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM transactions
            WHERE tenant_id = ?
            """,
            (str(tenant_a),),
        ).fetchone()

        before_tenant_a_outbox = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM outbox
            WHERE tenant_id = ?
            """,
            (str(tenant_a),),
        ).fetchone()

        assert before_tenant_a_transactions is not None
        assert before_tenant_a_outbox is not None

        with pytest.raises(TenantBoundaryViolation):
            runtime.execute_payment(
                session_id=authentication_a.session_id,
                req=payment_execution(
                    request_id=proposal_b.request_id,
                    amount=Decimal("4000.00"),
                ),
                spending_limit=Decimal("5000.00"),
                now=now + timedelta(seconds=3),
            )

        after_tenant_a_transactions = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM transactions
            WHERE tenant_id = ?
            """,
            (str(tenant_a),),
        ).fetchone()

        after_tenant_a_outbox = connection.execute(
            """
            SELECT COUNT(*) AS count
            FROM outbox
            WHERE tenant_id = ?
            """,
            (str(tenant_a),),
        ).fetchone()

        assert after_tenant_a_transactions is not None
        assert after_tenant_a_outbox is not None

        assert (
            after_tenant_a_transactions["count"]
            == before_tenant_a_transactions["count"]
        )
        assert (
            after_tenant_a_outbox["count"]
            == before_tenant_a_outbox["count"]
        )
    finally:
        connection.close()


def test_cross_tenant_webhook_cannot_mutate_transaction(
    runtime: OvelaRuntime,
):
    tenant_a = uuid4()
    tenant_b = uuid4()
    subject_a = uuid4()
    now = utc_now()

    authentication_a = authenticate(
        runtime=runtime,
        tenant_id=tenant_a,
        subject_id=subject_a,
        now=now,
    )

    proposal_a = runtime.propose_payment(
        session_id=authentication_a.session_id,
        req=payment_proposal(Decimal("750.00")),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=1),
    )

    execution_a = runtime.execute_payment(
        session_id=authentication_a.session_id,
        req=payment_execution(
            request_id=proposal_a.request_id,
            amount=Decimal("750.00"),
        ),
        spending_limit=Decimal("5000.00"),
        now=now + timedelta(seconds=2),
    )

    with pytest.raises(TenantBoundaryViolation):
        runtime.ingest_rail_webhook(
            tenant_id=tenant_b,
            transaction_id=execution_a.transaction_id,
            status="SETTLED",
            now=now + timedelta(seconds=3),
        )

    verification = runtime.verify_audit_chain(tenant_a)

    assert verification.valid is True
    assert verification.first_failure is None