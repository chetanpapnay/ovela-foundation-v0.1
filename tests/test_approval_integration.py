from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

from app.actions import ActionExecutor
from app.approval_evidence import (
    ApprovalEvidence,
    ApprovalEvidenceRegistry,
    _issue_internal_approval_evidence,
)
from app.ledger import AppendOnlyLedger
from app.models import ActionRequest
from app.security import authorize_action
from tests.approval_test_helpers import trusted_approval_for_action
from tests.authorization_test_helpers import trusted_context_for_action


SESSION_ID = "00000000-0000-0000-0000-000000000001"


def payment_action(**overrides):
    values = {
        "session_id": SESSION_ID,
        "action_type": "PAYMENT_INITIATE",
        "authorization_state": "STEP_UP_VERIFIED",
        "amount": Decimal("1000.00"),
        "currency": "INR",
        "destination_id": "merchant-1",
        "destination_verified": True,
        "user_confirmation": True,
    }
    values.update(overrides)
    return ActionRequest(**values)


def test_payment_requires_trusted_approval_evidence():
    action = payment_action()
    context = trusted_context_for_action(action)

    decision = authorize_action(action, context)

    assert decision.allowed is False
    assert "approval evidence" in decision.reason.lower()


def test_valid_approval_authorizes_payment_even_when_caller_flags_are_false():
    action = payment_action(
        destination_verified=False,
        user_confirmation=False,
        confirmation_action_id=None,
    )
    context = trusted_context_for_action(action)
    approval = trusted_approval_for_action(action, context)

    decision = authorize_action(action, context, approval)

    assert decision.allowed is True


def test_approval_must_match_action_id():
    action = payment_action()
    context = trusted_context_for_action(action)
    approval = _issue_internal_approval_evidence(
        action_id=uuid4(),
        session_id=UUID(action.session_id),
        subject_id=context.subject_id,
        destination_id=action.destination_id,
        amount=action.amount,
        currency=action.currency,
        approved_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    decision = authorize_action(action, context, approval)

    assert decision.allowed is False
    assert "match" in decision.reason.lower()


def test_approval_must_match_session():
    action = payment_action()
    context = trusted_context_for_action(action)
    approval = _issue_internal_approval_evidence(
        action_id=action.action_id,
        session_id=uuid4(),
        subject_id=context.subject_id,
        destination_id=action.destination_id,
        amount=action.amount,
        currency=action.currency,
        approved_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    decision = authorize_action(action, context, approval)

    assert decision.allowed is False


def test_approval_must_match_subject():
    action = payment_action()
    context = trusted_context_for_action(action)
    approval = _issue_internal_approval_evidence(
        action_id=action.action_id,
        session_id=UUID(action.session_id),
        subject_id=uuid4(),
        destination_id=action.destination_id,
        amount=action.amount,
        currency=action.currency,
        approved_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    decision = authorize_action(action, context, approval)

    assert decision.allowed is False


def test_approval_must_match_destination_amount_and_currency():
    action = payment_action()
    context = trusted_context_for_action(action)

    approval = _issue_internal_approval_evidence(
        action_id=action.action_id,
        session_id=UUID(action.session_id),
        subject_id=context.subject_id,
        destination_id="attacker-destination",
        amount=Decimal("999999.00"),
        currency="USD",
        approved_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    decision = authorize_action(action, context, approval)

    assert decision.allowed is False


def test_expired_approval_is_rejected():
    action = payment_action()
    context = trusted_context_for_action(action)
    approved_at = datetime.now(timezone.utc) - timedelta(minutes=10)
    approval = _issue_internal_approval_evidence(
        action_id=action.action_id,
        session_id=UUID(action.session_id),
        subject_id=context.subject_id,
        destination_id=action.destination_id,
        amount=action.amount,
        currency=action.currency,
        approved_at=approved_at,
        expires_at=approved_at + timedelta(minutes=1),
    )

    decision = authorize_action(action, context, approval)

    assert decision.allowed is False
    assert "approval evidence" in decision.reason.lower()


def test_forged_approval_subclass_is_rejected():
    class ForgedApproval(ApprovalEvidence):
        def matches_transaction(self, *args, **kwargs):
            return True

    action = payment_action()
    context = trusted_context_for_action(action)
    values = {
        "approval_id": uuid4(),
        "action_id": action.action_id,
        "session_id": UUID(action.session_id),
        "subject_id": context.subject_id,
        "destination_id": action.destination_id,
        "amount": action.amount,
        "currency": action.currency,
        "approved_at": datetime.now(timezone.utc),
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
    }
    forged = ForgedApproval(**values)

    decision = authorize_action(action, context, forged)

    assert decision.allowed is False


def test_execution_consumes_approval_once_across_executors():
    ledger = AppendOnlyLedger()
    first_executor = ActionExecutor(ledger)
    second_executor = ActionExecutor(ledger)
    action = payment_action()
    context = trusted_context_for_action(action)
    approval = trusted_approval_for_action(action, context)

    first = first_executor.execute(action, context, approval)
    second = second_executor.execute(action, context, approval)

    assert first.executed is True
    assert second.executed is False
    assert len(ledger.all()) == 1


def test_concurrent_reuse_of_one_approval_has_one_success():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)
    action = payment_action()
    context = trusted_context_for_action(action)
    approval = trusted_approval_for_action(action, context)

    def execute_once():
        return executor.execute(action, context, approval)

    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: execute_once(), range(32)))

    successful = [result for result in results if result.executed]

    assert len(successful) == 1
    assert len(ledger.all()) == 1


def test_approval_is_not_reissued_from_caller_confirmation_flags():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)
    action = payment_action(
        user_confirmation=True,
        destination_verified=True,
        confirmation_action_id=None,
    )
    context = trusted_context_for_action(action)

    result = executor.execute(action, context)

    assert result.executed is False
    assert ledger.all() == []


def test_custom_registry_is_supported_for_isolated_execution():
    registry = ApprovalEvidenceRegistry()
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger, approval_registry=registry)
    action = payment_action()
    context = trusted_context_for_action(action)
    approval = trusted_approval_for_action(action, context)

    result = executor.execute(action, context, approval)

    assert result.executed is True
    assert registry.is_consumed(approval.approval_id)
