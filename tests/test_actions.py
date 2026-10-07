from decimal import Decimal
from uuid import uuid4

from app.actions import ActionExecutor
from app.authorization_context import AuthorizationState
from app.ledger import AppendOnlyLedger
from app.models import ActionRequest, EventType
from tests.approval_test_helpers import (
    execute_with_trusted_approval,
    trusted_approval_for_action,
)
from tests.authorization_test_helpers import (
    DEFAULT_SESSION_ID,
    trusted_context_for_action,
)


def payment_action(**overrides):
    values = {
        "session_id": DEFAULT_SESSION_ID,
        "action_type": "PAYMENT_INITIATE",
        "authorization_state": "STEP_UP_VERIFIED",
        "amount": Decimal("1000.00"),
        "currency": "INR",
        "destination_id": "merchant-1",
        "destination_verified": True,
        "user_confirmation": True,
    }

    action_id = overrides.get("action_id", uuid4())

    values["action_id"] = action_id

    if "confirmation_action_id" not in overrides:
        values["confirmation_action_id"] = action_id

    values.update(overrides)

    return ActionRequest(**values)


def test_denied_action_cannot_execute():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        authorization_state="AUTHENTICATED",
    )

    result = executor.execute(
        action,
        trusted_context_for_action(
            action,
            state=AuthorizationState.AUTHENTICATED,
        ),
    )

    assert result.executed is False
    assert ledger.all() == []


def test_payment_requires_step_up_before_execution():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        authorization_state="AUTHENTICATED",
    )

    result = executor.execute(
        action,
        trusted_context_for_action(
            action,
            state=AuthorizationState.AUTHENTICATED,
        ),
    )

    assert result.executed is False
    assert "step-up" in result.reason.lower()
    assert ledger.all() == []


def test_successful_payment_creates_one_ledger_event():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action()

    result = execute_with_trusted_approval(executor, action)

    assert result.executed is True

    events = ledger.all()

    assert len(events) == 1
    assert events[0].event_type == EventType.EXPENSE
    assert events[0].amount == Decimal("1000.00")
    assert events[0].currency == "INR"
    assert events[0].direction == "DEBIT"
    assert events[0].account_id == action.session_id
    assert events[0].source_event_id == str(action.action_id)


def test_same_action_cannot_execute_twice():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action()

    first = execute_with_trusted_approval(executor, action)
    second = execute_with_trusted_approval(executor, action)

    assert first.executed is True
    assert second.executed is False
    assert "already" in second.reason.lower()

    assert len(ledger.all()) == 1


def test_approval_bound_to_different_action_cannot_execute():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action()
    context = trusted_context_for_action(action)
    other_action = payment_action()
    approval = trusted_approval_for_action(other_action, context)

    result = executor.execute(action, context, approval)

    assert result.executed is False
    assert "approval" in result.reason.lower()
    assert ledger.all() == []


def test_caller_destination_flag_cannot_block_valid_approval():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        destination_verified=False,
    )

    result = execute_with_trusted_approval(executor, action)

    assert result.executed is True
    assert len(ledger.all()) == 1


def test_missing_destination_cannot_execute():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        destination_id=None,
    )

    context = trusted_context_for_action(action)
    result = executor.execute(action, context)

    assert result.executed is False
    assert ledger.all() == []


def test_zero_amount_cannot_execute():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        amount=Decimal("0"),
    )

    context = trusted_context_for_action(action)
    result = executor.execute(action, context)

    assert result.executed is False
    assert ledger.all() == []


def test_currency_is_preserved_in_ledger_event():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        amount=Decimal("25.50"),
        currency="usd",
    )

    result = execute_with_trusted_approval(executor, action)

    assert result.executed is True

    events = ledger.all()

    assert len(events) == 1
    assert events[0].currency == "USD"


def test_caller_confirmation_flag_cannot_block_valid_approval():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        user_confirmation=False,
    )

    result = execute_with_trusted_approval(executor, action)

    assert result.executed is True
    assert len(ledger.all()) == 1
