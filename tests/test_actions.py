from decimal import Decimal
from uuid import uuid4

from app.actions import ActionExecutor
from app.ledger import AppendOnlyLedger
from app.models import ActionRequest, EventType


def payment_action(**overrides):
    values = {
        "session_id": "session-1",
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

    result = executor.execute(action)

    assert result.executed is False
    assert ledger.all() == []


def test_payment_requires_step_up_before_execution():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        authorization_state="AUTHENTICATED",
    )

    result = executor.execute(action)

    assert result.executed is False
    assert "step-up" in result.reason.lower()
    assert ledger.all() == []


def test_successful_payment_creates_one_ledger_event():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action()

    result = executor.execute(action)

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

    first = executor.execute(action)
    second = executor.execute(action)

    assert first.executed is True
    assert second.executed is False
    assert "already" in second.reason.lower()

    assert len(ledger.all()) == 1


def test_confirmation_bound_to_different_action_cannot_execute():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        confirmation_action_id="00000000-0000-0000-0000-000000000001",
    )

    result = executor.execute(action)

    assert result.executed is False
    assert ledger.all() == []


def test_unverified_destination_cannot_execute():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        destination_verified=False,
    )

    result = executor.execute(action)

    assert result.executed is False
    assert ledger.all() == []


def test_missing_destination_cannot_execute():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        destination_id=None,
    )

    result = executor.execute(action)

    assert result.executed is False
    assert ledger.all() == []


def test_zero_amount_cannot_execute():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        amount=Decimal("0"),
    )

    result = executor.execute(action)

    assert result.executed is False
    assert ledger.all() == []


def test_currency_is_preserved_in_ledger_event():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        amount=Decimal("25.50"),
        currency="usd",
    )

    result = executor.execute(action)

    assert result.executed is True

    events = ledger.all()

    assert len(events) == 1
    assert events[0].currency == "USD"


def test_failed_execution_does_not_write_ledger_event():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(
        user_confirmation=False,
    )

    result = executor.execute(action)

    assert result.executed is False
    assert ledger.all() == []