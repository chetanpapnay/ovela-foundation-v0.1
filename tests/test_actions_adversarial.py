from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from decimal import Decimal
from typing import ClassVar

from app.actions import ActionExecutor
from app.ledger import AppendOnlyLedger
from app.models import ActionRequest, EventType, FinancialEvent
from tests.approval_test_helpers import (
    execute_with_trusted_approval,
    trusted_approval_for_action,
)
from tests.authorization_test_helpers import (
    DEFAULT_SESSION_ID,
    trusted_context_for_action,
    trusted_context_for_session,
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

    values.update(overrides)

    action = ActionRequest(**values)

    if "confirmation_action_id" not in overrides:
        action.confirmation_action_id = action.action_id

    return action


def test_concurrent_duplicate_execution_creates_only_one_event():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)
    action = payment_action()

    def execute():
        return execute_with_trusted_approval(executor, action)

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: execute(), range(8)))

    successful = [result for result in results if result.executed]

    assert len(successful) == 1
    assert len(ledger.all()) == 1


def test_different_actions_can_execute_independently():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    first = payment_action(
        amount=Decimal("100.00"),
        destination_id="merchant-1",
    )

    second = payment_action(
        amount=Decimal("200.00"),
        destination_id="merchant-2",
    )

    first_result = execute_with_trusted_approval(executor, first)
    second_result = execute_with_trusted_approval(executor, second)

    assert first_result.executed is True
    assert second_result.executed is True

    events = ledger.all()

    assert len(events) == 2
    assert {event.source_event_id for event in events} == {
        str(first.action_id),
        str(second.action_id),
    }


def test_existing_ledger_conflict_prevents_execution():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action()

    existing_event = FinancialEvent(
        account_id=action.session_id,
        source_id="ACTION_EXECUTOR",
        source_event_id=str(action.action_id),
        event_type=EventType.EXPENSE,
        amount=action.amount,
        currency=action.currency,
        direction="DEBIT",
        event_date=datetime.now(timezone.utc),
        recorded_at=datetime.now(timezone.utc),
    )

    ledger.append(existing_event)

    result = execute_with_trusted_approval(executor, action)

    assert result.executed is False
    assert "already" in result.reason.lower()
    assert len(ledger.all()) == 1


def test_two_executors_cannot_execute_same_action_against_shared_ledger():
    ledger = AppendOnlyLedger()

    first_executor = ActionExecutor(ledger)
    second_executor = ActionExecutor(ledger)

    action = payment_action()

    first = execute_with_trusted_approval(first_executor, action)
    second = execute_with_trusted_approval(second_executor, action)

    assert first.executed is True
    assert second.executed is False

    assert len(ledger.all()) == 1


def test_mutating_action_after_first_execution_cannot_create_second_event():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action()

    first = execute_with_trusted_approval(executor, action)

    assert first.executed is True

    action.amount = Decimal("999999.99")
    action.destination_id = "attacker-destination"
    action.currency = "USD"

    second = execute_with_trusted_approval(executor, action)

    assert second.executed is False
    assert len(ledger.all()) == 1

    event = ledger.all()[0]

    assert event.amount == Decimal("1000.00")
    assert event.currency == "INR"
    assert event.account_id == DEFAULT_SESSION_ID
    assert event.source_event_id == str(action.action_id)


def test_currency_is_normalized_before_ledger_commit():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(currency="inr")

    result = execute_with_trusted_approval(executor, action)

    assert result.executed is True
    assert ledger.all()[0].currency == "INR"


def test_invalid_action_object_fails_closed():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    result = executor.execute(object(), trusted_context_for_session())

    assert result.executed is False
    assert ledger.all() == []


def test_zero_amount_cannot_reach_ledger():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    action = payment_action(amount=Decimal("0"))

    context = trusted_context_for_action(action)
    result = executor.execute(action, context)

    assert result.executed is False
    assert ledger.all() == []


def test_negative_amount_cannot_reach_ledger():
    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    with __import__("pytest").raises(ValueError):
        payment_action(amount=Decimal("-1.00"))

    assert ledger.all() == []


def test_action_mutation_between_snapshot_operations_cannot_change_execution_intent():
    class MutatingAction(ActionRequest):
        copy_count: ClassVar[int] = 0

        def model_copy(self, *args, **kwargs):
            snapshot = super().model_copy(*args, **kwargs)

            type(self).copy_count += 1

            if type(self).copy_count == 1:
                self.amount = Decimal("999999.99")

            return snapshot

    values = {
        "session_id": DEFAULT_SESSION_ID,
        "action_type": "PAYMENT_INITIATE",
        "authorization_state": "STEP_UP_VERIFIED",
        "amount": Decimal("100.00"),
        "currency": "INR",
        "destination_id": "merchant-1",
        "destination_verified": True,
        "user_confirmation": True,
    }

    action = MutatingAction(**values)
    action.confirmation_action_id = action.action_id

    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    result = execute_with_trusted_approval(executor, action)

    assert result.executed is True

    events = ledger.all()

    assert len(events) == 1
    assert events[0].amount == Decimal("100.00")


def test_action_id_cannot_be_mutated_after_creation():
    action = payment_action()

    original_action_id = action.action_id

    with __import__("pytest").raises(
        __import__("pydantic").ValidationError
    ):
        action.action_id = original_action_id

    assert action.action_id == original_action_id


def test_invalid_action_id_type_is_rejected():
    with __import__("pytest").raises(
        __import__("pydantic").ValidationError
    ):
        ActionRequest(
            action_id="not-a-valid-uuid",
            session_id=DEFAULT_SESSION_ID,
            action_type="PAYMENT_INITIATE",
            authorization_state="STEP_UP_VERIFIED",
            amount=Decimal("100.00"),
            currency="INR",
            destination_id="merchant-1",
            destination_verified=True,
            user_confirmation=True,
        )


def test_invalid_confirmation_action_id_type_is_rejected():
    action = payment_action()

    original_confirmation_action_id = action.confirmation_action_id

    with __import__("pytest").raises(
        __import__("pydantic").ValidationError
    ):
        action.confirmation_action_id = "not-a-valid-uuid"

    assert action.confirmation_action_id == original_confirmation_action_id


def test_model_construct_invalid_action_id_is_rejected_by_execution_boundary():
    action = ActionRequest.model_construct(
        action_id="not-a-valid-uuid",
        session_id=DEFAULT_SESSION_ID,
        action_type="PAYMENT_INITIATE",
        authorization_state="STEP_UP_VERIFIED",
        amount=Decimal("100.00"),
        currency="INR",
        destination_id="merchant-1",
        destination_verified=True,
        user_confirmation=True,
        confirmation_action_id="not-a-valid-uuid",
    )

    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    with __import__("pytest").raises(
        __import__("pydantic").ValidationError
    ):
        executor.execute(action, trusted_context_for_action(action))

    assert ledger.all() == []


def test_model_copy_unvalidated_update_cannot_bypass_execution_boundary():
    action = payment_action()

    forged_action = action.model_copy(
        update={
            "amount": "not-a-valid-decimal",
            "confirmation_action_id": "not-a-valid-uuid",
        }
    )

    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)

    with __import__("pytest").raises(
        __import__("pydantic").ValidationError
    ):
        executor.execute(
            forged_action,
            trusted_context_for_action(forged_action),
        )

    assert ledger.all() == []


def test_confirmation_field_cannot_bypass_or_block_approval_binding():
    action = payment_action()
    other_action = payment_action()

    forged_action = action.model_copy(
        update={
            "confirmation_action_id": other_action.action_id,
        }
    )

    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)
    context = trusted_context_for_action(forged_action)
    approval = trusted_approval_for_action(forged_action, context)

    result = executor.execute(forged_action, context, approval)

    assert result.executed is True
    assert len(ledger.all()) == 1


def test_model_copy_cannot_change_frozen_action_id():
    action = payment_action()

    original_action_id = action.action_id
    replacement_action_id = payment_action().action_id

    with __import__("pytest").raises(TypeError):
        action.model_copy(
            update={
                "action_id": replacement_action_id,
            }
        )

    assert action.action_id == original_action_id


def test_ledger_rejects_malicious_event_copy_override():
    class MaliciousEvent(FinancialEvent):
        def model_copy(self, *args, **kwargs):
            copied = super().model_copy(*args, **kwargs)
            copied.amount = Decimal("999999.99")
            copied.currency = "USD"
            return copied

    action = payment_action()

    event = MaliciousEvent(
        account_id=action.session_id,
        source_id="ATTACKER",
        source_event_id=str(action.action_id),
        event_type=EventType.EXPENSE,
        amount=Decimal("100.00"),
        currency="INR",
        direction="DEBIT",
        event_date=datetime.now(timezone.utc),
        recorded_at=datetime.now(timezone.utc),
    )

    ledger = AppendOnlyLedger()

    ledger.append(event)

    stored = ledger.all()

    assert len(stored) == 1
    assert stored[0].amount == Decimal("100.00")
    assert stored[0].currency == "INR"


def test_ledger_rejects_malicious_event_dump_override():
    class MaliciousEvent(FinancialEvent):
        def model_dump(self, *args, **kwargs):
            dumped = super().model_dump(*args, **kwargs)
            dumped["amount"] = Decimal("999999.99")
            dumped["currency"] = "USD"
            return dumped

    action = payment_action()

    event = MaliciousEvent(
        account_id=action.session_id,
        source_id="ATTACKER",
        source_event_id=str(action.action_id),
        event_type=EventType.EXPENSE,
        amount=Decimal("100.00"),
        currency="INR",
        direction="DEBIT",
        event_date=datetime.now(timezone.utc),
        recorded_at=datetime.now(timezone.utc),
    )

    ledger = AppendOnlyLedger()

    ledger.append(event)

    stored = ledger.all()

    assert len(stored) == 1
    assert stored[0].amount == Decimal("100.00")
    assert stored[0].currency == "INR"


def test_ledger_snapshot_mutation_cannot_modify_stored_event():
    action = payment_action()

    event = FinancialEvent(
        account_id=action.session_id,
        source_id="TEST",
        source_event_id=str(action.action_id),
        event_type=EventType.EXPENSE,
        amount=Decimal("100.00"),
        currency="INR",
        direction="DEBIT",
        event_date=datetime.now(timezone.utc),
        recorded_at=datetime.now(timezone.utc),
    )

    ledger = AppendOnlyLedger()
    ledger.append(event)

    snapshot = ledger.all()[0]

    snapshot.amount = Decimal("999999.99")
    snapshot.currency = "USD"

    stored = ledger.all()

    assert len(stored) == 1
    assert stored[0].amount == Decimal("100.00")
    assert stored[0].currency == "INR"


def test_ledger_get_snapshot_mutation_cannot_modify_stored_event():
    action = payment_action()

    event = FinancialEvent(
        account_id=action.session_id,
        source_id="TEST",
        source_event_id=str(action.action_id),
        event_type=EventType.EXPENSE,
        amount=Decimal("100.00"),
        currency="INR",
        direction="DEBIT",
        event_date=datetime.now(timezone.utc),
        recorded_at=datetime.now(timezone.utc),
    )

    ledger = AppendOnlyLedger()
    ledger.append(event)

    stored_before = ledger.all()[0]

    snapshot = ledger.get(stored_before.event_id)

    assert snapshot is not None

    snapshot.amount = Decimal("999999.99")
    snapshot.currency = "USD"

    stored_after = ledger.get(stored_before.event_id)

    assert stored_after is not None
    assert stored_after.amount == Decimal("100.00")
    assert stored_after.currency == "INR"


def test_ledger_rejects_non_financial_event_object():
    class ForgedEvent:
        source_id = "ATTACKER"
        source_event_id = "forged-event"

    ledger = AppendOnlyLedger()

    with __import__("pytest").raises(TypeError):
        ledger.append(ForgedEvent())

    assert ledger.all() == []


def test_ledger_rejects_invalid_model_construct_event():
    event = FinancialEvent.model_construct(
        account_id=DEFAULT_SESSION_ID,
        source_id="ATTACKER",
        source_event_id="forged-event",
        event_type=EventType.EXPENSE,
        amount=Decimal("-999999.99"),
        currency="INR",
        direction="DEBIT",
        event_date=datetime.now(timezone.utc),
        recorded_at=datetime.now(timezone.utc),
    )

    ledger = AppendOnlyLedger()

    with __import__("pytest").raises(
        __import__("pydantic").ValidationError
    ):
        ledger.append(event)

    assert ledger.all() == []


def test_ledger_rejects_invalid_model_copy_event():
    action = payment_action()

    valid_event = FinancialEvent(
        account_id=action.session_id,
        source_id="TEST",
        source_event_id=str(action.action_id),
        event_type=EventType.EXPENSE,
        amount=Decimal("100.00"),
        currency="INR",
        direction="DEBIT",
        event_date=datetime.now(timezone.utc),
        recorded_at=datetime.now(timezone.utc),
    )

    forged_event = valid_event.model_copy(
        update={
            "amount": Decimal("-999999.99"),
            "currency": "INVALID",
        }
    )

    ledger = AppendOnlyLedger()

    with __import__("pytest").raises(
        __import__("pydantic").ValidationError
    ):
        ledger.append(forged_event)

    assert ledger.all() == []


def test_ledger_concurrent_duplicate_append_allows_only_one_event():
    ledger = AppendOnlyLedger()

    action = payment_action()

    def append_event():
        return ledger.append(
            FinancialEvent(
                account_id=action.session_id,
                source_id="CONCURRENT_TEST",
                source_event_id=str(action.action_id),
                event_type=EventType.EXPENSE,
                amount=Decimal("100.00"),
                currency="INR",
                direction="DEBIT",
                event_date=datetime.now(timezone.utc),
                recorded_at=datetime.now(timezone.utc),
            )
        )

    successful = 0
    conflicts = 0

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [
            pool.submit(append_event)
            for _ in range(100)
        ]

        for future in futures:
            try:
                future.result()
                successful += 1
            except __import__(
                "app.ledger",
                fromlist=["LedgerConflict"],
            ).LedgerConflict:
                conflicts += 1

    assert successful == 1
    assert conflicts == 99
    assert len(ledger.all()) == 1


def test_ledger_failed_append_does_not_create_phantom_event():
    ledger = AppendOnlyLedger()

    action = payment_action()

    event = FinancialEvent(
        account_id=action.session_id,
        source_id="FAILED_APPEND_TEST",
        source_event_id=str(action.action_id),
        event_type=EventType.EXPENSE,
        amount=Decimal("100.00"),
        currency="INR",
        direction="DEBIT",
        event_date=datetime.now(timezone.utc),
        recorded_at=datetime.now(timezone.utc),
    )

    original_append = ledger.append

    failed_once = True

    def fail_before_commit(incoming_event):
        nonlocal failed_once

        if failed_once:
            failed_once = False
            raise RuntimeError("simulated append failure")

        return original_append(incoming_event)

    ledger.append = fail_before_commit

    with __import__("pytest").raises(RuntimeError):
        ledger.append(event)

    assert ledger.all() == []

    stored = original_append(event)

    assert stored.amount == Decimal("100.00")
    assert stored.currency == "INR"
    assert len(ledger.all()) == 1


def test_executor_handles_ambiguous_ledger_commit_without_duplicate_event():
    class CommitThenFailLedger(AppendOnlyLedger):
        def __init__(self):
            super().__init__()
            self._fail_after_commit = True

        def append(self, event):
            if self._fail_after_commit:
                self._fail_after_commit = False
                super().append(event)
                raise __import__(
                    "app.ledger",
                    fromlist=["LedgerConflict"],
                ).LedgerConflict(
                    "simulated ambiguous commit"
                )

            return super().append(event)

    ledger = CommitThenFailLedger()
    executor = ActionExecutor(ledger)

    action = payment_action()

    first = execute_with_trusted_approval(executor, action)

    assert first.executed is False
    assert len(ledger.all()) == 1

    second = execute_with_trusted_approval(executor, action)

    assert second.executed is False
    assert len(ledger.all()) == 1

def test_financial_account_context_sets_event_account_id():
    from uuid import uuid4
    from app.financial_account_context import _issue_internal_financial_account_context
    from datetime import datetime, timezone, timedelta

    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)
    action = payment_action()

    target_acc_id = uuid4()
    now = datetime.now(timezone.utc)
    fac = _issue_internal_financial_account_context(
        account_id=target_acc_id,
        subject_id=uuid4(),
        session_id=uuid4(),
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
    )

    auth_ctx = trusted_context_for_action(action)
    approval = trusted_approval_for_action(action, auth_ctx)
    result = executor.execute(
        action,
        auth_ctx,
        approval,
        financial_account_context=fac,
    )

    assert result.executed is True
    events = ledger.all()
    assert len(events) == 1
    assert events[0].account_id == str(target_acc_id)


def test_untrusted_financial_account_context_rejected():
    from uuid import uuid4
    from app.financial_account_context import FinancialAccountContext
    from datetime import datetime, timezone, timedelta

    ledger = AppendOnlyLedger()
    executor = ActionExecutor(ledger)
    action = payment_action()

    now = datetime.now(timezone.utc)
    untrusted_fac = FinancialAccountContext(
        account_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        issued_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(minutes=5),
    )

    auth_ctx = trusted_context_for_action(action)
    approval = trusted_approval_for_action(action, auth_ctx)
    result = executor.execute(
        action,
        auth_ctx,
        approval,
        financial_account_context=untrusted_fac,
    )

    assert result.executed is False
    assert "financial account context" in result.reason
    assert len(ledger.all()) == 0
