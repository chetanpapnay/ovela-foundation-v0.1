from datetime import datetime, timezone
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from app.ledger import AppendOnlyLedger, LedgerConflict
from app.main import app
from app.models import ActionRequest, EventType, FinancialEvent
from app.security import authorize_action
from app.authorization_context import AuthorizationState
from tests.authorization_test_helpers import trusted_context_for_action


def event(**overrides):
    data = dict(
        account_id="acct-1",
        source_id="bank-demo",
        source_event_id="txn-1",
        event_type=EventType.EXPENSE,
        amount=Decimal("100.10"),
        currency="INR",
        direction="DEBIT",
        event_date=datetime(2026, 10, 1, tzinfo=timezone.utc),
    )
    data.update(overrides)
    return FinancialEvent(**data)


def test_decimal_amount_is_exact():
    e = event(amount=Decimal("0.10"))
    assert e.amount == Decimal("0.10")


def test_negative_amount_is_rejected():
    with pytest.raises(ValueError):
        event(amount=Decimal("-1"))


def test_ledger_rejects_replay():
    ledger = AppendOnlyLedger()
    ledger.append(event())

    with pytest.raises(LedgerConflict):
        ledger.append(event())


def test_ledger_is_append_only():
    ledger = AppendOnlyLedger()
    e = ledger.append(event())

    assert ledger.get(e.event_id) == e
    assert len(ledger.all()) == 1


def test_ledger_does_not_expose_mutable_internal_event():
    ledger = AppendOnlyLedger()
    stored = ledger.append(event(note="original"))

    stored.note = "tampered"

    persisted = ledger.get(stored.event_id)

    assert persisted is not None
    assert persisted.note == "original"


def test_ledger_all_returns_isolated_snapshot():
    ledger = AppendOnlyLedger()
    stored = ledger.append(event(note="original"))

    snapshot = ledger.all()
    snapshot[0].note = "tampered"

    persisted = ledger.get(stored.event_id)

    assert persisted is not None
    assert persisted.note == "original"


def test_ledger_rejects_non_event_objects():
    ledger = AppendOnlyLedger()

    with pytest.raises(TypeError):
        ledger.append("not an event")


def test_ledger_get_rejects_non_uuid():
    ledger = AppendOnlyLedger()

    with pytest.raises(TypeError):
        ledger.get("not-a-uuid")


def test_payment_requires_step_up_and_confirmation():
    action = ActionRequest(
        session_id="00000000-0000-0000-0000-000000000001",
        action_type="PAYMENT_INITIATE",
        authorization_state="AUTHENTICATED",
        amount=Decimal("1000"),
        currency="INR",
        destination_id="beneficiary-1",
        user_confirmation=True,
        confirmation_action_id=None,
        destination_verified=True,
    )

    decision = authorize_action(
        action,
        trusted_context_for_action(
            action,
            state=AuthorizationState.AUTHENTICATED,
        ),
    )

    assert not decision.allowed
    assert decision.requires_step_up


def test_payment_passes_policy_after_step_up():
    action = ActionRequest(
        session_id="00000000-0000-0000-0000-000000000001",
        action_type="PAYMENT_INITIATE",
        authorization_state="STEP_UP_VERIFIED",
        amount=Decimal("1000"),
        currency="INR",
        destination_id="beneficiary-1",
        user_confirmation=True,
        destination_verified=True,
    )

    action.confirmation_action_id = action.action_id

    decision = authorize_action(action, trusted_context_for_action(action))

    assert decision.allowed


def test_model_cannot_authorize_payment_without_confirmation():
    action = ActionRequest(
        session_id="00000000-0000-0000-0000-000000000001",
        action_type="PAYMENT_INITIATE",
        authorization_state="STEP_UP_VERIFIED",
        amount=Decimal("1000"),
        currency="INR",
        destination_id="beneficiary-1",
        user_confirmation=False,
        destination_verified=True,
    )

    assert not authorize_action(action, trusted_context_for_action(action)).allowed


def test_zero_payment_amount_is_blocked():
    action = ActionRequest(
        session_id="00000000-0000-0000-0000-000000000001",
        action_type="PAYMENT_INITIATE",
        authorization_state="STEP_UP_VERIFIED",
        amount=Decimal("0"),
        currency="INR",
        destination_id="beneficiary-1",
        destination_verified=True,
        user_confirmation=True,
    )

    action.confirmation_action_id = action.action_id

    decision = authorize_action(action, trusted_context_for_action(action))

    assert not decision.allowed
    assert "positive" in decision.reason


def test_missing_payment_destination_is_blocked():
    action = ActionRequest(
        session_id="00000000-0000-0000-0000-000000000001",
        action_type="PAYMENT_INITIATE",
        authorization_state="STEP_UP_VERIFIED",
        amount=Decimal("100"),
        currency="INR",
        destination_id=None,
        destination_verified=True,
        user_confirmation=True,
    )

    action.confirmation_action_id = action.action_id

    assert not authorize_action(action, trusted_context_for_action(action)).allowed


def test_unverified_identity_cannot_perform_protected_action():
    action = ActionRequest(
        session_id="00000000-0000-0000-0000-000000000001",
        action_type="SECURITY_CHANGE",
        authorization_state="UNVERIFIED",
    )

    decision = authorize_action(
        action,
        trusted_context_for_action(
            action,
            state=AuthorizationState.UNVERIFIED,
        ),
    )

    assert not decision.allowed


def test_invalid_authorization_state_is_rejected_by_model():
    with pytest.raises(ValueError):
        ActionRequest(
            session_id="00000000-0000-0000-0000-000000000001",
            action_type="SECURITY_CHANGE",
            authorization_state="ADMIN_OVERRIDE",
        )


def test_unknown_action_is_blocked():
    action = ActionRequest(
        session_id="00000000-0000-0000-0000-000000000001",
        action_type="DO_ANYTHING",
        authorization_state="AUTHENTICATED",
    )

    assert not authorize_action(action, trusted_context_for_action(action)).allowed


def test_payment_confirmation_must_bind_to_action():
    action = ActionRequest(
        session_id="00000000-0000-0000-0000-000000000001",
        action_type="PAYMENT_INITIATE",
        authorization_state="STEP_UP_VERIFIED",
        amount=Decimal("1000"),
        currency="INR",
        destination_id="beneficiary-1",
        destination_verified=True,
        user_confirmation=True,
    )

    assert not authorize_action(action, trusted_context_for_action(action)).allowed


def test_http_health():
    client = TestClient(app)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_internal_api_is_disabled_without_key(monkeypatch):
    monkeypatch.delenv("OVELA_INTERNAL_KEY", raising=False)

    client = TestClient(app)
    response = client.get("/internal/events")

    assert response.status_code == 503


def test_internal_api_rejects_missing_key(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "test-secret")

    client = TestClient(app)
    response = client.get("/internal/events")

    assert response.status_code == 403


def test_internal_api_rejects_wrong_key(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    client = TestClient(app)
    response = client.get(
        "/internal/events",
        headers={"X-Ovela-Internal-Key": "wrong-secret"},
    )

    assert response.status_code == 403
