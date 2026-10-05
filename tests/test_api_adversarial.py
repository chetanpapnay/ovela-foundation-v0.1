import os

from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_internal_events_disabled_without_server_key(monkeypatch):
    monkeypatch.delenv("OVELA_INTERNAL_KEY", raising=False)

    response = client.get("/internal/events")

    assert response.status_code == 503
    assert "disabled" in response.json()["detail"].lower()


def test_internal_events_reject_missing_key(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "test-secret")

    response = client.get("/internal/events")

    assert response.status_code == 403
    assert "authorization failed" in response.json()["detail"].lower()


def test_internal_events_reject_wrong_key(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.get(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "wrong-secret",
        },
    )

    assert response.status_code == 403
    assert "authorization failed" in response.json()["detail"].lower()


def test_internal_events_accept_correct_key(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.get(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
    )

    assert response.status_code == 200
    assert response.json() == []


def test_authorization_endpoint_rejects_missing_key(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        json={
            "session_id": "session-1",
            "action_type": "READ_FINANCIAL",
            "authorization_state": "UNVERIFIED",
        },
    )

    assert response.status_code == 403
    assert "authorization failed" in response.json()["detail"].lower()


def test_authorization_endpoint_accepts_correct_key(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "READ_FINANCIAL",
            "authorization_state": "UNVERIFIED",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["allowed"] is True
    assert body["requires_step_up"] is False
    assert body["reason"] == "read-only policy checks passed"
    assert "action_id" in body


def test_internal_key_is_not_returned_in_response(monkeypatch):
    secret = "super-secret-value"

    monkeypatch.setenv("OVELA_INTERNAL_KEY", secret)

    response = client.get(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": secret,
        },
    )

    assert response.status_code == 200
    assert secret not in response.text


def test_security_headers_are_present():
    response = client.get("/health")

    assert response.status_code == 200

    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Permissions-Policy"] == (
        "camera=(), microphone=(), geolocation=()"
    )
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]


def test_health_endpoint_does_not_require_internal_key(monkeypatch):
    monkeypatch.delenv("OVELA_INTERNAL_KEY", raising=False)

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_internal_event_append_rejects_missing_key(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "unauthorized-event",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 403
    assert "authorization failed" in response.json()["detail"].lower()


def test_internal_event_append_rejects_wrong_key(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "wrong-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "wrong-key-event",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 403
    assert "authorization failed" in response.json()["detail"].lower()


def test_internal_event_append_accepts_correct_key(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "authorized-event",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 201

    body = response.json()

    assert body["account_id"] == "session-1"
    assert body["source_id"] == "API_TEST"
    assert body["source_event_id"] == "authorized-event"
    assert body["event_type"] == "EXPENSE"
    assert body["amount"] == "100.00"
    assert body["currency"] == "INR"
    assert body["direction"] == "DEBIT"


def test_internal_event_duplicate_returns_conflict(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    payload = {
        "account_id": "session-1",
        "source_id": "API_DUPLICATE_TEST",
        "source_event_id": "duplicate-event",
        "event_type": "EXPENSE",
        "amount": "100.00",
        "currency": "INR",
        "direction": "DEBIT",
        "event_date": "2026-10-05T10:00:00Z",
    }

    headers = {
        "X-Ovela-Internal-Key": "correct-secret",
    }

    first = client.post(
        "/internal/events",
        headers=headers,
        json=payload,
    )

    second = client.post(
        "/internal/events",
        headers=headers,
        json=payload,
    )

    assert first.status_code == 201
    assert second.status_code == 409
    assert "duplicate" in second.json()["detail"].lower()


def test_internal_event_append_rejects_invalid_amount(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "invalid-amount",
            "event_type": "EXPENSE",
            "amount": "not-a-number",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_invalid_currency(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "invalid-currency",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INVALID",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_invalid_direction(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "invalid-direction",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "INVALID",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_negative_amount(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "negative-amount",
            "event_type": "EXPENSE",
            "amount": "-100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_missing_source_event_id(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_missing_account_id(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "source_id": "API_TEST",
            "source_event_id": "missing-account-id",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_missing_event_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "missing-event-type",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_invalid_event_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "invalid-event-type",
            "event_type": "FAKE_EVENT",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_missing_currency(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "missing-currency",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_missing_direction(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "missing-direction",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_missing_event_date(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "missing-event-date",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_invalid_event_date(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "invalid-event-date",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "not-a-date",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_zero_amount(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "zero-amount",
            "event_type": "EXPENSE",
            "amount": "0.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_preserves_nonblank_identifier_whitespace(
    monkeypatch,
):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": " session-1 ",
            "source_id": "API_TEST",
            "source_event_id": "identifier-whitespace",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 201
    assert response.json()["account_id"] == " session-1 "


def test_internal_event_append_rejects_blank_source_event_id(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "session-1",
            "source_id": "API_TEST",
            "source_event_id": "   ",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_internal_event_append_rejects_blank_account_id(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/events",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "account_id": "   ",
            "source_id": "API_TEST",
            "source_event_id": "blank-account-id",
            "event_type": "EXPENSE",
            "amount": "100.00",
            "currency": "INR",
            "direction": "DEBIT",
            "event_date": "2026-10-05T10:00:00Z",
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_blank_destination_id(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "   ",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_blank_session_id(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "   ",
            "action_type": "READ_FINANCIAL",
            "authorization_state": "UNVERIFIED",
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_unverified_destination(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": False,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["allowed"] is False
    assert "destination" in body["reason"].lower()


def test_authorization_rejects_unconfirmed_payment(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": False,
            "destination_verified": True,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["allowed"] is False
    assert "confirmation" in body["reason"].lower()


def test_authorization_rejects_confirmation_for_different_action(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "action_id": "11111111-1111-1111-1111-111111111111",
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "confirmation_action_id": "22222222-2222-2222-2222-222222222222",
            "destination_verified": True,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["allowed"] is False
    assert "confirmation" in body["reason"].lower()


def test_authorization_rejects_invalid_authorization_state(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "ADMIN_OVERRIDE",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_missing_authorization_state(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_unknown_action_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "ADMIN_OVERRIDE",
            "authorization_state": "STEP_UP_VERIFIED",
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["allowed"] is False
    assert "unknown" in body["reason"].lower()


def test_authorization_rejects_invalid_session_id_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": 12345,
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_invalid_action_type_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": 12345,
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_invalid_authorization_state_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": 12345,
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_invalid_amount_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "not-a-number",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_invalid_currency_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": 12345,
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_invalid_destination_id_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": 12345,
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_invalid_user_confirmation_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": "yes",
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_invalid_destination_verified_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": "true",
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_invalid_confirmation_action_id_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
            "confirmation_action_id": "not-a-uuid",
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_invalid_action_id_type(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "action_id": "not-a-uuid",
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_invalid_confirmation_action_id_value(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
            "confirmation_action_id": (
                "00000000-0000-0000-0000-000000000000"
            ),
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["allowed"] is False
    assert "confirmation" in body["reason"].lower()


def test_authorization_rejects_zero_payment_amount(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "0",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["allowed"] is False
    assert "amount" in body["reason"].lower()


def test_authorization_rejects_negative_payment_amount(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "-1.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_missing_payment_amount(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["allowed"] is False
    assert "amount" in body["reason"].lower()


def test_authorization_rejects_non_finite_payment_amount(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "NaN",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_infinite_payment_amount(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "Infinity",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 422


def test_authorization_rejects_negative_zero_equivalent_amount(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "-0.00",
            "currency": "INR",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["allowed"] is False
    assert "amount" in body["reason"].lower()


def test_authorization_rejects_missing_currency(monkeypatch):
    monkeypatch.setenv("OVELA_INTERNAL_KEY", "correct-secret")

    response = client.post(
        "/internal/security/authorize",
        headers={
            "X-Ovela-Internal-Key": "correct-secret",
        },
        json={
            "session_id": "session-1",
            "action_type": "PAYMENT_INITIATE",
            "authorization_state": "STEP_UP_VERIFIED",
            "amount": "100.00",
            "destination_id": "destination-1",
            "user_confirmation": True,
            "destination_verified": True,
        },
    )

    assert response.status_code == 200

    body = response.json()

    assert body["allowed"] is False
    assert "currency" in body["reason"].lower()