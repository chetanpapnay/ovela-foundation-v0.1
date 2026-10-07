from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

import app.security as security
from app.approval_evidence import (
    ApprovalEvidenceInvalid,
    ApprovalEvidenceRegistry,
    _issue_internal_approval_evidence,
)
from app.authorization_context import (
    AuthorizationContextInvalid,
    AuthorizationState,
    _issue_internal_authorization_context,
)
from app.models import ActionRequest
from app.security import authorize_action
from tests.authorization_test_helpers import DEFAULT_SESSION_ID


def _action():
    return ActionRequest(
        session_id=DEFAULT_SESSION_ID,
        action_type="PAYMENT_INITIATE",
        authorization_state="STEP_UP_VERIFIED",
        amount=Decimal("100.00"),
        currency="INR",
        destination_id="merchant-1",
        destination_verified=True,
        user_confirmation=True,
    )


def _context(issued_at, expires_at, subject_id=None):
    return _issue_internal_authorization_context(
        session_id=UUID(DEFAULT_SESSION_ID),
        subject_id=subject_id or uuid4(),
        state=AuthorizationState.STEP_UP_VERIFIED,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _approval(action, context, approved_at, expires_at):
    return _issue_internal_approval_evidence(
        action_id=action.action_id,
        session_id=UUID(action.session_id),
        subject_id=context.subject_id,
        destination_id=action.destination_id,
        amount=action.amount,
        currency=action.currency,
        approved_at=approved_at,
        expires_at=expires_at,
    )


def test_valid_current_context_and_approval_are_allowed():
    now = datetime.now(timezone.utc)
    action = _action()
    context = _context(now - timedelta(minutes=1), now + timedelta(minutes=5))
    approval = _approval(
        action, context, now - timedelta(seconds=1), now + timedelta(minutes=5)
    )

    assert authorize_action(action, context, approval).allowed is True


def test_future_dated_approval_is_rejected_by_authorization():
    now = datetime.now(timezone.utc)
    action = _action()
    context = _context(now - timedelta(minutes=1), now + timedelta(hours=3))
    approval = _approval(
        action, context, now + timedelta(hours=1), now + timedelta(hours=2)
    )

    decision = authorize_action(action, context, approval)

    assert decision.allowed is False


def test_future_dated_context_is_rejected_by_authorization():
    now = datetime.now(timezone.utc)
    action = _action()
    context = _context(now + timedelta(hours=1), now + timedelta(hours=2))
    approval = _approval(
        action, context, now - timedelta(seconds=1), now + timedelta(minutes=5)
    )

    decision = authorize_action(action, context, approval)

    assert decision.allowed is False


def test_future_dated_approval_fails_require_valid_at():
    now = datetime.now(timezone.utc)
    action = _action()
    context = _context(now - timedelta(minutes=1), now + timedelta(hours=3))
    approval = _approval(
        action, context, now + timedelta(hours=1), now + timedelta(hours=2)
    )

    with pytest.raises(ApprovalEvidenceInvalid):
        approval.require_valid_at(now)


def test_future_dated_context_fails_require_valid_at():
    now = datetime.now(timezone.utc)
    context = _context(now + timedelta(hours=1), now + timedelta(hours=2))

    with pytest.raises(AuthorizationContextInvalid):
        context.require_valid_at(now)


def test_registry_rejects_future_dated_approval_without_consuming_it():
    now = datetime.now(timezone.utc)
    action = _action()
    context = _context(now - timedelta(minutes=1), now + timedelta(hours=3))
    approval = _approval(
        action, context, now + timedelta(hours=1), now + timedelta(hours=2)
    )
    registry = ApprovalEvidenceRegistry()

    with pytest.raises(ApprovalEvidenceInvalid):
        registry.consume(approval, now=now)

    assert registry.is_consumed(approval.approval_id) is False


def test_small_clock_skew_is_tolerated():
    now = datetime.now(timezone.utc)
    action = _action()
    context = _context(now + timedelta(seconds=1), now + timedelta(minutes=5))
    approval = _approval(
        action, context, now + timedelta(seconds=1), now + timedelta(minutes=5)
    )

    context.require_valid_at(now)
    approval.require_valid_at(now)


def test_trusted_now_comes_from_temporal_boundary(monkeypatch):
    fixed = datetime(2030, 1, 1, 12, 0, tzinfo=timezone.utc)

    monkeypatch.setattr(
        security,
        "from_server_clock",
        lambda *args, **kwargs: SimpleNamespace(timestamp_utc=fixed),
    )

    assert security._trusted_now() == fixed