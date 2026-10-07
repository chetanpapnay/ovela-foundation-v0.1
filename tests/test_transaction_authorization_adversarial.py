"""Adversarial attack and boundary tests for M4 Transaction Authorization."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4
import pytest

from app.approval_evidence import _issue_internal_approval_evidence
from app.models import ActionRequest
from app.step_up import DefaultStepUpProvider, StepUpMethod
from app.transaction_authorization import (
    AuthorizationDecision,
    AuthorizationReason,
    DefaultTransactionAuthorizationPolicy,
    TransactionAuthorizationDecision,
)
from tests.test_transaction_authorization import _setup_payment_flow, _utc_now


def test_caller_cannot_fabricate_trusted_authorization_decision():
    now = _utc_now()
    fake_decision = TransactionAuthorizationDecision(
        decision_id=uuid4(),
        action_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        decision=AuthorizationDecision.ALLOW,
        reason=AuthorizationReason.PERMITTED,
        risk_evaluation_id=uuid4(),
        step_up_evidence_id=None,
        evaluated_at=now,
        policy_version="2026.1-M4",
        trusted=True,
    )
    assert fake_decision.is_trusted() is False


def test_caller_confirmation_field_cannot_bypass_authorization():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, _, approval_ev, now = _setup_payment_flow(
        include_step_up=False,
    )
    object.__setattr__(action, "user_confirmation", True)
    object.__setattr__(action, "confirmation_action_id", str(uuid4()))

    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=None,
        approval_evidence=approval_ev,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.STEP_UP_REQUIRED


def test_amount_tampering_after_approval_denied():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, step_up_ev, approval_ev, now = _setup_payment_flow(
        amount=Decimal("50.00"),
    )
    object.__setattr__(action, "amount", Decimal("5000.00"))

    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=step_up_ev,
        approval_evidence=approval_ev,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.DENY
    assert dec.reason == AuthorizationReason.TRANSACTION_MISMATCH


def test_currency_tampering_after_approval_denied():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, step_up_ev, approval_ev, now = _setup_payment_flow(
        currency="USD",
    )
    object.__setattr__(action, "currency", "EUR")

    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=step_up_ev,
        approval_evidence=approval_ev,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.DENY
    assert dec.reason == AuthorizationReason.TRANSACTION_MISMATCH


def test_destination_tampering_after_approval_denied():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, step_up_ev, approval_ev, now = _setup_payment_flow(
        destination="merchant-account",
    )
    object.__setattr__(action, "destination_id", "attacker-account")

    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=step_up_ev,
        approval_evidence=approval_ev,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.DENY
    assert dec.reason == AuthorizationReason.TRANSACTION_MISMATCH


def test_session_id_substitution_after_step_up_denied():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, step_up_ev, approval_ev, now = _setup_payment_flow()
    other_session_id = uuid4()
    object.__setattr__(step_up_ev, "session_id", other_session_id)

    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=step_up_ev,
        approval_evidence=approval_ev,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.DENY
    assert dec.reason == AuthorizationReason.TRANSACTION_MISMATCH