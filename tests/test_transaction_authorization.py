"""Tests for M4 Transaction Authorization Policy Engine."""

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4
import pytest

from app.approval_evidence import _issue_internal_approval_evidence
from app.authorization_context import (
    AuthorizationState,
    _issue_internal_authorization_context,
)
from app.models import ActionRequest
from app.risk import DefaultRiskEngine, RiskLevel
from app.step_up import DefaultStepUpProvider, StepUpMethod
from app.transaction_authorization import (
    AuthorizationDecision,
    AuthorizationReason,
    DefaultTransactionAuthorizationPolicy,
)
from tests.test_risk import _make_context


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _setup_payment_flow(
    risk_level: RiskLevel = RiskLevel.LOW,
    auth_state: AuthorizationState = AuthorizationState.AUTHENTICATED,
    amount: Decimal = Decimal("100.00"),
    currency: str = "USD",
    destination: str = "dest-1",
    include_step_up: bool = True,
    include_approval: bool = True,
):
    now = _utc_now()
    subj_id = uuid4()
    sess_id = uuid4()
    act_id = uuid4()

    action = ActionRequest(
        action_id=act_id,
        action_type="PAYMENT",
        session_id=str(sess_id),
        amount=amount,
        currency=currency,
        destination_id=destination,
        authorization_state="AUTHENTICATED",
    )

    auth_ctx = _issue_internal_authorization_context(
        session_id=sess_id,
        subject_id=subj_id,
        state=auth_state,
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )

    risk_engine = DefaultRiskEngine()
    ctx = _make_context(amount=amount)
    object.__setattr__(ctx, "subject_id", subj_id)
    object.__setattr__(ctx, "session_id", sess_id)
    object.__setattr__(ctx, "action", action)
    object.__setattr__(ctx, "authorization_context", auth_ctx)
    risk_eval = risk_engine.evaluate(ctx)

    step_up_ev = None
    if include_step_up:
        provider = DefaultStepUpProvider()
        chal, raw_n = provider.issue_challenge(
            subject_id=subj_id,
            session_id=sess_id,
            action_id=act_id,
            method=StepUpMethod.TOTP,
            now=now,
        )
        step_up_ev = provider.verify_challenge(challenge=chal, proof=raw_n, now=now)

    approval_ev = None
    if include_approval:
        approval_ev = _issue_internal_approval_evidence(
            action_id=act_id,
            session_id=sess_id,
            subject_id=subj_id,
            destination_id=destination,
            amount=amount,
            currency=currency,
            approved_at=now,
            expires_at=now + timedelta(minutes=5),
        )

    return action, auth_ctx, risk_eval, step_up_ev, approval_ev, now


def test_unauthenticated_payment_denied():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, step_up_ev, approval_ev, now = _setup_payment_flow(
        auth_state=AuthorizationState.UNVERIFIED,
    )
    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=step_up_ev,
        approval_evidence=approval_ev,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.DENY
    assert dec.reason == AuthorizationReason.UNAUTHENTICATED


def test_authenticated_payment_without_step_up_requires_step_up():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, _, approval_ev, now = _setup_payment_flow(
        include_step_up=False,
    )
    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=None,
        approval_evidence=approval_ev,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.STEP_UP_REQUIRED
    assert dec.reason == AuthorizationReason.STEP_UP_REQUIRED


def test_critical_risk_payment_denied():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, step_up_ev, approval_ev, now = _setup_payment_flow()
    object.__setattr__(risk_eval, "level", RiskLevel.CRITICAL)

    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=step_up_ev,
        approval_evidence=approval_ev,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.DENY
    assert dec.reason == AuthorizationReason.RISK_TOO_HIGH


def test_valid_step_up_and_valid_approval_allowed():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, step_up_ev, approval_ev, now = _setup_payment_flow()

    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=step_up_ev,
        approval_evidence=approval_ev,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.ALLOW
    assert dec.reason == AuthorizationReason.PERMITTED
    assert dec.is_trusted() is True


def test_valid_step_up_with_mismatched_approval_denied():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, step_up_ev, _, now = _setup_payment_flow()

    mismatched_approval = _issue_internal_approval_evidence(
        action_id=action.action_id,
        session_id=auth_ctx.session_id,
        subject_id=auth_ctx.subject_id,
        destination_id="attacker-destination",
        amount=action.amount,
        currency=action.currency,
        approved_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=step_up_ev,
        approval_evidence=mismatched_approval,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.DENY
    assert dec.reason == AuthorizationReason.TRANSACTION_MISMATCH


def test_expired_approval_evidence_denied():
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, _, _, now = _setup_payment_flow()

    provider = DefaultStepUpProvider()
    chal, raw_n = provider.issue_challenge(
        subject_id=auth_ctx.subject_id,
        session_id=auth_ctx.session_id,
        action_id=action.action_id,
        method=StepUpMethod.TOTP,
        now=now,
        ttl=timedelta(hours=1),
    )
    long_lived_step_up = provider.verify_challenge(challenge=chal, proof=raw_n, now=now)
    object.__setattr__(long_lived_step_up, "expires_at", now + timedelta(hours=1))

    expired_approval = _issue_internal_approval_evidence(
        action_id=action.action_id,
        session_id=auth_ctx.session_id,
        subject_id=auth_ctx.subject_id,
        destination_id=action.destination_id,
        amount=action.amount,
        currency=action.currency,
        approved_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=1),
    )

    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=long_lived_step_up,
        approval_evidence=expired_approval,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.DENY
    assert dec.reason == AuthorizationReason.APPROVAL_EXPIRED


def test_untrusted_approval_evidence_denied():
    from app.approval_evidence import ApprovalEvidence
    policy = DefaultTransactionAuthorizationPolicy()
    action, auth_ctx, risk_eval, step_up_ev, _, now = _setup_payment_flow()

    untrusted_approval = ApprovalEvidence(
        approval_id=uuid4(),
        action_id=action.action_id,
        session_id=auth_ctx.session_id,
        subject_id=auth_ctx.subject_id,
        destination_id=action.destination_id,
        amount=action.amount,
        currency=action.currency,
        approved_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    dec = policy.decide(
        action=action,
        authorization_context=auth_ctx,
        risk_evaluation=risk_eval,
        step_up_evidence=step_up_ev,
        approval_evidence=untrusted_approval,
        now=now,
    )
    assert dec.decision == AuthorizationDecision.DENY
    assert dec.reason == AuthorizationReason.APPROVAL_INVALID