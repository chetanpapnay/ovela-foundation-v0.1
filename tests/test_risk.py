"""Tests for M4 Risk Domain and Default Risk Engine."""

from datetime import datetime, timezone
from decimal import Decimal
from uuid import uuid4
import pytest

from app.authorization_context import (
    AuthorizationState,
    _issue_internal_authorization_context,
)
from app.models import ActionRequest
from app.risk import (
    DefaultRiskEngine,
    RiskAssessmentContext,
    RiskContextInvalid,
    RiskFactor,
    RiskFactorName,
    RiskFactorStatus,
    RiskInvalid,
    RiskLevel,
    RiskUntrusted,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _make_context(
    amount: Decimal = Decimal("50.00"),
    assurance: int = 100,
    device_trust: int | None = 100,
    novelty: int | None = 0,
    auth_failures: int = 0,
    sec_events: int = 0,
    is_trusted_auth: bool = True,
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
        currency="USD",
        destination_id="dest-1",
        authorization_state="AUTHENTICATED",  # Legacy wire field requirement
    )

    if is_trusted_auth:
        from datetime import timedelta
        auth_ctx = _issue_internal_authorization_context(
            session_id=sess_id,
            subject_id=subj_id,
            state=AuthorizationState.AUTHENTICATED,
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )
    else:
        from app.authorization_context import AuthorizationContext
        from datetime import timedelta
        auth_ctx = AuthorizationContext(
            context_id=uuid4(),
            session_id=sess_id,
            subject_id=subj_id,
            state=AuthorizationState.AUTHENTICATED,
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )

    return RiskAssessmentContext(
        subject_id=subj_id,
        session_id=sess_id,
        action=action,
        authorization_context=auth_ctx,
        evaluated_at=now,
        authentication_assurance=assurance,
        device_trust=device_trust,
        network_trust=100,
        destination_novelty=novelty,
        velocity_score=0,
        recent_auth_failures=auth_failures,
        recent_security_events=sec_events,
    )


def test_valid_low_risk_evaluation():
    engine = DefaultRiskEngine()
    ctx = _make_context(amount=Decimal("10.00"), assurance=100, device_trust=100, novelty=0)
    eval_res = engine.evaluate(ctx)
    assert eval_res.level == RiskLevel.LOW
    assert eval_res.score < Decimal("25")
    assert eval_res.is_trusted() is True


def test_valid_medium_risk_evaluation():
    engine = DefaultRiskEngine()
    ctx = _make_context(amount=Decimal("2000.00"), assurance=70, device_trust=50, novelty=60)
    eval_res = engine.evaluate(ctx)
    assert eval_res.level in (RiskLevel.MEDIUM, RiskLevel.HIGH)
    assert eval_res.score >= Decimal("25")
    assert eval_res.is_trusted() is True


def test_valid_high_risk_evaluation():
    engine = DefaultRiskEngine()
    ctx = _make_context(amount=Decimal("8000.00"), assurance=40, device_trust=20, novelty=90, auth_failures=2)
    eval_res = engine.evaluate(ctx)
    assert eval_res.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert eval_res.score >= Decimal("50")


def test_valid_critical_evaluation():
    engine = DefaultRiskEngine()
    ctx = _make_context(amount=Decimal("10000.00"), assurance=10, device_trust=0, novelty=100, sec_events=2)
    eval_res = engine.evaluate(ctx)
    assert eval_res.level == RiskLevel.CRITICAL
    assert eval_res.score >= Decimal("75")


def test_missing_telemetry_conservative_result():
    engine = DefaultRiskEngine()
    # Missing device trust and novelty
    ctx = _make_context(amount=Decimal("10.00"), assurance=100, device_trust=None, novelty=None)
    eval_res = engine.evaluate(ctx)
    # Never downgrades; unknown telemetry conservatively keeps risk elevated
    assert eval_res.level != RiskLevel.LOW
    assert eval_res.is_trusted() is True


def test_untrusted_authorization_context_rejected():
    engine = DefaultRiskEngine()
    ctx = _make_context(is_trusted_auth=False)
    with pytest.raises(RiskUntrusted):
        engine.evaluate(ctx)


def test_session_subject_mismatch_fails_closed():
    now = _utc_now()
    subj1 = uuid4()
    subj2 = uuid4()
    sess_id = uuid4()
    from datetime import timedelta
    auth_ctx = _issue_internal_authorization_context(
        session_id=sess_id,
        subject_id=subj1,
        state=AuthorizationState.AUTHENTICATED,
        issued_at=now,
        expires_at=now + timedelta(hours=1),
    )
    action = ActionRequest(
        action_id=uuid4(),
        action_type="PAYMENT",
        session_id=str(sess_id),
        amount=Decimal("10.00"),
        currency="USD",
        destination_id="d1",
        authorization_state="AUTHENTICATED",
    )
    with pytest.raises(RiskContextInvalid):
        RiskAssessmentContext(
            subject_id=subj2,  # mismatch with auth_ctx
            session_id=sess_id,
            action=action,
            authorization_context=auth_ctx,
            evaluated_at=now,
            authentication_assurance=100,
            device_trust=100,
            network_trust=100,
            destination_novelty=0,
            velocity_score=0,
            recent_auth_failures=0,
            recent_security_events=0,
        )