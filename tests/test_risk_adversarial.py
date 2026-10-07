"""Adversarial and boundary tests for M4 Risk Evaluation."""

from datetime import datetime, timezone
from decimal import Decimal
from uuid import uuid4
import pytest

from app.risk import (
    DefaultRiskEngine,
    RiskAssessmentContext,
    RiskContextInvalid,
    RiskEvaluation,
    RiskFactor,
    RiskFactorName,
    RiskFactorStatus,
    RiskInvalid,
    RiskLevel,
    RiskUntrusted,
)
from tests.test_risk import _make_context, _utc_now


def test_caller_cannot_fabricate_trusted_risk_evaluation():
    now = _utc_now()
    fake_eval = RiskEvaluation(
        evaluation_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        action_id=uuid4(),
        level=RiskLevel.LOW,
        score=Decimal("0.00"),
        factors=(),
        evaluated_at=now,
        policy_version="2026.1-M4",
        trusted=True,  # Caller sets trusted=True without private marker
    )
    assert fake_eval.is_trusted() is False


def test_score_greater_than_100_rejected():
    now = _utc_now()
    with pytest.raises(RiskInvalid):
        RiskEvaluation(
            evaluation_id=uuid4(),
            subject_id=uuid4(),
            session_id=uuid4(),
            action_id=uuid4(),
            level=RiskLevel.HIGH,
            score=Decimal("101.00"),
            factors=(),
            evaluated_at=now,
            policy_version="2026.1-M4",
        )


def test_negative_score_rejected():
    now = _utc_now()
    with pytest.raises(RiskInvalid):
        RiskEvaluation(
            evaluation_id=uuid4(),
            subject_id=uuid4(),
            session_id=uuid4(),
            action_id=uuid4(),
            level=RiskLevel.LOW,
            score=Decimal("-5.00"),
            factors=(),
            evaluated_at=now,
            policy_version="2026.1-M4",
        )


def test_nan_score_rejected():
    now = _utc_now()
    with pytest.raises(RiskInvalid):
        RiskEvaluation(
            evaluation_id=uuid4(),
            subject_id=uuid4(),
            session_id=uuid4(),
            action_id=uuid4(),
            level=RiskLevel.LOW,
            score=Decimal("NaN"),
            factors=(),
            evaluated_at=now,
            policy_version="2026.1-M4",
        )


def test_infinity_score_rejected():
    now = _utc_now()
    with pytest.raises(RiskInvalid):
        RiskEvaluation(
            evaluation_id=uuid4(),
            subject_id=uuid4(),
            session_id=uuid4(),
            action_id=uuid4(),
            level=RiskLevel.LOW,
            score=Decimal("Infinity"),
            factors=(),
            evaluated_at=now,
            policy_version="2026.1-M4",
        )


def test_factor_negative_weight_rejected():
    now = _utc_now()
    with pytest.raises(RiskInvalid):
        RiskFactor(
            name=RiskFactorName.TRANSACTION_AMOUNT,
            value=Decimal("10.00"),
            weight=Decimal("-0.5"),
            status=RiskFactorStatus.MEASURED,
            observed_at=now,
            source="test",
        )


def test_unknown_telemetry_cannot_lower_risk():
    engine = DefaultRiskEngine()
    # High risk inputs with unknown telemetry
    ctx = _make_context(amount=Decimal("5000.00"), assurance=50, device_trust=None, novelty=None)
    eval_res = engine.evaluate(ctx)
    assert eval_res.level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


def test_malformed_assurance_score_rejected():
    with pytest.raises(RiskContextInvalid):
        _make_context(assurance=150)  # > 100
    with pytest.raises(RiskContextInvalid):
        _make_context(assurance=-10)  # < 0


def test_expired_auth_context_fails_closed():
    engine = DefaultRiskEngine()
    from datetime import timedelta
    ctx = _make_context()
    # Evaluate at a time past context expiration
    future_time = ctx.authorization_context.expires_at + timedelta(minutes=5)
    expired_ctx = RiskAssessmentContext(
        subject_id=ctx.subject_id,
        session_id=ctx.session_id,
        action=ctx.action,
        authorization_context=ctx.authorization_context,
        evaluated_at=future_time,
        authentication_assurance=100,
        device_trust=100,
        network_trust=100,
        destination_novelty=0,
        velocity_score=0,
        recent_auth_failures=0,
        recent_security_events=0,
    )
    with pytest.raises(RiskContextInvalid):
        engine.evaluate(expired_ctx)