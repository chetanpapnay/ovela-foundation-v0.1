"""
OVELA / JURIX Risk Evaluation Engine.

Security principles:
    - Risk is advisory until policy consumes it.
    - Missing or unknown telemetry cannot lower risk or reduce required assurance (INV-11).
    - Risk scores are finite decimals strictly bounded in [0, 100].
    - Direct caller construction is untrusted; only the engine marks trusted provenance.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Final, Protocol
from uuid import UUID, uuid4

from .authorization_context import AuthorizationContext
from .models import ActionRequest


class RiskFactorName(StrEnum):
    TRANSACTION_AMOUNT = "TRANSACTION_AMOUNT"
    DESTINATION_NOVELTY = "DESTINATION_NOVELTY"
    DESTINATION_CHANGE = "DESTINATION_CHANGE"
    SESSION_AGE = "SESSION_AGE"
    AUTHENTICATION_ASSURANCE = "AUTHENTICATION_ASSURANCE"
    DEVICE_TRUST = "DEVICE_TRUST"
    NETWORK_TRUST = "NETWORK_TRUST"
    GEO_ANOMALY = "GEO_ANOMALY"
    VELOCITY = "VELOCITY"
    RECENT_SECURITY_EVENT = "RECENT_SECURITY_EVENT"
    RECENT_AUTH_FAILURE = "RECENT_AUTH_FAILURE"
    BEHAVIORAL_DEVIATION = "BEHAVIORAL_DEVIATION"
    ACCOUNT_STATE = "ACCOUNT_STATE"
    PROVIDER_ANOMALY = "PROVIDER_ANOMALY"
    DATA_QUALITY = "DATA_QUALITY"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class RiskFactorStatus(StrEnum):
    OBSERVED = "OBSERVED"
    MEASURED = "MEASURED"
    INFERRED = "INFERRED"
    SUSPECTED = "SUSPECTED"
    UNKNOWN = "UNKNOWN"


class RiskError(Exception):
    """Base error for risk engine violations."""


class RiskInvalid(RiskError):
    """Raised when risk factors, scores, or models violate invariants."""


class RiskUntrusted(RiskError):
    """Raised when an evaluation lacks trusted engine provenance."""


class RiskContextInvalid(RiskError):
    """Raised when risk assessment context is inconsistent or invalid."""


class RiskEvaluationInvalid(RiskError):
    """Raised when risk evaluation structure is invalid."""


class RiskUnavailable(RiskError):
    """Raised when required risk telemetry cannot be computed."""


@dataclass(frozen=True, slots=True)
class RiskFactor:
    name: RiskFactorName
    value: Decimal
    weight: Decimal
    status: RiskFactorStatus
    observed_at: datetime
    source: str

    def __post_init__(self) -> None:
        if not isinstance(self.name, RiskFactorName):
            raise TypeError("name must be a RiskFactorName")
        if not isinstance(self.value, Decimal):
            raise TypeError("value must be a Decimal")
        if not self.value.is_finite():
            raise RiskInvalid("value must be finite")
        if not isinstance(self.weight, Decimal):
            raise TypeError("weight must be a Decimal")
        if not self.weight.is_finite() or self.weight < Decimal("0"):
            raise RiskInvalid("weight must be finite and non-negative")
        if not isinstance(self.status, RiskFactorStatus):
            raise TypeError("status must be a RiskFactorStatus")
        if not isinstance(self.observed_at, datetime) or self.observed_at.tzinfo is None:
            raise RiskInvalid("observed_at must be a timezone-aware datetime")
        if not isinstance(self.source, str) or not self.source.strip():
            raise RiskInvalid("source must be a non-empty string")


_INTERNAL_RISK_MARKER: Final[object] = object()


@dataclass(frozen=True, slots=True)
class RiskEvaluation:
    evaluation_id: UUID
    subject_id: UUID
    session_id: UUID
    action_id: UUID
    level: RiskLevel
    score: Decimal
    factors: tuple[RiskFactor, ...]
    evaluated_at: datetime
    policy_version: str
    trusted: bool = field(default=False)
    _provenance_marker: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.evaluation_id, UUID):
            raise TypeError("evaluation_id must be a UUID")
        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")
        if not isinstance(self.action_id, UUID):
            raise TypeError("action_id must be a UUID")
        if not isinstance(self.level, RiskLevel):
            raise TypeError("level must be a RiskLevel")
        if not isinstance(self.score, Decimal):
            raise TypeError("score must be a Decimal")
        if not self.score.is_finite():
            raise RiskInvalid("score must be finite")
        if not (Decimal("0") <= self.score <= Decimal("100")):
            raise RiskInvalid("score must be between 0 and 100")
        if not isinstance(self.factors, tuple):
            raise TypeError("factors must be a tuple")
        for f in self.factors:
            if not isinstance(f, RiskFactor):
                raise TypeError("each factor must be a RiskFactor")
        if not isinstance(self.evaluated_at, datetime) or self.evaluated_at.tzinfo is None:
            raise RiskInvalid("evaluated_at must be a timezone-aware datetime")
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise RiskInvalid("policy_version must be non-empty")

    def is_trusted(self) -> bool:
        return self.trusted is True and self._provenance_marker is _INTERNAL_RISK_MARKER


@dataclass(frozen=True, slots=True)
class RiskAssessmentContext:
    subject_id: UUID
    session_id: UUID
    action: ActionRequest
    authorization_context: AuthorizationContext
    evaluated_at: datetime
    authentication_assurance: int
    device_trust: int | None
    network_trust: int | None
    destination_novelty: int | None
    velocity_score: int | None
    recent_auth_failures: int
    recent_security_events: int

    def __post_init__(self) -> None:
        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")
        if not isinstance(self.action, ActionRequest):
            raise TypeError("action must be an ActionRequest")
        if not isinstance(self.authorization_context, AuthorizationContext):
            raise TypeError("authorization_context must be an AuthorizationContext")
        if not isinstance(self.evaluated_at, datetime) or self.evaluated_at.tzinfo is None:
            raise RiskContextInvalid("evaluated_at must be a timezone-aware datetime")

        # Consistency checks
        if self.subject_id != self.authorization_context.subject_id:
            raise RiskContextInvalid("subject_id mismatch with authorization_context")
        if self.session_id != self.authorization_context.session_id:
            raise RiskContextInvalid("session_id mismatch with authorization_context")
        if str(self.action.session_id) != str(self.authorization_context.session_id):
            raise RiskContextInvalid("action.session_id mismatch with authorization_context")

        if not (0 <= self.authentication_assurance <= 100):
            raise RiskContextInvalid("authentication_assurance must be in [0, 100]")
        if self.device_trust is not None and not (0 <= self.device_trust <= 100):
            raise RiskContextInvalid("device_trust must be in [0, 100]")
        if self.network_trust is not None and not (0 <= self.network_trust <= 100):
            raise RiskContextInvalid("network_trust must be in [0, 100]")
        if self.destination_novelty is not None and not (0 <= self.destination_novelty <= 100):
            raise RiskContextInvalid("destination_novelty must be in [0, 100]")
        if self.velocity_score is not None and not (0 <= self.velocity_score <= 100):
            raise RiskContextInvalid("velocity_score must be in [0, 100]")
        if self.recent_auth_failures < 0:
            raise RiskContextInvalid("recent_auth_failures must be non-negative")
        if self.recent_security_events < 0:
            raise RiskContextInvalid("recent_security_events must be non-negative")


class RiskEngine(Protocol):
    def evaluate(self, context: RiskAssessmentContext) -> RiskEvaluation:
        ...


class DefaultRiskEngine:
    """
    Production-grade, fail-closed Risk Engine.

    Default Score Bands:
        0 - 24:   LOW
        25 - 49:  MEDIUM
        50 - 74:  HIGH
        75 - 100: CRITICAL
    """

    POLICY_VERSION: Final[str] = "2026.1-M4"

    def evaluate(self, context: RiskAssessmentContext) -> RiskEvaluation:
        if not isinstance(context, RiskAssessmentContext):
            raise TypeError("context must be a RiskAssessmentContext")

        # Authorization context must be trusted
        if not context.authorization_context.is_trusted():
            raise RiskUntrusted("authorization_context lacks trusted provenance")

        # Context must not be expired at evaluated_at
        if context.authorization_context.is_expired(context.evaluated_at):
            raise RiskContextInvalid("authorization_context has expired")

        factors: list[RiskFactor] = []

        # 1. Transaction Amount factor
        amount = getattr(context.action, "amount", None)
        if amount is not None:
            try:
                dec_amount = Decimal(str(amount))
                # Bounded score based on amount magnitude: 1000 = 10, 5000 = 50, 10000 = 100
                amt_score = min(Decimal("100"), (dec_amount / Decimal("100")).quantize(Decimal("1.00")))
                factors.append(
                    RiskFactor(
                        name=RiskFactorName.TRANSACTION_AMOUNT,
                        value=amt_score,
                        weight=Decimal("0.30"),
                        status=RiskFactorStatus.MEASURED,
                        observed_at=context.evaluated_at,
                        source="action_request",
                    )
                )
            except (InvalidOperation, TypeError):
                factors.append(
                    RiskFactor(
                        name=RiskFactorName.TRANSACTION_AMOUNT,
                        value=Decimal("100"),
                        weight=Decimal("0.30"),
                        status=RiskFactorStatus.UNKNOWN,
                        observed_at=context.evaluated_at,
                        source="action_request",
                    )
                )

        # 2. Authentication assurance inverse risk
        auth_risk = Decimal(str(100 - context.authentication_assurance))
        factors.append(
            RiskFactor(
                name=RiskFactorName.AUTHENTICATION_ASSURANCE,
                value=auth_risk,
                weight=Decimal("0.25"),
                status=RiskFactorStatus.MEASURED,
                observed_at=context.evaluated_at,
                source="m3_session",
            )
        )

        # 3. Device Trust
        if context.device_trust is not None:
            dev_risk = Decimal(str(100 - context.device_trust))
            dev_status = RiskFactorStatus.MEASURED
        else:
            dev_risk = Decimal("85")  # Conservative default for unknown device
            dev_status = RiskFactorStatus.UNKNOWN

        factors.append(
            RiskFactor(
                name=RiskFactorName.DEVICE_TRUST,
                value=dev_risk,
                weight=Decimal("0.20"),
                status=dev_status,
                observed_at=context.evaluated_at,
                source="device_binding",
            )
        )

        # 4. Destination novelty
        if context.destination_novelty is not None:
            dest_score = Decimal(str(context.destination_novelty))
            dest_status = RiskFactorStatus.MEASURED
        else:
            dest_score = Decimal("75")  # Conservative default for unknown destination
            dest_status = RiskFactorStatus.UNKNOWN

        factors.append(
            RiskFactor(
                name=RiskFactorName.DESTINATION_NOVELTY,
                value=dest_score,
                weight=Decimal("0.15"),
                status=dest_status,
                observed_at=context.evaluated_at,
                source="ledger_history",
            )
        )

        # 5. Security events & auth failures penalty
        sec_penalty = Decimal(str(min(100, (context.recent_auth_failures * 20) + (context.recent_security_events * 40))))
        factors.append(
            RiskFactor(
                name=RiskFactorName.RECENT_SECURITY_EVENT,
                value=sec_penalty,
                weight=Decimal("0.10"),
                status=RiskFactorStatus.OBSERVED,
                observed_at=context.evaluated_at,
                source="security_audit",
            )
        )

        # Weighted score sum
        total_weight = sum(f.weight for f in factors)
        if total_weight <= Decimal("0"):
            score = Decimal("100")
        else:
            weighted_sum = sum(f.value * f.weight for f in factors)
            score = (weighted_sum / total_weight).quantize(Decimal("1.00"))

        score = max(Decimal("0.00"), min(Decimal("100.00"), score))

        # Risk level categorization
        if score < Decimal("25"):
            level = RiskLevel.LOW
        elif score < Decimal("50"):
            level = RiskLevel.MEDIUM
        elif score < Decimal("75"):
            level = RiskLevel.HIGH
        else:
            level = RiskLevel.CRITICAL

        # INV-11: Unknown telemetry with elevated risk cannot downgrade assurance
        unknown_high_factors = [
            f for f in factors if f.status == RiskFactorStatus.UNKNOWN and f.value >= Decimal("75")
        ]
        if unknown_high_factors:
            # If multiple critical unknowns exist or assurance is lowered, elevate level
            if len(unknown_high_factors) >= 2 or context.authentication_assurance < 70:
                if level in (RiskLevel.LOW, RiskLevel.MEDIUM):
                    level = RiskLevel.HIGH
            elif level == RiskLevel.LOW:
                level = RiskLevel.MEDIUM

        action_uuid = UUID(str(context.action.action_id)) if hasattr(context.action, "action_id") else uuid4()

        return RiskEvaluation(
            evaluation_id=uuid4(),
            subject_id=context.subject_id,
            session_id=context.session_id,
            action_id=action_uuid,
            level=level,
            score=score,
            factors=tuple(factors),
            evaluated_at=context.evaluated_at,
            policy_version=self.POLICY_VERSION,
            trusted=True,
            _provenance_marker=_INTERNAL_RISK_MARKER,
        )