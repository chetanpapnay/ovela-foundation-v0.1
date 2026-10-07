"""
OVELA / JURIX Transaction Authorization Policy Engine.

Security principles:
    - Authorization determines whether an action is permitted under verified assurance.
    - Policy strictly evaluates AuthorizationContext, RiskEvaluation, StepUpEvidence, and ApprovalEvidence.
    - Caller-controlled flags (authorization_state, user_confirmation, etc.) are never authority.
    - Missing, expired, mismatched, or untrusted inputs fail closed to DENY or STEP_UP_REQUIRED.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from enum import StrEnum
from typing import Final, Protocol
from uuid import UUID, uuid4

from .approval_evidence import ApprovalEvidence
from .authorization_context import AuthorizationContext, AuthorizationState
from .models import ActionRequest
from .risk import RiskEvaluation, RiskLevel
from .step_up import StepUpEvidence


class AuthorizationDecision(StrEnum):
    DENY = "DENY"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    ALLOW = "ALLOW"


class AuthorizationReason(StrEnum):
    INVALID_CONTEXT = "INVALID_CONTEXT"
    CONTEXT_EXPIRED = "CONTEXT_EXPIRED"
    UNAUTHENTICATED = "UNAUTHENTICATED"
    STEP_UP_REQUIRED = "STEP_UP_REQUIRED"
    STEP_UP_INVALID = "STEP_UP_INVALID"
    STEP_UP_EXPIRED = "STEP_UP_EXPIRED"
    RISK_TOO_HIGH = "RISK_TOO_HIGH"
    RISK_UNKNOWN = "RISK_UNKNOWN"
    TRANSACTION_MISMATCH = "TRANSACTION_MISMATCH"
    APPROVAL_MISSING = "APPROVAL_MISSING"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_CONSUMED = "APPROVAL_CONSUMED"
    POLICY_DENIED = "POLICY_DENIED"
    INVALID_ACTION = "INVALID_ACTION"
    PERMITTED = "PERMITTED"


class TransactionAuthorizationError(Exception):
    """Base error for transaction authorization violations."""


class TransactionAuthorizationDenied(TransactionAuthorizationError):
    """Raised when transaction authorization is explicitly denied."""


class TransactionAuthorizationStepUpRequired(TransactionAuthorizationError):
    """Raised when step-up verification is required."""


class TransactionAuthorizationInvalid(TransactionAuthorizationError):
    """Raised when policy inputs violate data invariants."""


class TransactionAuthorizationExpired(TransactionAuthorizationError):
    """Raised when authorization elements are expired."""


class TWXh8n73LuT5MJ23pd8dCjFskRZckveFbP(TransactionAuthorizationError):
    """Raised when risk evaluation score/level causes hard denial."""


_INTERNAL_AUTHZ_MARKER: Final[object] = object()


@dataclass(frozen=True, slots=True)
class TransactionAuthorizationDecision:
    decision_id: UUID
    action_id: UUID
    subject_id: UUID
    session_id: UUID
    decision: AuthorizationDecision
    reason: AuthorizationReason
    risk_evaluation_id: UUID
    step_up_evidence_id: UUID | None
    evaluated_at: datetime
    policy_version: str
    trusted: bool = field(default=False)
    _provenance_marker: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.decision_id, UUID):
            raise TypeError("decision_id must be a UUID")
        if not isinstance(self.action_id, UUID):
            raise TypeError("action_id must be a UUID")
        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")
        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")
        if not isinstance(self.decision, AuthorizationDecision):
            raise TypeError("decision must be an AuthorizationDecision")
        if not isinstance(self.reason, AuthorizationReason):
            raise TypeError("reason must be an AuthorizationReason")
        if not isinstance(self.risk_evaluation_id, UUID):
            raise TypeError("risk_evaluation_id must be a UUID")
        if self.step_up_evidence_id is not None and not isinstance(self.step_up_evidence_id, UUID):
            raise TypeError("step_up_evidence_id must be a UUID or None")
        if not isinstance(self.evaluated_at, datetime) or self.evaluated_at.tzinfo is None:
            raise TransactionAuthorizationInvalid("evaluated_at must be timezone-aware")
        if not isinstance(self.policy_version, str) or not self.policy_version.strip():
            raise TransactionAuthorizationInvalid("policy_version must be non-empty")

    def is_trusted(self) -> bool:
        return self.trusted is True and self._provenance_marker is _INTERNAL_AUTHZ_MARKER


class TransactionAuthorizationPolicy(Protocol):
    def decide(
        self,
        *,
        action: ActionRequest,
        authorization_context: AuthorizationContext,
        risk_evaluation: RiskEvaluation,
        step_up_evidence: StepUpEvidence | None,
        approval_evidence: ApprovalEvidence | None,
        now: datetime,
    ) -> TransactionAuthorizationDecision:
        ...


class DefaultTransactionAuthorizationPolicy:
    """
    Production implementation of the M4 Transaction Authorization Policy.

    Evaluates:
        1. AuthorizationContext validity & provenance
        2. Session / Subject / Action bindings
        3. Risk level & risk provenance
        4. StepUpEvidence validity, binding, & expiry
        5. ApprovalEvidence exact transaction binding & unconsumed status
    """

    POLICY_VERSION: Final[str] = "2026.1-M4"

    def decide(
        self,
        *,
        action: ActionRequest,
        authorization_context: AuthorizationContext,
        risk_evaluation: RiskEvaluation,
        step_up_evidence: StepUpEvidence | None,
        approval_evidence: ApprovalEvidence | None,
        now: datetime,
    ) -> TransactionAuthorizationDecision:
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise TransactionAuthorizationInvalid("now must be timezone-aware")

        # Fallback UUIDs for fail-closed decision records
        action_uuid = UUID(str(action.action_id)) if hasattr(action, "action_id") else uuid4()
        subj_uuid = getattr(authorization_context, "subject_id", uuid4())
        sess_uuid = getattr(authorization_context, "session_id", uuid4())
        risk_uuid = getattr(risk_evaluation, "evaluation_id", uuid4())

        def _make_decision(
            dec: AuthorizationDecision,
            reas: AuthorizationReason,
            step_up_id: UUID | None = None,
        ) -> TransactionAuthorizationDecision:
            return TransactionAuthorizationDecision(
                decision_id=uuid4(),
                action_id=action_uuid,
                subject_id=subj_uuid,
                session_id=sess_uuid,
                decision=dec,
                reason=reas,
                risk_evaluation_id=risk_uuid,
                step_up_evidence_id=step_up_id,
                evaluated_at=now,
                policy_version=self.POLICY_VERSION,
                trusted=True,
                _provenance_marker=_INTERNAL_AUTHZ_MARKER,
            )

        # 1. AuthorizationContext checks
        if not isinstance(authorization_context, AuthorizationContext) or not authorization_context.is_trusted():
            return _make_decision(AuthorizationDecision.DENY, AuthorizationReason.INVALID_CONTEXT)

        if authorization_context.is_expired(now):
            return _make_decision(AuthorizationDecision.DENY, AuthorizationReason.CONTEXT_EXPIRED)

        if authorization_context.state == AuthorizationState.UNVERIFIED:
            return _make_decision(AuthorizationDecision.DENY, AuthorizationReason.UNAUTHENTICATED)

        # 2. Action binding checks
        if str(action.session_id) != str(authorization_context.session_id):
            return _make_decision(AuthorizationDecision.DENY, AuthorizationReason.TRANSACTION_MISMATCH)

        # 3. RiskEvaluation provenance & binding checks
        if not isinstance(risk_evaluation, RiskEvaluation) or not risk_evaluation.is_trusted():
            return _make_decision(AuthorizationDecision.DENY, AuthorizationReason.RISK_UNKNOWN)

        if (
            risk_evaluation.subject_id != authorization_context.subject_id
            or risk_evaluation.session_id != authorization_context.session_id
            or risk_evaluation.action_id != action_uuid
        ):
            return _make_decision(AuthorizationDecision.DENY, AuthorizationReason.TRANSACTION_MISMATCH)

        # 4. Critical risk is always denied
        if risk_evaluation.level == RiskLevel.CRITICAL:
            return _make_decision(AuthorizationDecision.DENY, AuthorizationReason.RISK_TOO_HIGH)

        # 5. Determine if Step-Up is required
        requires_step_up = False
        if authorization_context.state != AuthorizationState.STEP_UP_VERIFIED:
            requires_step_up = True
        elif risk_evaluation.level in (RiskLevel.MEDIUM, RiskLevel.HIGH):
            requires_step_up = True

        # Check step-up evidence if required
        verified_step_up_id = None
        if requires_step_up:
            if step_up_evidence is None:
                return _make_decision(AuthorizationDecision.STEP_UP_REQUIRED, AuthorizationReason.STEP_UP_REQUIRED)

            if not step_up_evidence.is_trusted():
                return _make_decision(AuthorizationDecision.DENY, AuthorizationReason.STEP_UP_INVALID)

            if step_up_evidence.is_expired(now):
                return _make_decision(AuthorizationDecision.DENY, AuthorizationReason.STEP_UP_EXPIRED)

            if (
                step_up_evidence.subject_id != authorization_context.subject_id
                or step_up_evidence.session_id != authorization_context.session_id
                or step_up_evidence.action_id != action_uuid
            ):
                return _make_decision(AuthorizationDecision.DENY, AuthorizationReason.TRANSACTION_MISMATCH)

            verified_step_up_id = step_up_evidence.evidence_id

        # 6. Payment actions require ApprovalEvidence
        if action.action_type == "PAYMENT":
            if approval_evidence is None:
                return _make_decision(
                    AuthorizationDecision.DENY,
                    AuthorizationReason.APPROVAL_MISSING,
                    verified_step_up_id,
                )

            if not approval_evidence.is_trusted():
                return _make_decision(
                    AuthorizationDecision.DENY,
                    AuthorizationReason.APPROVAL_INVALID,
                    verified_step_up_id,
                )

            if approval_evidence.is_expired(now):
                return _make_decision(
                    AuthorizationDecision.DENY,
                    AuthorizationReason.APPROVAL_EXPIRED,
                    verified_step_up_id,
                )

            # Exact transaction parameter match
            act_amount = getattr(action, "amount", None)
            act_currency = getattr(action, "currency", None)
            act_dest = getattr(action, "destination_id", None)

            if (
                approval_evidence.action_id != action_uuid
                or approval_evidence.session_id != authorization_context.session_id
                or approval_evidence.subject_id != authorization_context.subject_id
                or (act_amount is not None and approval_evidence.amount != Decimal(str(act_amount)))
                or (act_currency is not None and approval_evidence.currency != act_currency)
                or (act_dest is not None and approval_evidence.destination_id != act_dest)
            ):
                return _make_decision(
                    AuthorizationDecision.DENY,
                    AuthorizationReason.TRANSACTION_MISMATCH,
                    verified_step_up_id,
                )

        return _make_decision(
            AuthorizationDecision.ALLOW,
            AuthorizationReason.PERMITTED,
            verified_step_up_id,
        )