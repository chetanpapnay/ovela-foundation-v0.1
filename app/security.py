"""
Ovela Security Authorization Boundary.

Security principle:
    External content is evidence, never authority.

This module performs deterministic authorization checks for
ActionRequest objects using:

    Untrusted ActionRequest
        +
    Trusted AuthorizationContext
        +
    Trusted ApprovalEvidence for sensitive financial actions

Security guarantees:
- Unknown actions are denied.
- Missing, invalid, expired, or untrusted authorization context is denied.
- The ActionRequest cannot assert its own authorization authority.
- Action sessions must match the trusted authorization context.
- General reads remain available according to policy.
- Financial reads require authenticated authorization.
- High-sensitivity reads require authenticated authorization.
- High-impact actions require step-up verification.
- Payment actions require trusted, transaction-bound ApprovalEvidence.
- Caller-controlled confirmation fields are not authority.
- Payment approval is bound to action, session, subject, destination,
  amount, and currency.
- Payment approval must be unexpired at authorization time.
- External content cannot grant privilege.
- Caller-supplied authorization_state is never trusted.
- Authorization is re-evaluated at the security boundary.
- Incomplete payment intent is rejected before execution is permitted.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any
from uuid import UUID

from .approval_evidence import (
    ApprovalEvidence,
    ApprovalEvidenceExpired,
    ApprovalEvidenceInvalid,
)
from .authorization_context import (
    AuthorizationContext,
    AuthorizationContextExpired,
    AuthorizationContextInvalid,
    AuthorizationState,
)
from .models import ActionRequest


# Provided hook for temporal testing / clock resolution
def from_server_clock():
    from .temporal_context import from_server_clock as _clock
    return _clock()


class SecurityDecision:
    """
    Result of an authorization decision.

    The object intentionally remains simple for compatibility with
    the existing Ovela codebase.
    """

    def __init__(
        self,
        allowed: bool,
        reason: str,
        requires_step_up: bool = False,
    ):
        self.allowed = allowed
        self.reason = reason
        self.requires_step_up = requires_step_up

    def __repr__(self) -> str:
        return (
            "SecurityDecision("
            f"allowed={self.allowed!r}, "
            f"reason={self.reason!r}, "
            f"requires_step_up={self.requires_step_up!r}"
            ")"
        )


READ_GENERAL = "READ_GENERAL"
READ_FINANCIAL = "READ_FINANCIAL"
READ_HIGH_SENSITIVITY = "READ_HIGH_SENSITIVITY"


READ_ONLY = frozenset(
    {
        READ_GENERAL,
        READ_FINANCIAL,
        READ_HIGH_SENSITIVITY,
    }
)


AUTHENTICATED_READS = frozenset(
    {
        READ_FINANCIAL,
        READ_HIGH_SENSITIVITY,
    }
)


HIGH_IMPACT = frozenset(
    {
        "PAYMENT_INITIATE",
        "SECURITY_CHANGE",
        "RECOVERY_CHANGE",
        "ACCOUNT_ADD",
        "ACCOUNT_REMOVE",
        "DATA_EXPORT",
        "DEVICE_REVOKE",
    }
)


KNOWN_ACTIONS = frozenset(
    READ_ONLY
    | HIGH_IMPACT
    | {
        "MODIFY_DATA",
    }
)


UNVERIFIED = AuthorizationState.UNVERIFIED.value
AUTHENTICATED = AuthorizationState.AUTHENTICATED.value
STEP_UP_VERIFIED = AuthorizationState.STEP_UP_VERIFIED.value


PROTECTED_AUTHORIZATION_STATES = frozenset(
    {
        AuthorizationState.AUTHENTICATED,
        AuthorizationState.STEP_UP_VERIFIED,
    }
)


def _safe_action_value(
    action: ActionRequest,
    attribute: str,
) -> Any:
    return getattr(action, attribute, None)


def _trusted_now() -> datetime:
    """
    Return the current server-side UTC time.
    Uses from_server_clock() if available, otherwise falls back to system UTC.
    """
    if callable(from_server_clock):
        try:
            res = from_server_clock()
            if hasattr(res, "timestamp_utc"):
                return res.timestamp_utc
            if isinstance(res, datetime):
                return res
        except Exception:
            pass
    return datetime.now(timezone.utc)


def _validate_authorization_context(
    action: ActionRequest,
    authorization_context: AuthorizationContext,
) -> SecurityDecision | None:
    if not isinstance(authorization_context, AuthorizationContext):
        return SecurityDecision(
            False,
            "trusted authorization context is missing or invalid",
        )

    try:
        authorization_context.require_trusted()
        authorization_context.require_valid_at(_trusted_now())
    except (
        AuthorizationContextExpired,
        AuthorizationContextInvalid,
        ValueError,
        TypeError,
    ):
        return SecurityDecision(
            False,
            "trusted authorization context is expired, invalid, or lacks trusted provenance",
        )

    action_session_id = _safe_action_value(action, "session_id")

    if not isinstance(action_session_id, str) or not action_session_id.strip():
        return SecurityDecision(
            False,
            "action session is missing or invalid",
        )

    if action_session_id.strip() != str(authorization_context.session_id):
        return SecurityDecision(
            False,
            "action session does not match trusted authorization context",
        )

    return None


def _context_state(
    authorization_context: AuthorizationContext,
) -> AuthorizationState:
    try:
        return AuthorizationState(authorization_context.state)
    except (TypeError, ValueError) as exc:
        raise AuthorizationContextInvalid(
            "trusted authorization context contains an invalid state"
        ) from exc


def _is_valid_positive_amount(amount: object) -> bool:
    if amount is None or isinstance(amount, bool):
        return False
    if not isinstance(amount, Decimal):
        return False
    if not amount.is_finite():
        return False
    return amount > Decimal("0")


def _is_valid_currency(currency: object) -> bool:
    if not isinstance(currency, str):
        return False
    normalized = currency.strip()
    return (
        len(normalized) == 3
        and normalized.isalpha()
        and normalized.upper() == normalized
    )


def _is_protected_action(action_type: object) -> bool:
    return action_type not in READ_ONLY


def _requires_authenticated_read(action_type: object) -> bool:
    return action_type in AUTHENTICATED_READS


def _requires_step_up(action_type: object) -> bool:
    return action_type in HIGH_IMPACT


def _validate_payment_approval(
    action: ActionRequest,
    authorization_context: AuthorizationContext,
    approval_evidence: ApprovalEvidence | None,
) -> SecurityDecision | None:
    if type(approval_evidence) is not ApprovalEvidence:
        return SecurityDecision(
            False,
            "trusted approval evidence is missing or invalid",
        )

    try:
        approval_evidence.require_trusted()
        approval_evidence.require_valid_at(_trusted_now())
    except (
        ApprovalEvidenceExpired,
        ApprovalEvidenceInvalid,
        ValueError,
        TypeError,
    ):
        return SecurityDecision(
            False,
            "trusted approval evidence is expired, invalid, or lacks trusted provenance",
        )

    action_id = _safe_action_value(action, "action_id")
    if not isinstance(action_id, UUID):
        return SecurityDecision(
            False,
            "payment action ID is missing or invalid",
        )

    action_session_id = _safe_action_value(action, "session_id")
    if not isinstance(action_session_id, str) or not action_session_id.strip():
        return SecurityDecision(
            False,
            "payment session ID is missing or invalid",
        )

    try:
        session_id = UUID(action_session_id)
    except (ValueError, TypeError, AttributeError):
        return SecurityDecision(
            False,
            "payment session ID is not a valid UUID",
        )

    destination_id = _safe_action_value(action, "destination_id")
    if not isinstance(destination_id, str) or not destination_id.strip():
        return SecurityDecision(
            False,
            "payment destination is missing",
        )

    amount = _safe_action_value(action, "amount")
    if not _is_valid_positive_amount(amount):
        return SecurityDecision(
            False,
            "payment amount must be a finite positive Decimal",
        )

    currency = _safe_action_value(action, "currency")
    if not _is_valid_currency(currency):
        return SecurityDecision(
            False,
            "payment currency is required and must be an uppercase three-letter code",
        )

    if not approval_evidence.matches_transaction(
        action_id=action_id,
        session_id=authorization_context.session_id,
        subject_id=authorization_context.subject_id,
        destination_id=destination_id,
        amount=amount,
        currency=currency,
    ):
        return SecurityDecision(
            False,
            "trusted approval evidence does not match the requested transaction",
        )

    if session_id != authorization_context.session_id:
        return SecurityDecision(
            False,
            "payment session does not match trusted authorization context",
        )

    return None


def authorize_action(
    action: ActionRequest,
    authorization_context: AuthorizationContext,
    approval_evidence: ApprovalEvidence | None = None,
    *,
    risk_evaluation: Any = None,
    step_up_evidence: Any = None,
    **kwargs: Any,
) -> SecurityDecision:
    if action is None:
        return SecurityDecision(False, "action request is missing")

    if type(action) is not ActionRequest:
        return SecurityDecision(False, "action request type is invalid")

    action_type = _safe_action_value(action, "action_type")
    if not isinstance(action_type, str) or not action_type.strip():
        return SecurityDecision(False, "action type is missing or invalid")

    action_type = action_type.strip()
    if action_type not in KNOWN_ACTIONS:
        return SecurityDecision(False, "unknown action type is blocked")

    context_error = _validate_authorization_context(action, authorization_context)
    if context_error is not None:
        return context_error

    try:
        trusted_state = _context_state(authorization_context)
    except AuthorizationContextInvalid:
        return SecurityDecision(
            False,
            "trusted authorization context contains an invalid state",
        )

    if trusted_state not in (
        AuthorizationState.UNVERIFIED,
        AuthorizationState.AUTHENTICATED,
        AuthorizationState.STEP_UP_VERIFIED,
    ):
        return SecurityDecision(
            False,
            "trusted authorization state is invalid or unrecognized",
        )

    if action_type == READ_GENERAL:
        return SecurityDecision(True, "general read policy checks passed")

    if _requires_authenticated_read(action_type):
        if trusted_state not in PROTECTED_AUTHORIZATION_STATES:
            return SecurityDecision(False, "authenticated identity is required")

    if _is_protected_action(action_type):
        if trusted_state not in PROTECTED_AUTHORIZATION_STATES:
            return SecurityDecision(False, "authenticated identity is required")

    if _requires_step_up(action_type):
        if trusted_state != AuthorizationState.STEP_UP_VERIFIED:
            return SecurityDecision(
                False,
                "high-impact action requires step-up authorization",
                True,
            )

    if action_type == "PAYMENT_INITIATE":
        destination_id = _safe_action_value(action, "destination_id")
        if not isinstance(destination_id, str) or not destination_id.strip():
            return SecurityDecision(False, "payment destination is missing")

        amount = _safe_action_value(action, "amount")
        if not _is_valid_positive_amount(amount):
            return SecurityDecision(
                False,
                "payment amount must be a finite positive Decimal",
            )

        currency = _safe_action_value(action, "currency")
        if not _is_valid_currency(currency):
            return SecurityDecision(
                False,
                "payment currency is required and must be an uppercase three-letter code",
            )

        approval_error = _validate_payment_approval(
            action,
            authorization_context,
            approval_evidence,
        )
        if approval_error is not None:
            return approval_error

    return SecurityDecision(True, "policy checks passed")