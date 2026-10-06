"""
Ovela Security Authorization Boundary.

Security principle:
    External content is evidence, never authority.

This module performs deterministic authorization checks for
ActionRequest objects using a trusted AuthorizationContext.

Security guarantees:
- Unknown actions are denied.
- Missing, invalid, expired, or untrusted authorization context is denied.
- The ActionRequest cannot assert its own authorization authority.
- Action sessions must match the trusted authorization context.
- General reads remain available according to policy.
- Financial reads require authenticated authorization.
- High-sensitivity reads require authenticated authorization.
- High-impact actions require step-up verification.
- Payment actions require destination verification,
  positive finite Decimal amount, valid currency, and
  transaction-bound confirmation.
- External content cannot grant privilege.
- Caller-supplied authorization_state is never trusted.
- Authorization is re-evaluated at the security boundary.
- Payment authorization rejects incomplete transaction intent
  before execution is permitted.
"""

from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from .authorization_context import (
    AuthorizationContext,
    AuthorizationContextExpired,
    AuthorizationContextInvalid,
    AuthorizationState,
)
from .models import ActionRequest


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
    """
    Read an ActionRequest attribute without converting missing attributes
    into an authorization bypass.

    Missing attributes are treated as None.
    """
    return getattr(action, attribute, None)


def _trusted_now() -> datetime:
    """
    Return the current server-side UTC time.

    This function deliberately does not accept caller-supplied time.
    Authorization expiry must be evaluated against trusted runtime time.
    """
    return datetime.now(timezone.utc)


def _validate_authorization_context(
    action: ActionRequest,
    authorization_context: AuthorizationContext,
) -> SecurityDecision | None:
    """
    Validate authorization-context provenance, validity, expiry,
    and session binding.

    The ActionRequest's authorization_state is intentionally ignored.
    Authority comes only from the trusted AuthorizationContext.
    """

    if not isinstance(
        authorization_context,
        AuthorizationContext,
    ):
        return SecurityDecision(
            False,
            "trusted authorization context is missing or invalid",
        )

    try:
        authorization_context.require_trusted()
        authorization_context.require_valid_at(
            _trusted_now(),
        )
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

    action_session_id = _safe_action_value(
        action,
        "session_id",
    )

    if not isinstance(action_session_id, str) or not action_session_id.strip():
        return SecurityDecision(
            False,
            "action session is missing or invalid",
        )

    if action_session_id.strip() != str(
        authorization_context.session_id
    ):
        return SecurityDecision(
            False,
            "action session does not match trusted authorization context",
        )

    return None


def _context_state(
    authorization_context: AuthorizationContext,
) -> AuthorizationState:
    """
    Return the trusted authorization state.

    The type conversion is defensive even though AuthorizationContext
    validates its state during construction.
    """
    try:
        return AuthorizationState(authorization_context.state)
    except (TypeError, ValueError):
        raise AuthorizationContextInvalid(
            "trusted authorization context contains an invalid state"
        )


def _is_valid_positive_amount(amount: object) -> bool:
    """
    Return True only for a finite, strictly positive Decimal amount.

    Security authorization deliberately avoids converting arbitrary
    numeric values through float because binary floating-point conversion
    is unnecessary at a financial security boundary.
    """

    if amount is None:
        return False

    if isinstance(amount, bool):
        return False

    if not isinstance(amount, Decimal):
        return False

    if not amount.is_finite():
        return False

    return amount > Decimal("0")


def _is_valid_currency(currency: object) -> bool:
    """
    Return True only for a valid uppercase three-letter currency code.
    """

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


def authorize_action(
    action: ActionRequest,
    authorization_context: AuthorizationContext,
) -> SecurityDecision:
    """
    Deterministically authorize an ActionRequest using trusted authority.

    Security rules:

    1. Invalid or unknown action types are denied.
    2. A valid, unexpired, trusted AuthorizationContext is mandatory.
    3. The action session must match the trusted context session.
    4. ActionRequest.authorization_state is never trusted.
    5. READ_GENERAL is available without authentication.
    6. READ_FINANCIAL and READ_HIGH_SENSITIVITY require authentication.
    7. Protected actions require an authenticated trusted context.
    8. High-impact actions require STEP_UP_VERIFIED.
    9. Payment actions require:
       - a destination
       - a verified destination
       - a finite positive Decimal amount
       - a valid uppercase three-letter currency code
       - explicit user confirmation
       - confirmation bound to the current action ID
    10. Unexpected authorization states are denied.
    11. External content never grants privilege.
    12. Incomplete payment intent is rejected before authorization succeeds.
    """

    if action is None:
        return SecurityDecision(
            False,
            "action request is missing",
        )

    if not isinstance(action, ActionRequest):
        return SecurityDecision(
            False,
            "action request type is invalid",
        )

    action_type = _safe_action_value(
        action,
        "action_type",
    )

    if not isinstance(action_type, str) or not action_type.strip():
        return SecurityDecision(
            False,
            "action type is missing or invalid",
        )

    action_type = action_type.strip()

    if action_type not in KNOWN_ACTIONS:
        return SecurityDecision(
            False,
            "unknown action type is blocked",
        )

    context_error = _validate_authorization_context(
        action,
        authorization_context,
    )

    if context_error is not None:
        return context_error

    try:
        trusted_state = _context_state(
            authorization_context,
        )
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
        return SecurityDecision(
            True,
            "general read policy checks passed",
        )

    if _requires_authenticated_read(action_type):
        if trusted_state not in PROTECTED_AUTHORIZATION_STATES:
            return SecurityDecision(
                False,
                "authenticated identity is required",
            )

    if _is_protected_action(action_type):
        if trusted_state not in PROTECTED_AUTHORIZATION_STATES:
            return SecurityDecision(
                False,
                "authenticated identity is required",
            )

    if _requires_step_up(action_type):
        if trusted_state != AuthorizationState.STEP_UP_VERIFIED:
            return SecurityDecision(
                False,
                "high-impact action requires step-up authorization",
                True,
            )

    if action_type == "PAYMENT_INITIATE":

        destination_id = _safe_action_value(
            action,
            "destination_id",
        )

        if (
            not isinstance(destination_id, str)
            or not destination_id.strip()
        ):
            return SecurityDecision(
                False,
                "payment destination is missing",
            )

        destination_verified = _safe_action_value(
            action,
            "destination_verified",
        )

        if destination_verified is not True:
            return SecurityDecision(
                False,
                "payment destination is not verified",
            )

        amount = _safe_action_value(
            action,
            "amount",
        )

        if not _is_valid_positive_amount(amount):
            return SecurityDecision(
                False,
                "payment amount must be a finite positive Decimal",
            )

        currency = _safe_action_value(
            action,
            "currency",
        )

        if not _is_valid_currency(currency):
            return SecurityDecision(
                False,
                "payment currency is required and must be an uppercase three-letter code",
            )

        user_confirmation = _safe_action_value(
            action,
            "user_confirmation",
        )

        if user_confirmation is not True:
            return SecurityDecision(
                False,
                "explicit transaction-bound confirmation is required",
            )

        action_id = _safe_action_value(
            action,
            "action_id",
        )

        confirmation_action_id = _safe_action_value(
            action,
            "confirmation_action_id",
        )

        if (
            not action_id
            or not confirmation_action_id
            or confirmation_action_id != action_id
        ):
            return SecurityDecision(
                False,
                "confirmation is not bound to this action",
            )

    return SecurityDecision(
        True,
        "policy checks passed",
    )