"""
Ovela Security Authorization Boundary.

Security principle:
    External content is evidence, never authority.

This module performs deterministic authorization checks for
ActionRequest objects.

Security guarantees:
- Unknown actions are denied.
- Missing or malformed authorization state is denied.
- Read-only actions remain available according to policy.
- Protected actions require authenticated authorization.
- High-impact actions require step-up verification.
- Payment actions require destination verification,
  positive finite amount, valid currency, and transaction-bound
  confirmation.
- External content cannot grant privilege.
- The caller cannot bypass authorization by supplying an
  unexpected authorization state.
- Payment authorization rejects incomplete transaction intent
  before execution is permitted.
"""

from __future__ import annotations

import math

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


READ_ONLY = frozenset(
    {
        "READ_GENERAL",
        "READ_FINANCIAL",
        "READ_HIGH_SENSITIVITY",
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


UNVERIFIED = "UNVERIFIED"
AUTHENTICATED = "AUTHENTICATED"
STEP_UP_VERIFIED = "STEP_UP_VERIFIED"


PROTECTED_AUTHORIZATION_STATES = frozenset(
    {
        AUTHENTICATED,
        STEP_UP_VERIFIED,
    }
)


def _safe_action_value(action: ActionRequest, attribute: str):
    """
    Read an ActionRequest attribute without converting missing attributes
    into an authorization bypass.

    Missing attributes are treated as None.
    """
    return getattr(action, attribute, None)


def _is_valid_positive_amount(amount: object) -> bool:
    """
    Return True only for a finite, strictly positive numeric amount.

    This deliberately rejects:
    - None
    - booleans
    - zero
    - negative values
    - NaN
    - positive infinity
    - negative infinity
    - non-numeric values
    """

    if amount is None:
        return False

    if isinstance(amount, bool):
        return False

    try:
        numeric_amount = float(amount)
    except (TypeError, ValueError, OverflowError):
        return False

    if not math.isfinite(numeric_amount):
        return False

    return numeric_amount > 0


def _is_valid_currency(currency: object) -> bool:
    """
    Return True only for a valid three-letter currency code.

    This is intentionally enforced at the authorization boundary as
    defense-in-depth, even though ActionRequest validation also
    constrains the field.
    """

    if not isinstance(currency, str):
        return False

    normalized = currency.strip()

    return (
        len(normalized) == 3
        and normalized.isalpha()
    )


def _is_protected_action(action_type: object) -> bool:
    return action_type not in READ_ONLY


def _requires_step_up(action_type: object) -> bool:
    return action_type in HIGH_IMPACT


def authorize_action(action: ActionRequest) -> SecurityDecision:
    """
    Deterministically authorize an ActionRequest.

    Security rules:

    1. Invalid or unknown action types are denied.
    2. Read-only actions are allowed according to the existing policy.
    3. Protected actions require an explicitly recognized authenticated
       authorization state.
    4. High-impact actions require STEP_UP_VERIFIED.
    5. Payment actions require:
       - a destination
       - a verified destination
       - a finite positive amount
       - a valid three-letter currency code
       - explicit user confirmation
       - confirmation bound to the current action ID
    6. Unexpected authorization states are denied.
    7. This function never grants privilege merely because content claims
       authority.
    8. Incomplete payment intent is rejected before authorization succeeds.
    """

    if action is None:
        return SecurityDecision(
            False,
            "action request is missing",
        )

    action_type = _safe_action_value(action, "action_type")

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

    if action_type in READ_ONLY:
        return SecurityDecision(
            True,
            "read-only policy checks passed",
        )

    authorization_state = _safe_action_value(
        action,
        "authorization_state",
    )

    if authorization_state == UNVERIFIED:
        return SecurityDecision(
            False,
            "authenticated identity is required",
        )

    if authorization_state not in PROTECTED_AUTHORIZATION_STATES:
        return SecurityDecision(
            False,
            "authorization state is invalid or unrecognized",
        )

    if _requires_step_up(action_type):
        if authorization_state != STEP_UP_VERIFIED:
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

        if not isinstance(destination_id, str) or not destination_id.strip():
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
                "payment amount must be a finite positive number",
            )

        currency = _safe_action_value(
            action,
            "currency",
        )

        if not _is_valid_currency(currency):
            return SecurityDecision(
                False,
                "payment currency is required and must be a three-letter code",
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