"""
Ovela Action Execution Boundary.

This module is the boundary between an authorized ActionRequest
and a financial ledger side effect.

Security principles:
- Authorization must succeed before execution.
- Trusted AuthorizationContext is mandatory.
- ActionRequest.authorization_state is never treated as authority.
- Action session identity must match trusted authorization context.
- Only supported high-impact actions may execute.
- Payment intent must be complete and internally consistent.
- An action ID may execute at most once per executor instance.
- A failed authorization produces no ledger event.
- A successful payment produces exactly one ledger event.
- Caller-controlled input is captured once at the security boundary.
- The canonical request is converted to the exact ActionRequest type.
- Authorization and execution use separate independent snapshots.
- Authorization-side mutation cannot alter execution intent.
- External content has no authority over execution.
- Security-relevant time comes from the trusted temporal boundary.
- The execution timestamp is captured once per successful execution.
- Callers cannot supply ledger timestamps through execute().
"""

from __future__ import annotations

from dataclasses import dataclass
from threading import RLock

from .approval_evidence import (
    ApprovalEvidence,
    ApprovalEvidenceConsumed,
    ApprovalEvidenceExpired,
    ApprovalEvidenceInvalid,
    ApprovalEvidenceRegistry,
)
from .authorization_context import AuthorizationContext
from .ledger import AppendOnlyLedger, LedgerConflict
from .models import (
    ActionRequest,
    EvidenceStatus,
    EventType,
    FinancialEvent,
)
from .security import authorize_action
from .temporal_context import from_server_clock


_DEFAULT_APPROVAL_REGISTRY = ApprovalEvidenceRegistry()


@dataclass(frozen=True)
class ExecutionResult:
    """
    Immutable result of an execution attempt.
    """

    executed: bool
    reason: str
    action_id: str


class ActionExecutor:
    """
    Execute security-sensitive actions against the ledger.

    The executor owns the single-use execution boundary.

    An action that has successfully produced a ledger event is marked
    as executed and cannot be executed again by this executor.

    Authorization authority is deliberately supplied through a trusted
    AuthorizationContext rather than through caller-controlled fields
    inside ActionRequest.

    Temporal authority is deliberately not accepted through execute().
    Financial event timestamps are resolved internally through the
    trusted temporal boundary.
    """

    def __init__(
        self,
        ledger: AppendOnlyLedger,
        approval_registry: ApprovalEvidenceRegistry | None = None,
    ):
        if not isinstance(ledger, AppendOnlyLedger):
            raise TypeError("ledger must be an AppendOnlyLedger")

        if approval_registry is None:
            approval_registry = _DEFAULT_APPROVAL_REGISTRY

        if type(approval_registry) is not ApprovalEvidenceRegistry:
            raise TypeError(
                "approval_registry must be an ApprovalEvidenceRegistry"
            )

        self._ledger = ledger
        self._approval_registry = approval_registry
        self._executed_actions: set[str] = set()
        self._lock = RLock()

    def execute(
        self,
        action: ActionRequest,
        authorization_context: AuthorizationContext,
        approval_evidence: ApprovalEvidence | None = None,
    ) -> ExecutionResult:
        """
        Authorize and execute one action.

        Security ordering:

            validate request
                ↓
            validate trusted authorization context
                ↓
            capture caller input once
                ↓
            normalize into exact ActionRequest boundary
                ↓
            create independent authorization/execution snapshots
                ↓
            single-use protection
                ↓
            authorize authorization snapshot against trusted context and approval
                ↓
            validate execution snapshot
                ↓
            resolve trusted temporal context
                ↓
            consume single-use trusted approval
                ↓
            append exactly one ledger event
                ↓
            mark action executed

        The caller-controlled ActionRequest is captured exactly once.

        The captured data is then reconstructed as the exact
        ActionRequest class. This prevents a caller-controlled subclass
        from overriding model_copy() or model_dump() and changing the
        transaction between the capture and validation boundary.

        Authorization and execution then receive separate deep copies.
        Therefore:

        - caller mutation cannot change the captured transaction
        - subclass model_copy() overrides cannot affect the boundary
        - subclass model_dump() overrides cannot affect the boundary
        - authorization mutation cannot affect execution
        - execution uses only the isolated execution snapshot

        Authorization authority comes exclusively from the supplied
        AuthorizationContext.

        The temporal boundary is also explicit:

        - production execution obtains time only through
          from_server_clock()
        - execute() accepts no caller-supplied timestamp
        - datetime.now() is never called directly by this module
        - one trusted timestamp is reused for event_date and recorded_at

        The lock covers the authorization-to-ledger boundary so two
        concurrent calls cannot execute the same action simultaneously.
        """

        if not isinstance(action, ActionRequest):
            return ExecutionResult(
                executed=False,
                reason="invalid action request",
                action_id="",
            )

        if not isinstance(
            authorization_context,
            AuthorizationContext,
        ):
            return ExecutionResult(
                executed=False,
                reason="trusted authorization context is missing or invalid",
                action_id="",
            )

        # --------------------------------------------------------------
        # 1. Capture the caller-controlled request exactly once.
        #
        # Call the base ActionRequest implementation directly so a
        # malicious or unexpected ActionRequest subclass cannot replace
        # this operation with its own model_copy() implementation.
        # --------------------------------------------------------------

        captured = ActionRequest.model_copy(
            action,
            deep=True,
        )

        # --------------------------------------------------------------
        # 2. Serialize using the trusted ActionRequest implementation.
        #
        # IMPORTANT:
        # Do NOT call captured.model_dump().
        #
        # captured may still be an ActionRequest subclass, and a malicious
        # subclass can override model_dump() to alter security-sensitive
        # values before canonical validation.
        #
        # Calling ActionRequest.model_dump(captured) invokes the trusted
        # base implementation directly and bypasses subclass overrides.
        #
        # warnings=False: unvalidated objects (model_construct()/
        # model_copy(update=...)) may hold invalid values. Pydantic would
        # emit a serializer UserWarning here. The real rejection happens
        # in model_validate() below, which raises ValidationError.
        # --------------------------------------------------------------

        captured_data = ActionRequest.model_dump(
            captured,
            warnings=False,
        )

        # --------------------------------------------------------------
        # 3. Reconstruct an exact ActionRequest.
        #
        # This is the intentional type-boundary normalization.
        #
        # Validation now occurs through the trusted ActionRequest model,
        # rejecting unvalidated model_construct()/model_copy() payloads.
        # --------------------------------------------------------------

        canonical_snapshot = ActionRequest.model_validate(
            captured_data,
        )

        # --------------------------------------------------------------
        # 4. Create two independent snapshots from the same canonical
        #    transaction intent.
        #
        # Both snapshots are now plain ActionRequest instances.
        # Authorization cannot mutate execution intent.
        # --------------------------------------------------------------

        authorization_snapshot = canonical_snapshot.model_copy(
            deep=True,
        )

        execution_snapshot = canonical_snapshot.model_copy(
            deep=True,
        )

        action_id = str(execution_snapshot.action_id)

        with self._lock:
            # ----------------------------------------------------------
            # 5. Single-use protection.
            # ----------------------------------------------------------

            if action_id in self._executed_actions:
                return ExecutionResult(
                    executed=False,
                    reason="action has already been executed",
                    action_id=action_id,
                )

            # ----------------------------------------------------------
            # 6. Authorization.
            #
            # Authorization receives:
            #   - isolated action intent
            #   - trusted authorization context
            #
            # ActionRequest.authorization_state is not authoritative.
            # ----------------------------------------------------------

            decision = authorize_action(
                authorization_snapshot,
                authorization_context,
                approval_evidence,
            )

            if not decision.allowed:
                return ExecutionResult(
                    executed=False,
                    reason=decision.reason,
                    action_id=action_id,
                )

            # ----------------------------------------------------------
            # 7. Execution currently supports payments only.
            #
            # IMPORTANT:
            # use execution_snapshot, never authorization_snapshot.
            # ----------------------------------------------------------

            if execution_snapshot.action_type != "PAYMENT_INITIATE":
                return ExecutionResult(
                    executed=False,
                    reason="action type is not executable",
                    action_id=action_id,
                )

            # ----------------------------------------------------------
            # 8. Complete payment intent.
            #
            # These checks are intentionally repeated at the execution
            # boundary. Authorization and execution are separate
            # security boundaries and must both fail closed.
            # ----------------------------------------------------------

            if (
                execution_snapshot.amount is None
                or execution_snapshot.amount <= 0
            ):
                return ExecutionResult(
                    executed=False,
                    reason="payment amount must be positive",
                    action_id=action_id,
                )

            if not execution_snapshot.amount.is_finite():
                return ExecutionResult(
                    executed=False,
                    reason="payment amount must be finite",
                    action_id=action_id,
                )

            if not execution_snapshot.currency:
                return ExecutionResult(
                    executed=False,
                    reason="payment currency is required",
                    action_id=action_id,
                )

            currency = execution_snapshot.currency.upper()

            if len(currency) != 3 or not currency.isalpha():
                return ExecutionResult(
                    executed=False,
                    reason="payment currency must be a three-letter code",
                    action_id=action_id,
                )

            if not execution_snapshot.destination_id:
                return ExecutionResult(
                    executed=False,
                    reason="payment destination is required",
                    action_id=action_id,
                )

            # Caller-controlled destination_verified, user_confirmation,
            # and confirmation_action_id are deliberately not consulted.
            # Approval authority comes only from trusted ApprovalEvidence.

            # ----------------------------------------------------------
            # 9. Resolve trusted temporal context.
            #
            # The caller cannot provide or influence the temporal
            # context through execute().
            #
            # The temporal boundary is responsible for obtaining the
            # authoritative server timestamp.
            #
            # One timestamp is captured and reused for the complete
            # financial event so event_date and recorded_at cannot drift.
            # ----------------------------------------------------------

            temporal_context = from_server_clock("UTC")

            event_timestamp = temporal_context.timestamp_utc

            try:
                self._approval_registry.consume(
                    approval_evidence,
                    now=event_timestamp,
                )
            except (
                ApprovalEvidenceConsumed,
                ApprovalEvidenceExpired,
                ApprovalEvidenceInvalid,
                TypeError,
                ValueError,
            ):
                return ExecutionResult(
                    executed=False,
                    reason="trusted approval evidence could not be consumed",
                    action_id=action_id,
                )

            # ----------------------------------------------------------
            # 10. Build the immutable financial event exclusively from
            #     the isolated execution snapshot and trusted temporal
            #     context.
            # ----------------------------------------------------------

            event = FinancialEvent(
                account_id=execution_snapshot.session_id,
                source_id="ACTION_EXECUTOR",
                source_event_id=action_id,
                event_type=EventType.EXPENSE,
                amount=execution_snapshot.amount,
                currency=currency,
                direction="DEBIT",
                event_date=event_timestamp,
                recorded_at=event_timestamp,
                evidence_status=EvidenceStatus.USER_CONFIRMED,
                note=f"Payment action {action_id}",
            )

            # ----------------------------------------------------------
            # 11. Commit exactly one ledger event.
            #
            # LedgerConflict is treated as a failed execution. The
            # action is NOT marked executed unless the ledger accepts it.
            # ----------------------------------------------------------

            try:
                self._ledger.append(event)
            except LedgerConflict:
                return ExecutionResult(
                    executed=False,
                    reason=(
                        "action could not be committed because "
                        "it was already recorded"
                    ),
                    action_id=action_id,
                )

            # ----------------------------------------------------------
            # 12. Only mark the action executed after the ledger commit.
            # ----------------------------------------------------------

            self._executed_actions.add(action_id)

            return ExecutionResult(
                executed=True,
                reason="action executed successfully",
                action_id=action_id,
            )