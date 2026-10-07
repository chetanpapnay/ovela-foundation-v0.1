from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Callable, Mapping
from uuid import UUID, uuid4

from app.session_gateway import SessionContext
from app.tenant_context import TenantContext


class ActionType(StrEnum):
    PAYMENT_INITIATE = "PAYMENT_INITIATE"
    TRANSFER_INITIATE = "TRANSFER_INITIATE"
    BILL_PAYMENT = "BILL_PAYMENT"
    DATA_EXPORT = "DATA_EXPORT"
    SECURITY_CHANGE = "SECURITY_CHANGE"


class PolicyEffect(StrEnum):
    ALLOW = "ALLOW"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class Decision(StrEnum):
    PERMIT = "PERMIT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class JurixSecurityError(Exception):
    """Base exception for JURIX boundary and kernel security failures."""


class JurixInputInvalid(JurixSecurityError):
    """Raised when trusted kernel input is structurally invalid."""


class JurixDigestMismatch(JurixSecurityError):
    """Raised when a proposal or command digest does not match its contents."""


class JurixProvenanceError(JurixSecurityError):
    """Raised when an untrusted proposal cannot be bound to trusted input."""


class JurixPolicyInvalid(JurixSecurityError):
    """Raised when the supplied policy snapshot is invalid or expired."""


@dataclass(frozen=True)
class CandidateParameters:
    amount: Decimal | None
    currency: str | None
    destination_id: str | None
    metadata: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.amount is not None:
            try:
                amount = Decimal(self.amount)
            except (InvalidOperation, TypeError, ValueError) as exc:
                raise JurixInputInvalid("amount must be a valid Decimal.") from exc

            if not amount.is_finite():
                raise JurixInputInvalid("amount must be finite.")

            if amount < Decimal("0"):
                raise JurixInputInvalid("amount cannot be negative.")

            object.__setattr__(self, "amount", amount)

        if self.currency is not None:
            currency = str(self.currency).strip().upper()
            if not currency:
                raise JurixInputInvalid("currency cannot be empty.")
            object.__setattr__(self, "currency", currency)

        if self.destination_id is not None:
            destination_id = str(self.destination_id).strip()
            if not destination_id:
                raise JurixInputInvalid("destination_id cannot be empty.")
            object.__setattr__(self, "destination_id", destination_id)

        normalized_metadata: dict[str, str] = {}
        for key, value in dict(self.metadata).items():
            key_text = str(key)
            value_text = str(value)

            if not key_text:
                raise JurixInputInvalid("metadata keys cannot be empty.")

            normalized_metadata[key_text] = value_text

        object.__setattr__(
            self,
            "metadata",
            MappingProxyType(normalized_metadata),
        )


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    action_type: ActionType
    effect: PolicyEffect
    max_amount: Decimal | None = None
    currency: str | None = None

    def __post_init__(self) -> None:
        rule_id = str(self.rule_id).strip()
        if not rule_id:
            raise JurixPolicyInvalid("rule_id cannot be empty.")
        object.__setattr__(self, "rule_id", rule_id)

        if self.max_amount is not None:
            try:
                max_amount = Decimal(self.max_amount)
            except (InvalidOperation, TypeError, ValueError) as exc:
                raise JurixPolicyInvalid(
                    f"Invalid max_amount for policy rule {rule_id}."
                ) from exc

            if not max_amount.is_finite() or max_amount < Decimal("0"):
                raise JurixPolicyInvalid(
                    f"max_amount for policy rule {rule_id} must be finite and non-negative."
                )

            object.__setattr__(self, "max_amount", max_amount)

        if self.currency is not None:
            currency = str(self.currency).strip().upper()
            if not currency:
                raise JurixPolicyInvalid(
                    f"currency for policy rule {rule_id} cannot be empty."
                )
            object.__setattr__(self, "currency", currency)


@dataclass(frozen=True)
class TenantPolicySnapshot:
    policy_snapshot_id: UUID
    tenant_id: UUID
    rules: tuple[PolicyRule, ...]
    spending_limit_without_approval: Decimal
    effective_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.policy_snapshot_id, UUID):
            raise JurixPolicyInvalid("policy_snapshot_id must be a UUID.")

        if not isinstance(self.tenant_id, UUID):
            raise JurixPolicyInvalid("tenant_id must be a UUID.")

        try:
            spending_limit = Decimal(self.spending_limit_without_approval)
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise JurixPolicyInvalid(
                "spending_limit_without_approval must be a valid Decimal."
            ) from exc

        if not spending_limit.is_finite() or spending_limit < Decimal("0"):
            raise JurixPolicyInvalid(
                "spending_limit_without_approval must be finite and non-negative."
            )

        object.__setattr__(
            self,
            "spending_limit_without_approval",
            spending_limit,
        )

        if self.effective_at.tzinfo is None or self.effective_at.utcoffset() is None:
            raise JurixPolicyInvalid("effective_at must be timezone-aware.")

        if self.expires_at.tzinfo is None or self.expires_at.utcoffset() is None:
            raise JurixPolicyInvalid("expires_at must be timezone-aware.")

        if self.expires_at <= self.effective_at:
            raise JurixPolicyInvalid(
                "expires_at must be later than effective_at."
            )

        normalized_rules = tuple(self.rules)
        for rule in normalized_rules:
            if not isinstance(rule, PolicyRule):
                raise JurixPolicyInvalid(
                    "TenantPolicySnapshot.rules must contain PolicyRule objects."
                )

        object.__setattr__(self, "rules", normalized_rules)

    def is_valid_at(self, now: datetime) -> bool:
        if now.tzinfo is None or now.utcoffset() is None:
            raise JurixPolicyInvalid("now must be timezone-aware.")

        return self.effective_at <= now < self.expires_at

    def require_valid_at(self, now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise JurixPolicyInvalid("now must be timezone-aware.")

        if now < self.effective_at:
            raise JurixPolicyInvalid(
                "Policy snapshot is not yet effective."
            )

        if now >= self.expires_at:
            raise JurixPolicyInvalid(
                "Policy snapshot has expired."
            )


@dataclass(frozen=True)
class PolicyReasoningInput:
    request_id: UUID
    tenant_id: UUID
    subject_id: UUID
    session_id: UUID
    action_type: ActionType
    parameters: CandidateParameters
    policy_snapshot_id: UUID
    input_digest: str

    @staticmethod
    def canonical_input(
        request_id: UUID,
        tenant_id: UUID,
        subject_id: UUID,
        session_id: UUID,
        action_type: ActionType,
        parameters: CandidateParameters,
        policy_snapshot_id: UUID,
    ) -> str:
        return (
            f"{request_id}:"
            f"{tenant_id}:"
            f"{subject_id}:"
            f"{session_id}:"
            f"{action_type}:"
            f"{parameters.amount}:"
            f"{parameters.currency}:"
            f"{parameters.destination_id}:"
            f"{policy_snapshot_id}"
        )

    @classmethod
    def compute_input_digest(
        cls,
        request_id: UUID,
        tenant_id: UUID,
        subject_id: UUID,
        session_id: UUID,
        action_type: ActionType,
        parameters: CandidateParameters,
        policy_snapshot_id: UUID,
    ) -> str:
        canonical = cls.canonical_input(
            request_id=request_id,
            tenant_id=tenant_id,
            subject_id=subject_id,
            session_id=session_id,
            action_type=action_type,
            parameters=parameters,
            policy_snapshot_id=policy_snapshot_id,
        )
        return sha256(canonical.encode("utf-8")).hexdigest()

    def expected_input_digest(self) -> str:
        return self.compute_input_digest(
            request_id=self.request_id,
            tenant_id=self.tenant_id,
            subject_id=self.subject_id,
            session_id=self.session_id,
            action_type=self.action_type,
            parameters=self.parameters,
            policy_snapshot_id=self.policy_snapshot_id,
        )

    def is_digest_valid(self) -> bool:
        return self.input_digest == self.expected_input_digest()


@dataclass(frozen=True)
class ActionProposal:
    proposal_id: UUID
    request_id: UUID
    decision: Decision
    matched_rule_ids: tuple[str, ...]
    reason: str
    claimed_capability: str | None
    input_digest: str
    proposal_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.proposal_id, UUID):
            raise JurixInputInvalid("proposal_id must be a UUID.")

        if not isinstance(self.request_id, UUID):
            raise JurixInputInvalid("request_id must be a UUID.")

        normalized_rules = tuple(str(rule_id) for rule_id in self.matched_rule_ids)
        object.__setattr__(self, "matched_rule_ids", normalized_rules)

        reason = str(self.reason)
        object.__setattr__(self, "reason", reason)

        if self.claimed_capability is not None:
            object.__setattr__(
                self,
                "claimed_capability",
                str(self.claimed_capability),
            )

    @staticmethod
    def canonical_proposal(
        proposal_id: UUID,
        request_id: UUID,
        decision: Decision,
        matched_rule_ids: tuple[str, ...],
        reason: str,
        claimed_capability: str | None,
        input_digest: str,
    ) -> str:
        return (
            f"{proposal_id}:"
            f"{request_id}:"
            f"{decision}:"
            f"{'|'.join(matched_rule_ids)}:"
            f"{reason}:"
            f"{claimed_capability}:"
            f"{input_digest}"
        )

    @classmethod
    def compute_proposal_digest(
        cls,
        proposal_id: UUID,
        request_id: UUID,
        decision: Decision,
        matched_rule_ids: tuple[str, ...],
        reason: str,
        claimed_capability: str | None,
        input_digest: str,
    ) -> str:
        canonical = cls.canonical_proposal(
            proposal_id=proposal_id,
            request_id=request_id,
            decision=decision,
            matched_rule_ids=matched_rule_ids,
            reason=reason,
            claimed_capability=claimed_capability,
            input_digest=input_digest,
        )
        return sha256(canonical.encode("utf-8")).hexdigest()

    def expected_proposal_digest(self) -> str:
        return self.compute_proposal_digest(
            proposal_id=self.proposal_id,
            request_id=self.request_id,
            decision=self.decision,
            matched_rule_ids=self.matched_rule_ids,
            reason=self.reason,
            claimed_capability=self.claimed_capability,
            input_digest=self.input_digest,
        )

    def is_digest_valid(self) -> bool:
        return self.proposal_digest == self.expected_proposal_digest()


@dataclass(frozen=True)
class KernelDecision:
    kernel_decision_id: UUID
    request_id: UUID
    decision: Decision
    matched_rule_ids: tuple[str, ...]
    approval_required: bool
    reason: str
    policy_snapshot_id: UUID
    evaluated_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.kernel_decision_id, UUID):
            raise JurixInputInvalid("kernel_decision_id must be a UUID.")

        if not isinstance(self.request_id, UUID):
            raise JurixInputInvalid("request_id must be a UUID.")

        if not isinstance(self.policy_snapshot_id, UUID):
            raise JurixInputInvalid(
                "policy_snapshot_id must be a UUID."
            )

        if self.evaluated_at.tzinfo is None or self.evaluated_at.utcoffset() is None:
            raise JurixInputInvalid("evaluated_at must be timezone-aware.")

        object.__setattr__(
            self,
            "matched_rule_ids",
            tuple(str(rule_id) for rule_id in self.matched_rule_ids),
        )


@dataclass(frozen=True)
class KernelExecutionCommand:
    command_id: UUID
    request_id: UUID
    tenant_id: UUID
    subject_id: UUID
    session_id: UUID
    action_type: ActionType
    amount: Decimal
    currency: str
    destination_id: str
    kernel_decision_id: UUID
    approval_evidence_id: UUID | None
    command_digest: str

    def __post_init__(self) -> None:
        for field_name in (
            "command_id",
            "request_id",
            "tenant_id",
            "subject_id",
            "session_id",
            "kernel_decision_id",
        ):
            if not isinstance(getattr(self, field_name), UUID):
                raise JurixInputInvalid(
                    f"{field_name} must be a UUID."
                )

        try:
            amount = Decimal(self.amount)
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise JurixInputInvalid(
                "command amount must be a valid Decimal."
            ) from exc

        if not amount.is_finite() or amount < Decimal("0"):
            raise JurixInputInvalid(
                "command amount must be finite and non-negative."
            )

        object.__setattr__(self, "amount", amount)

        currency = str(self.currency).strip().upper()
        if not currency:
            raise JurixInputInvalid("command currency cannot be empty.")
        object.__setattr__(self, "currency", currency)

        destination_id = str(self.destination_id).strip()
        if not destination_id:
            raise JurixInputInvalid(
                "command destination_id cannot be empty."
            )
        object.__setattr__(self, "destination_id", destination_id)

    @staticmethod
    def canonical_command(
        command_id: UUID,
        request_id: UUID,
        tenant_id: UUID,
        subject_id: UUID,
        session_id: UUID,
        action_type: ActionType,
        amount: Decimal,
        currency: str,
        destination_id: str,
        kernel_decision_id: UUID,
        approval_evidence_id: UUID | None,
    ) -> str:
        return (
            f"{command_id}:"
            f"{request_id}:"
            f"{tenant_id}:"
            f"{subject_id}:"
            f"{session_id}:"
            f"{action_type}:"
            f"{amount}:"
            f"{currency}:"
            f"{destination_id}:"
            f"{kernel_decision_id}:"
            f"{approval_evidence_id}"
        )

    @classmethod
    def compute_command_digest(
        cls,
        command_id: UUID,
        request_id: UUID,
        tenant_id: UUID,
        subject_id: UUID,
        session_id: UUID,
        action_type: ActionType,
        amount: Decimal,
        currency: str,
        destination_id: str,
        kernel_decision_id: UUID,
        approval_evidence_id: UUID | None,
    ) -> str:
        canonical = cls.canonical_command(
            command_id=command_id,
            request_id=request_id,
            tenant_id=tenant_id,
            subject_id=subject_id,
            session_id=session_id,
            action_type=action_type,
            amount=amount,
            currency=currency,
            destination_id=destination_id,
            kernel_decision_id=kernel_decision_id,
            approval_evidence_id=approval_evidence_id,
        )
        return sha256(canonical.encode("utf-8")).hexdigest()

    def expected_command_digest(self) -> str:
        return self.compute_command_digest(
            command_id=self.command_id,
            request_id=self.request_id,
            tenant_id=self.tenant_id,
            subject_id=self.subject_id,
            session_id=self.session_id,
            action_type=self.action_type,
            amount=self.amount,
            currency=self.currency,
            destination_id=self.destination_id,
            kernel_decision_id=self.kernel_decision_id,
            approval_evidence_id=self.approval_evidence_id,
        )

    def is_digest_valid(self) -> bool:
        return self.command_digest == self.expected_command_digest()


class JurixPolicySandbox:
    """
    Untrusted policy-reasoning boundary.

    This object deliberately has no credentials, execution capability, approval
    authority, context-issuer capability, transaction client, or ledger access.
    Every result it emits is treated as an untrusted claim by the kernel.
    """

    def __init__(
        self,
        *,
        prompt_injection_payload: str | None = None,
        forced_decision: Decision | None = None,
        claimed_capability: str | None = None,
        forge_input_digest: bool = False,
        forge_proposal_digest: bool = False,
        tamper_parameters: bool = False,
        tampered_input_digest: str | None = None,
        tampered_proposal_digest: str | None = None,
    ) -> None:
        self.prompt_injection_payload = prompt_injection_payload
        self.forced_decision = forced_decision
        self.claimed_capability = claimed_capability
        self.forge_input_digest = forge_input_digest
        self.forge_proposal_digest = forge_proposal_digest
        self.tamper_parameters = tamper_parameters
        self.tampered_input_digest = tampered_input_digest
        self.tampered_proposal_digest = tampered_proposal_digest

    @staticmethod
    def _evaluate_read_only(
        reasoning_input: PolicyReasoningInput,
        policy: TenantPolicySnapshot,
    ) -> tuple[Decision, tuple[str, ...], str]:
        amount = reasoning_input.parameters.amount
        currency = reasoning_input.parameters.currency

        matching_rules: list[PolicyRule] = []

        for rule in policy.rules:
            if rule.action_type is not reasoning_input.action_type:
                continue

            if rule.currency is not None and currency != rule.currency:
                continue

            if (
                rule.max_amount is not None
                and amount is not None
                and amount > rule.max_amount
            ):
                continue

            matching_rules.append(rule)

        matched_rule_ids = tuple(rule.rule_id for rule in matching_rules)

        deny_rules = tuple(
            rule for rule in matching_rules if rule.effect is PolicyEffect.DENY
        )
        if deny_rules:
            return (
                Decision.DENY,
                matched_rule_ids,
                "Policy contains a matching DENY rule.",
            )

        approval_rules = tuple(
            rule
            for rule in matching_rules
            if rule.effect is PolicyEffect.REQUIRE_APPROVAL
        )
        if approval_rules:
            return (
                Decision.REQUIRE_APPROVAL,
                matched_rule_ids,
                "Policy contains a matching approval-required rule.",
            )

        allow_rules = tuple(
            rule for rule in matching_rules if rule.effect is PolicyEffect.ALLOW
        )
        if allow_rules:
            if amount is not None and (
                amount > policy.spending_limit_without_approval
            ):
                return (
                    Decision.REQUIRE_APPROVAL,
                    matched_rule_ids,
                    "Amount exceeds the policy spending limit without approval.",
                )

            return (
                Decision.PERMIT,
                matched_rule_ids,
                "A matching ALLOW rule permits the requested action.",
            )

        return (
            Decision.DENY,
            matched_rule_ids,
            "No matching policy rule permits the requested action.",
        )

    def generate_proposal(
        self,
        reasoning_input: PolicyReasoningInput,
        policy: TenantPolicySnapshot,
    ) -> ActionProposal:
        if not isinstance(reasoning_input, PolicyReasoningInput):
            raise JurixInputInvalid(
                "reasoning_input must be PolicyReasoningInput."
            )

        if not isinstance(policy, TenantPolicySnapshot):
            raise JurixPolicyInvalid(
                "policy must be TenantPolicySnapshot."
            )

        decision, matched_rule_ids, reason = self._evaluate_read_only(
            reasoning_input,
            policy,
        )

        if self.prompt_injection_payload:
            reason = (
                f"{reason} "
                f"Sandbox prompt-injection simulation: "
                f"{self.prompt_injection_payload}"
            )

        if self.forced_decision is not None:
            decision = self.forced_decision

        input_digest = reasoning_input.input_digest

        if self.tamper_parameters:
            input_digest = (
                self.tampered_input_digest
                or sha256(
                    (
                        reasoning_input.input_digest
                        + ":tampered-parameters"
                    ).encode("utf-8")
                ).hexdigest()
            )

        if self.forge_input_digest:
            input_digest = (
                self.tampered_input_digest
                or sha256(
                    (reasoning_input.input_digest + ":forged").encode("utf-8")
                ).hexdigest()
            )

        proposal_id = uuid4()

        proposal_digest = ActionProposal.compute_proposal_digest(
            proposal_id=proposal_id,
            request_id=reasoning_input.request_id,
            decision=decision,
            matched_rule_ids=matched_rule_ids,
            reason=reason,
            claimed_capability=self.claimed_capability,
            input_digest=input_digest,
        )

        if self.forge_proposal_digest:
            proposal_digest = (
                self.tampered_proposal_digest
                or sha256(
                    (proposal_digest + ":forged").encode("utf-8")
                ).hexdigest()
            )

        return ActionProposal(
            proposal_id=proposal_id,
            request_id=reasoning_input.request_id,
            decision=decision,
            matched_rule_ids=matched_rule_ids,
            reason=reason,
            claimed_capability=self.claimed_capability,
            input_digest=input_digest,
            proposal_digest=proposal_digest,
        )

    def propose(
        self,
        reasoning_input: PolicyReasoningInput,
        policy: TenantPolicySnapshot,
    ) -> ActionProposal:
        return self.generate_proposal(reasoning_input, policy)

    def evaluate(
        self,
        reasoning_input: PolicyReasoningInput,
        policy: TenantPolicySnapshot,
    ) -> ActionProposal:
        return self.generate_proposal(reasoning_input, policy)


class DeterministicSecurityKernel:
    """
    Deterministic security authority.

    JURIX output is advisory data only. No proposal field can authorize an
    operation. The kernel independently validates trusted contexts, recomputes
    policy, evaluates spending limits, requires approval where necessary, and
    creates the sole execution command.
    """

    @staticmethod
    def _validate_now(now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise JurixInputInvalid("now must be timezone-aware.")

    @staticmethod
    def _validate_context_binding(
        session_context: SessionContext,
        tenant_context: TenantContext,
        policy: TenantPolicySnapshot,
    ) -> None:
        if session_context.tenant_id != tenant_context.tenant_id:
            raise JurixProvenanceError(
                "Session and tenant contexts belong to different tenants."
            )

        if session_context.tenant_id != policy.tenant_id:
            raise JurixProvenanceError(
                "Session context tenant does not match policy tenant."
            )

        if tenant_context.tenant_id != policy.tenant_id:
            raise JurixProvenanceError(
                "Tenant context tenant does not match policy tenant."
            )

        tenant_subject = getattr(tenant_context, "subject_id", None)
        if tenant_subject is not None and tenant_subject != session_context.subject_id:
            raise JurixProvenanceError(
                "Tenant context subject does not match session subject."
            )

        tenant_session = getattr(tenant_context, "session_id", None)
        if tenant_session is not None and tenant_session != session_context.session_id:
            raise JurixProvenanceError(
                "Tenant context session does not match session context."
            )

    @staticmethod
    def _validate_policy_input_binding(
        session_context: SessionContext,
        tenant_context: TenantContext,
        requested_action: ActionType,
        params: CandidateParameters,
        policy: TenantPolicySnapshot,
        proposal: ActionProposal,
    ) -> str:
        expected_digest = PolicyReasoningInput.compute_input_digest(
            request_id=proposal.request_id,
            tenant_id=session_context.tenant_id,
            subject_id=session_context.subject_id,
            session_id=session_context.session_id,
            action_type=requested_action,
            parameters=params,
            policy_snapshot_id=policy.policy_snapshot_id,
        )

        if proposal.input_digest != expected_digest:
            raise JurixDigestMismatch(
                "JURIX proposal input_digest does not match trusted kernel input."
            )

        if not proposal.is_digest_valid():
            raise JurixDigestMismatch(
                "JURIX proposal_digest does not match proposal contents."
            )

        return expected_digest

    @staticmethod
    def _matching_rules(
        requested_action: ActionType,
        params: CandidateParameters,
        policy: TenantPolicySnapshot,
    ) -> tuple[PolicyRule, ...]:
        matching: list[PolicyRule] = []

        for rule in policy.rules:
            if rule.action_type is not requested_action:
                continue

            if rule.currency is not None:
                if params.currency != rule.currency:
                    continue

            if rule.max_amount is not None:
                if params.amount is None:
                    continue
                if params.amount > rule.max_amount:
                    continue

            matching.append(rule)

        return tuple(matching)

    @classmethod
    def _recompute_policy(
        cls,
        requested_action: ActionType,
        params: CandidateParameters,
        policy: TenantPolicySnapshot,
    ) -> tuple[Decision, tuple[str, ...], str]:
        matching_rules = cls._matching_rules(
            requested_action=requested_action,
            params=params,
            policy=policy,
        )

        matched_rule_ids = tuple(rule.rule_id for rule in matching_rules)

        deny_rules = tuple(
            rule
            for rule in matching_rules
            if rule.effect is PolicyEffect.DENY
        )

        if deny_rules:
            return (
                Decision.DENY,
                matched_rule_ids,
                "Kernel policy evaluation found a matching DENY rule.",
            )

        approval_rules = tuple(
            rule
            for rule in matching_rules
            if rule.effect is PolicyEffect.REQUIRE_APPROVAL
        )

        if approval_rules:
            return (
                Decision.REQUIRE_APPROVAL,
                matched_rule_ids,
                "Kernel policy evaluation requires approval.",
            )

        allow_rules = tuple(
            rule
            for rule in matching_rules
            if rule.effect is PolicyEffect.ALLOW
        )

        if not allow_rules:
            return (
                Decision.DENY,
                matched_rule_ids,
                "Kernel policy evaluation found no matching ALLOW rule.",
            )

        if params.amount is None:
            return (
                Decision.REQUIRE_APPROVAL,
                matched_rule_ids,
                "An executable financial amount is required before authorization.",
            )

        if params.amount > policy.spending_limit_without_approval:
            return (
                Decision.REQUIRE_APPROVAL,
                matched_rule_ids,
                "Requested amount exceeds the spending limit without approval.",
            )

        return (
            Decision.PERMIT,
            matched_rule_ids,
            "Kernel policy evaluation permits the requested action.",
        )

    @staticmethod
    def _execution_parameters(
        params: CandidateParameters,
    ) -> tuple[Decimal, str, str]:
        if params.amount is None:
            raise JurixInputInvalid(
                "Execution command requires a concrete amount."
            )

        if params.currency is None:
            raise JurixInputInvalid(
                "Execution command requires a concrete currency."
            )

        if params.destination_id is None:
            raise JurixInputInvalid(
                "Execution command requires a concrete destination_id."
            )

        return (
            params.amount,
            params.currency,
            params.destination_id,
        )

    @classmethod
    def _build_execution_command(
        cls,
        session_context: SessionContext,
        requested_action: ActionType,
        params: CandidateParameters,
        kernel_decision: KernelDecision,
        approval_evidence_id: UUID | None,
    ) -> KernelExecutionCommand:
        amount, currency, destination_id = cls._execution_parameters(params)

        command_id = uuid4()

        command_digest = KernelExecutionCommand.compute_command_digest(
            command_id=command_id,
            request_id=kernel_decision.request_id,
            tenant_id=session_context.tenant_id,
            subject_id=session_context.subject_id,
            session_id=session_context.session_id,
            action_type=requested_action,
            amount=amount,
            currency=currency,
            destination_id=destination_id,
            kernel_decision_id=kernel_decision.kernel_decision_id,
            approval_evidence_id=approval_evidence_id,
        )

        return KernelExecutionCommand(
            command_id=command_id,
            request_id=kernel_decision.request_id,
            tenant_id=session_context.tenant_id,
            subject_id=session_context.subject_id,
            session_id=session_context.session_id,
            action_type=requested_action,
            amount=amount,
            currency=currency,
            destination_id=destination_id,
            kernel_decision_id=kernel_decision.kernel_decision_id,
            approval_evidence_id=approval_evidence_id,
            command_digest=command_digest,
        )

    @classmethod
    def evaluate_and_authorize(
        cls,
        session_context: SessionContext,
        tenant_context: TenantContext,
        requested_action: ActionType,
        params: CandidateParameters,
        policy: TenantPolicySnapshot,
        proposal: ActionProposal,
        approval_evidence_id: UUID | None = None,
        now: datetime | None = None,
    ) -> tuple[KernelDecision, KernelExecutionCommand | None]:
        evaluation_time = now or datetime.now(timezone.utc)

        cls._validate_now(evaluation_time)

        if not isinstance(session_context, SessionContext):
            raise JurixProvenanceError(
                "session_context must be a trusted SessionContext."
            )

        if not isinstance(tenant_context, TenantContext):
            raise JurixProvenanceError(
                "tenant_context must be a trusted TenantContext."
            )

        if not isinstance(requested_action, ActionType):
            raise JurixInputInvalid(
                "requested_action must be an ActionType."
            )

        if not isinstance(params, CandidateParameters):
            raise JurixInputInvalid(
                "params must be CandidateParameters."
            )

        if not isinstance(policy, TenantPolicySnapshot):
            raise JurixPolicyInvalid(
                "policy must be TenantPolicySnapshot."
            )

        if not isinstance(proposal, ActionProposal):
            raise JurixProvenanceError(
                "proposal must be an ActionProposal."
            )

        session_context.require_valid_at(evaluation_time)
        tenant_context.require_valid_at(evaluation_time)
        policy.require_valid_at(evaluation_time)

        cls._validate_context_binding(
            session_context=session_context,
            tenant_context=tenant_context,
            policy=policy,
        )

        if proposal.request_id != proposal.request_id:
            raise JurixProvenanceError(
                "Invalid proposal request identity."
            )

        expected_input_digest = cls._validate_policy_input_binding(
            session_context=session_context,
            tenant_context=tenant_context,
            requested_action=requested_action,
            params=params,
            policy=policy,
            proposal=proposal,
        )

        if not expected_input_digest:
            raise JurixDigestMismatch(
                "Trusted input digest generation returned an empty digest."
            )

        kernel_decision_value, matched_rule_ids, reason = cls._recompute_policy(
            requested_action=requested_action,
            params=params,
            policy=policy,
        )

        if kernel_decision_value is Decision.DENY:
            approval_required = False
        elif kernel_decision_value is Decision.REQUIRE_APPROVAL:
            approval_required = True
        else:
            approval_required = False

        if kernel_decision_value is Decision.REQUIRE_APPROVAL:
            if approval_evidence_id is None:
                kernel_decision = KernelDecision(
                    kernel_decision_id=uuid4(),
                    request_id=proposal.request_id,
                    decision=Decision.REQUIRE_APPROVAL,
                    matched_rule_ids=matched_rule_ids,
                    approval_required=True,
                    reason=reason,
                    policy_snapshot_id=policy.policy_snapshot_id,
                    evaluated_at=evaluation_time,
                )
                return kernel_decision, None

            if not isinstance(approval_evidence_id, UUID):
                raise JurixInputInvalid(
                    "approval_evidence_id must be a UUID when supplied."
                )

            reason = (
                f"{reason} "
                "Approval evidence is present; kernel authorization may proceed."
            )

            kernel_decision_value = Decision.PERMIT

        kernel_decision = KernelDecision(
            kernel_decision_id=uuid4(),
            request_id=proposal.request_id,
            decision=kernel_decision_value,
            matched_rule_ids=matched_rule_ids,
            approval_required=approval_required,
            reason=reason,
            policy_snapshot_id=policy.policy_snapshot_id,
            evaluated_at=evaluation_time,
        )

        if kernel_decision.decision is not Decision.PERMIT:
            return kernel_decision, None

        command = cls._build_execution_command(
            session_context=session_context,
            requested_action=requested_action,
            params=params,
            kernel_decision=kernel_decision,
            approval_evidence_id=approval_evidence_id,
        )

        if not command.is_digest_valid():
            raise JurixDigestMismatch(
                "Kernel execution command digest verification failed."
            )

        return kernel_decision, command


__all__ = [
    "ActionProposal",
    "ActionType",
    "CandidateParameters",
    "Decision",
    "DeterministicSecurityKernel",
    "JurixDigestMismatch",
    "JurixInputInvalid",
    "JurixPolicyInvalid",
    "JurixPolicySandbox",
    "JurixProvenanceError",
    "JurixSecurityError",
    "KernelDecision",
    "KernelExecutionCommand",
    "PolicyEffect",
    "PolicyReasoningInput",
    "PolicyRule",
    "TenantPolicySnapshot",
]