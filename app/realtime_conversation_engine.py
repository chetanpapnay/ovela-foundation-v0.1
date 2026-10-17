"""
OVELA / JURIX Realtime Conversation Engine.

This module is the conversation-runtime boundary behind the realtime
transport.

Security principles
-------------------
1. A realtime AuthorizationContext is trusted only after provenance,
   validity, and expiry checks.
2. User text and audio are untrusted input.
3. Content safety classification never grants authority.
4. Model/provider output is untrusted presentation data.
5. Model output cannot authorize, authenticate, approve, or execute
   financial/security actions.
6. Action execution remains behind ActionExecutor.
7. ApprovalEvidence is never fabricated or regenerated here.
8. Provider failures fail closed rather than becoming false success.
9. Provider output is bounded and validated before reaching transport.
10. Interrupts cancel conversational work without changing security
    authority.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from dataclasses import dataclass
from datetime import datetime, timezone  # FIX 1: needed for require_valid_at(now)
from typing import Any, AsyncIterator, Mapping, Protocol
from uuid import UUID

from app.actions import ActionExecutor, ExecutionResult
from app.approval_evidence import ApprovalEvidence
from app.authorization_context import AuthorizationContext
from app.content_safety import TrustClass, assess_untrusted_content
from app.http.realtime import RealtimeOutput, RealtimeOutputType
from app.models import ActionRequest
from app.risk import RiskEvaluation
from app.step_up import StepUpEvidence


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Runtime limits
# ---------------------------------------------------------------------------

MAX_TEXT_INPUT_CHARS = 32_000
MAX_OUTPUT_TEXT_CHARS = 32_000
MAX_AUDIO_INPUT_BYTES = 20 * 1024 * 1024
MAX_AUDIO_OUTPUT_BYTES = 20 * 1024 * 1024

DEFAULT_TURN_TIMEOUT_SECONDS = 120.0

MAX_METADATA_KEYS = 64
MAX_METADATA_KEY_LENGTH = 128
MAX_METADATA_STRING_LENGTH = 2_048


# ---------------------------------------------------------------------------
# Runtime exceptions
# ---------------------------------------------------------------------------


class RealtimeConversationError(Exception):
    """Base error for the conversation engine."""


class RealtimeConversationInputError(RealtimeConversationError):
    """Raised when conversational input is invalid."""


class RealtimeConversationOutputError(RealtimeConversationError):
    """Raised when provider output violates the runtime contract."""


class RealtimeConversationRuntimeUnavailable(RealtimeConversationError):
    """Raised when the provider/runtime is unavailable."""


# ---------------------------------------------------------------------------
# Provider contract
# ---------------------------------------------------------------------------


class ConversationProvider(Protocol):
    """
    Provider-side conversational runtime.

    The provider receives trusted session context only as contextual
    information. It does not receive security authority.

    The provider MUST NOT be treated as an authorization engine.

    Provider output remains untrusted and is validated by this module before
    it reaches the realtime transport.
    """

    async def stream(
        self,
        *,
        authorization_context: AuthorizationContext,
        text: str | None,
        audio: bytes | None,
        conversation_id: UUID,
        turn_id: UUID,
        cancel_event: asyncio.Event,
    ) -> AsyncIterator[RealtimeOutput]:
        ...

    async def interrupt(
        self,
        *,
        authorization_context: AuthorizationContext,
        conversation_id: UUID,
        turn_id: UUID | None,
    ) -> None:
        ...


# ---------------------------------------------------------------------------
# Engine state
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _TurnState:
    authorization_context: AuthorizationContext
    conversation_id: UUID
    turn_id: UUID
    cancel_event: asyncio.Event


# ---------------------------------------------------------------------------
# Realtime conversation engine
# ---------------------------------------------------------------------------


class RealtimeConversationEngine:
    """
    Security-aware realtime conversation orchestrator.

    This class deliberately does NOT become a second authorization system.

    Conversation flow:

        caller input
            |
            v
        input validation
            |
            v
        trusted AuthorizationContext validation
            |
            v
        content safety classification
            |
            v
        provider/model runtime
            |
            v
        provider output validation
            |
            v
        output safety moderation
            |
            v
        realtime transport

    Financial/security actions have a separate path:

        trusted ActionRequest
            +
        trusted AuthorizationContext
            +
        trusted ApprovalEvidence / risk / step-up evidence
            |
            v
        ActionExecutor
            |
            v
        security policy + execution boundary

    The conversation engine never manufactures authorization or approval
    evidence.
    """

    def __init__(
        self,
        provider: ConversationProvider,
        *,
        action_executor: ActionExecutor | None = None,
        turn_timeout_seconds: float = DEFAULT_TURN_TIMEOUT_SECONDS,
    ) -> None:
        if provider is None:
            raise TypeError("provider is required")

        if action_executor is not None and not isinstance(
            action_executor,
            ActionExecutor,
        ):
            raise TypeError(
                "action_executor must be an ActionExecutor"
            )

        if not isinstance(turn_timeout_seconds, (int, float)):
            raise TypeError(
                "turn_timeout_seconds must be numeric"
            )

        if not float(turn_timeout_seconds) > 0:
            raise ValueError(
                "turn_timeout_seconds must be positive"
            )

        self._provider = provider
        self._action_executor = action_executor
        self._turn_timeout_seconds = float(
            turn_timeout_seconds
        )

        self._turns: dict[
            tuple[UUID, UUID, UUID],
            _TurnState,
        ] = {}

        self._turns_lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Public conversation API
    # ------------------------------------------------------------------

    async def stream(
        self,
        *,
        authorization_context: AuthorizationContext,
        text: str | None,
        audio: bytes | None,
        conversation_id: UUID,
        turn_id: UUID,
    ) -> AsyncIterator[RealtimeOutput]:
        """
        Stream one conversational turn.

        Security-sensitive authority is never inferred from text, audio,
        provider output, metadata, or model confidence.
        """

        self._validate_authorization_context(
            authorization_context
        )

        self._validate_turn_identifiers(
            conversation_id,
            turn_id,
        )

        normalized_text, normalized_audio = (
            self._validate_input(
                text=text,
                audio=audio,
            )
        )

        assessment = self._assess_input(
            normalized_text
        )

        # FIX 3: block input that is BLOCKED or carries prompt-injection,
        # secret-request, or privileged-instruction patterns. This is the
        # same rule _moderate_output already applies to provider output.
        if assessment is not None:
            if (
                assessment.trust_class is TrustClass.BLOCKED
                or assessment.contains_prompt_injection
                or assessment.contains_secret_request
                or assessment.contains_privileged_instruction
            ):
                async for output in self._blocked_input_response(
                    turn_id=turn_id,
                ):
                    yield output

                return

        cancel_event = asyncio.Event()

        state = _TurnState(
            authorization_context=authorization_context,
            conversation_id=conversation_id,
            turn_id=turn_id,
            cancel_event=cancel_event,
        )

        key = (
            authorization_context.session_id,
            conversation_id,
            turn_id,
        )

        await self._register_turn(
            key,
            state,
        )

        try:
            try:
                async with asyncio.timeout(
                    self._turn_timeout_seconds
                ):
                    async for output in self._provider_stream(
                        authorization_context=authorization_context,
                        text=normalized_text,
                        audio=normalized_audio,
                        conversation_id=conversation_id,
                        turn_id=turn_id,
                        cancel_event=cancel_event,
                    ):
                        if cancel_event.is_set():
                            return

                        validated = self._validate_provider_output(
                            output
                        )

                        moderated = self._moderate_output(
                            validated
                        )

                        if moderated is None:
                            continue

                        yield moderated

            except asyncio.TimeoutError as exc:
                raise RealtimeConversationRuntimeUnavailable(
                    "realtime conversation provider timed out"
                ) from exc

            except asyncio.CancelledError:
                cancel_event.set()
                raise

            except RealtimeConversationError:
                raise

            except Exception as exc:
                logger.exception(
                    "realtime conversation provider failed",
                    extra={
                        "conversation_id": str(
                            conversation_id
                        ),
                        "turn_id": str(turn_id),
                    },
                )

                raise RealtimeConversationRuntimeUnavailable(
                    "realtime conversation provider is unavailable"
                ) from exc

        finally:
            await self._unregister_turn(
                key
            )

    async def interrupt(
        self,
        *,
        authorization_context: AuthorizationContext,
        conversation_id: UUID,
        turn_id: UUID | None,
    ) -> None:
        """
        Interrupt an active conversational turn.

        Interrupting conversation does not alter authorization state,
        approval state, financial state, or security state.
        """

        self._validate_authorization_context(
            authorization_context
        )

        if not isinstance(conversation_id, UUID):
            raise TypeError(
                "conversation_id must be a UUID"
            )

        if turn_id is not None and not isinstance(
            turn_id,
            UUID,
        ):
            raise TypeError(
                "turn_id must be a UUID or None"
            )

        matching_states: list[_TurnState] = []

        async with self._turns_lock:
            for state in self._turns.values():
                if (
                    state.authorization_context.session_id
                    == authorization_context.session_id
                    and state.conversation_id
                    == conversation_id
                    and (
                        turn_id is None
                        or state.turn_id == turn_id
                    )
                ):
                    state.cancel_event.set()
                    matching_states.append(state)

        try:
            await self._provider_interrupt(
                authorization_context=authorization_context,
                conversation_id=conversation_id,
                turn_id=turn_id,
            )
        except Exception:
            logger.warning(
                "realtime provider interrupt failed",
                extra={
                    "conversation_id": str(
                        conversation_id
                    ),
                    "turn_id": (
                        str(turn_id)
                        if turn_id is not None
                        else None
                    ),
                    "active_turns": len(
                        matching_states
                    ),
                },
                exc_info=True,
            )

    # ------------------------------------------------------------------
    # Explicit action boundary
    # ------------------------------------------------------------------

    async def execute_action(
        self,
        *,
        action: ActionRequest,
        authorization_context: AuthorizationContext,
        approval_evidence: ApprovalEvidence | None = None,
        risk_evaluation: RiskEvaluation | None = None,
        step_up_evidence: StepUpEvidence | None = None,
    ) -> ExecutionResult:
        """
        Delegate an already-formed action to the security execution boundary.

        This method is intentionally NOT reachable through conversational
        text parsing.

        The conversation engine does not:
        - create AuthorizationContext
        - create ApprovalEvidence
        - create RiskEvaluation
        - create StepUpEvidence
        - infer user confirmation
        - infer destination verification
        - infer step-up state
        - promote model confidence into authority
        - execute an action because a model requested it

        ActionExecutor remains the final enforcement boundary.
        """

        self._validate_authorization_context(
            authorization_context
        )

        # FIX 2: the "executor not configured" check now runs before the
        # action type check. Both still fail closed.
        if self._action_executor is None:
            raise RealtimeConversationRuntimeUnavailable(
                "action execution runtime is not configured"
            )

        if not isinstance(action, ActionRequest):
            raise TypeError(
                "action must be an ActionRequest"
            )

        result = self._action_executor.execute(
            action,
            authorization_context,
            approval_evidence,
            risk_evaluation=risk_evaluation,
            step_up_evidence=step_up_evidence,
        )

        return result

    # ------------------------------------------------------------------
    # Provider integration
    # ------------------------------------------------------------------

    async def _provider_stream(
        self,
        *,
        authorization_context: AuthorizationContext,
        text: str | None,
        audio: bytes | None,
        conversation_id: UUID,
        turn_id: UUID,
        cancel_event: asyncio.Event,
    ) -> AsyncIterator[RealtimeOutput]:
        result = self._provider.stream(
            authorization_context=authorization_context,
            text=text,
            audio=audio,
            conversation_id=conversation_id,
            turn_id=turn_id,
            cancel_event=cancel_event,
        )

        if inspect.isawaitable(result):
            result = await result

        if not hasattr(result, "__aiter__"):
            raise RealtimeConversationOutputError(
                "conversation provider must return an async iterator"
            )

        async for output in result:
            yield output

    async def _provider_interrupt(
        self,
        *,
        authorization_context: AuthorizationContext,
        conversation_id: UUID,
        turn_id: UUID | None,
    ) -> None:
        interrupt_method = getattr(
            self._provider,
            "interrupt",
            None,
        )

        if interrupt_method is None:
            return

        result = interrupt_method(
            authorization_context=authorization_context,
            conversation_id=conversation_id,
            turn_id=turn_id,
        )

        if inspect.isawaitable(result):
            await result

    # ------------------------------------------------------------------
    # Authorization validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_authorization_context(
        authorization_context: AuthorizationContext,
    ) -> None:
        if not isinstance(
            authorization_context,
            AuthorizationContext,
        ):
            raise RealtimeConversationInputError(
                "trusted authorization context is missing or invalid"
            )

        try:
            authorization_context.require_trusted()
            # FIX 1: require_valid_at(now) requires an explicit
            # timezone-aware time.
            authorization_context.require_valid_at(
                datetime.now(timezone.utc)
            )
        except Exception as exc:
            raise RealtimeConversationInputError(
                "trusted authorization context is invalid or expired"
            ) from exc

    @staticmethod
    def _validate_turn_identifiers(
        conversation_id: UUID,
        turn_id: UUID,
    ) -> None:
        if not isinstance(
            conversation_id,
            UUID,
        ):
            raise TypeError(
                "conversation_id must be a UUID"
            )

        if not isinstance(
            turn_id,
            UUID,
        ):
            raise TypeError(
                "turn_id must be a UUID"
            )

    # ------------------------------------------------------------------
    # Input validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_input(
        *,
        text: str | None,
        audio: bytes | None,
    ) -> tuple[str | None, bytes | None]:
        if text is not None and not isinstance(
            text,
            str,
        ):
            raise RealtimeConversationInputError(
                "text must be a string or None"
            )

        if audio is not None and not isinstance(
            audio,
            bytes,
        ):
            raise RealtimeConversationInputError(
                "audio must be bytes or None"
            )

        if text is None and audio is None:
            raise RealtimeConversationInputError(
                "realtime turn requires text or audio"
            )

        if text is not None:
            if not text.strip():
                raise RealtimeConversationInputError(
                    "text input cannot be blank"
                )

            if len(text) > MAX_TEXT_INPUT_CHARS:
                raise RealtimeConversationInputError(
                    "text input exceeds the realtime size limit"
                )

            normalized_text = text
        else:
            normalized_text = None

        if audio is not None:
            if not audio:
                raise RealtimeConversationInputError(
                    "audio input cannot be empty"
                )

            if len(audio) > MAX_AUDIO_INPUT_BYTES:
                raise RealtimeConversationInputError(
                    "audio input exceeds the realtime size limit"
                )

        return normalized_text, audio

    @staticmethod
    def _assess_input(
        text: str | None,
    ):
        if text is None:
            return None

        return assess_untrusted_content(
            text
        )

    # ------------------------------------------------------------------
    # Output validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_provider_output(
        output: RealtimeOutput,
    ) -> RealtimeOutput:
        if not isinstance(
            output,
            RealtimeOutput,
        ):
            raise RealtimeConversationOutputError(
                "conversation provider returned invalid output type"
            )

        if not isinstance(
            output.type,
            RealtimeOutputType,
        ):
            raise RealtimeConversationOutputError(
                "conversation provider returned invalid output type value"
            )

        if output.text is not None:
            if not isinstance(
                output.text,
                str,
            ):
                raise RealtimeConversationOutputError(
                    "conversation provider returned invalid text output"
                )

            if len(output.text) > MAX_OUTPUT_TEXT_CHARS:
                raise RealtimeConversationOutputError(
                    "conversation provider returned oversized text output"
                )

        if output.audio is not None:
            if not isinstance(
                output.audio,
                bytes,
            ):
                raise RealtimeConversationOutputError(
                    "conversation provider returned invalid audio output"
                )

            if len(output.audio) > MAX_AUDIO_OUTPUT_BYTES:
                raise RealtimeConversationOutputError(
                    "conversation provider returned oversized audio output"
                )

        metadata = RealtimeConversationEngine._sanitize_metadata(
            output.metadata
        )

        return RealtimeOutput(
            type=output.type,
            text=output.text,
            audio=output.audio,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Output moderation
    # ------------------------------------------------------------------

    @staticmethod
    def _moderate_output(
        output: RealtimeOutput,
    ) -> RealtimeOutput | None:
        """
        Moderate provider text before transport.

        Provider output is never treated as authority.

        BLOCKED content is suppressed.

        Security-sensitive instruction patterns are suppressed because
        conversational model output must not become an indirect command
        channel for security or financial operations.

        Ordinary financial discussion remains possible; actual execution
        still requires ActionExecutor and trusted evidence.
        """

        if output.text is None:
            return output

        assessment = assess_untrusted_content(
            output.text
        )

        if assessment.trust_class is TrustClass.BLOCKED:
            return RealtimeOutput(
                type=output.type,
                text=(
                    "I cannot provide that content through the "
                    "realtime channel."
                ),
                audio=None,
                metadata={},
            )

        if (
            assessment.contains_privileged_instruction
            or assessment.contains_secret_request
            or assessment.contains_prompt_injection
        ):
            return RealtimeOutput(
                type=output.type,
                text=(
                    "I cannot provide instructions that would "
                    "bypass security, expose protected credentials, "
                    "or alter authorization."
                ),
                audio=None,
                metadata={},
            )

        return output

    @staticmethod
    def _sanitize_metadata(
        metadata: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """
        Allow only small transport-safe primitive metadata.

        Security objects, authorization objects, provider objects,
        credentials, arbitrary nested structures, and callable objects
        are never forwarded to the browser.
        """

        if metadata is None:
            return {}

        if not isinstance(
            metadata,
            Mapping,
        ):
            raise RealtimeConversationOutputError(
                "provider metadata must be a mapping"
            )

        result: dict[str, Any] = {}

        for index, (key, value) in enumerate(
            metadata.items()
        ):
            if index >= MAX_METADATA_KEYS:
                break

            if not isinstance(
                key,
                str,
            ):
                continue

            if not key.strip():
                continue

            if len(key) > MAX_METADATA_KEY_LENGTH:
                continue

            if value is None:
                result[key] = None
                continue

            if isinstance(
                value,
                bool,
            ):
                result[key] = value
                continue

            if isinstance(
                value,
                int,
            ):
                result[key] = value
                continue

            if isinstance(
                value,
                float,
            ):
                if value == value and value not in (
                    float("inf"),
                    float("-inf"),
                ):
                    result[key] = value

                continue

            if isinstance(
                value,
                str,
            ):
                if len(value) <= MAX_METADATA_STRING_LENGTH:
                    result[key] = value

                continue

            # Everything else is deliberately discarded.

        return result

    # ------------------------------------------------------------------
    # Blocked-input response
    # ------------------------------------------------------------------

    @staticmethod
    async def _blocked_input_response(
        *,
        turn_id: UUID,
    ) -> AsyncIterator[RealtimeOutput]:
        yield RealtimeOutput(
            type=RealtimeOutputType.RESPONSE_START,
            text=None,
            audio=None,
            metadata={
                "turn_id": str(turn_id),
                "safety_blocked": True,
            },
        )

        yield RealtimeOutput(
            type=RealtimeOutputType.RESPONSE_DELTA,
            text=(
                "I cannot process that request through the "
                "realtime channel."
            ),
            audio=None,
            metadata={
                "safety_blocked": True,
            },
        )

        yield RealtimeOutput(
            type=RealtimeOutputType.RESPONSE_DONE,
            text=None,
            audio=None,
            metadata={
                "safety_blocked": True,
            },
        )

    # ------------------------------------------------------------------
    # Turn registry
    # ------------------------------------------------------------------

    async def _register_turn(
        self,
        key: tuple[UUID, UUID, UUID],
        state: _TurnState,
    ) -> None:
        async with self._turns_lock:
            if key in self._turns:
                raise RealtimeConversationInputError(
                    "realtime turn is already active"
                )

            self._turns[key] = state

    async def _unregister_turn(
        self,
        key: tuple[UUID, UUID, UUID],
    ) -> None:
        async with self._turns_lock:
            self._turns.pop(
                key,
                None,
            )