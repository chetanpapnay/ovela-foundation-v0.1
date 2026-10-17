"""
OVELA / JURIX realtime WebSocket transport boundary.

Endpoint:
    /v1/jurix/stream
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import logging
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, AsyncIterator, Mapping, Protocol
from uuid import UUID, uuid4

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, status
from starlette.websockets import WebSocketState

from app.authorization_context import AuthorizationContext

logger = logging.getLogger(__name__)

router = APIRouter()

MAX_TEXT_MESSAGE_BYTES = 64 * 1024
MAX_JSON_MESSAGE_BYTES = 128 * 1024
MAX_AUDIO_BUFFER_BYTES = 20 * 1024 * 1024
IDLE_TIMEOUT_SECONDS = 120
MAX_MESSAGES_PER_SECOND = 100
MAX_CONCURRENT_TURNS = 1
MAX_AUDIO_FRAME_BYTES = 256 * 1024
PROTOCOL_VERSION = 1


class ClientMessageType(StrEnum):
    HELLO = "hello"
    TEXT = "text"
    AUDIO_START = "audio_start"
    AUDIO_END = "audio_end"
    INTERRUPT = "interrupt"
    PING = "ping"
    CLOSE = "close"


class ServerMessageType(StrEnum):
    READY = "ready"
    TRANSCRIPT = "transcript"
    RESPONSE_START = "response_start"
    RESPONSE_DELTA = "response_delta"
    AUDIO = "audio"
    RESPONSE_DONE = "response_done"
    INTERRUPTED = "interrupted"
    ERROR = "error"
    PONG = "pong"
    CLOSED = "closed"


class RealtimeErrorCode(StrEnum):
    PROTOCOL_ERROR = "protocol_error"
    PROTOCOL_VIOLATION = "protocol_violation"
    MESSAGE_TOO_LARGE = "message_too_large"
    INVALID_MESSAGE = "invalid_message"
    INVALID_SEQUENCE = "invalid_sequence"
    AUTHENTICATION_REQUIRED = "authentication_required"
    SESSION_INVALID = "session_invalid"
    RUNTIME_UNAVAILABLE = "runtime_unavailable"
    RATE_LIMITED = "rate_limited"
    AUDIO_INVALID = "audio_invalid"
    INTERNAL_ERROR = "internal_error"


class RealtimeSessionResolver(Protocol):
    async def resolve(
        self,
        websocket: WebSocket,
    ) -> AuthorizationContext | None:
        ...


class RealtimeConversationEngine(Protocol):
    async def stream(
        self,
        *,
        authorization_context: AuthorizationContext,
        text: str | None,
        audio: bytes | None,
        conversation_id: UUID,
        turn_id: UUID,
    ) -> AsyncIterator["RealtimeOutput"]:
        ...

    async def interrupt(
        self,
        *,
        authorization_context: AuthorizationContext,
        conversation_id: UUID,
        turn_id: UUID | None,
    ) -> None:
        ...


class RealtimeOutputType(StrEnum):
    TRANSCRIPT = "transcript"
    RESPONSE_START = "response_start"
    RESPONSE_DELTA = "response_delta"
    AUDIO = "audio"
    RESPONSE_DONE = "response_done"


@dataclass(frozen=True, slots=True)
class RealtimeOutput:
    type: RealtimeOutputType
    text: str | None = None
    audio: bytes | None = None
    metadata: Mapping[str, Any] | None = None


_session_resolver: RealtimeSessionResolver | None = None
_conversation_engine: RealtimeConversationEngine | None = None


def configure_realtime_runtime(
    *,
    session_resolver: RealtimeSessionResolver,
    conversation_engine: RealtimeConversationEngine,
) -> None:
    if session_resolver is None:
        raise TypeError("session_resolver is required")
    if conversation_engine is None:
        raise TypeError("conversation_engine is required")

    global _session_resolver, _conversation_engine
    _session_resolver = session_resolver
    _conversation_engine = conversation_engine


def clear_realtime_runtime() -> None:
    global _session_resolver, _conversation_engine
    _session_resolver = None
    _conversation_engine = None


@dataclass(slots=True)
class _RateWindow:
    started_at: float
    count: int


@dataclass(slots=True)
class _RealtimeConnection:
    websocket: WebSocket
    connection_id: UUID
    conversation_id: UUID
    authorization_context: AuthorizationContext

    hello_received: bool = False
    closed: bool = False

    audio_buffer: bytearray | None = None
    audio_active: bool = False

    active_turn_id: UUID | None = None
    active_turn_task: asyncio.Task[None] | None = None

    last_activity: float = 0.0
    rate_window: _RateWindow | None = None
    expected_sequence: int = 0

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def check_rate(self) -> bool:
        now = time.monotonic()
        if self.rate_window is None:
            self.rate_window = _RateWindow(started_at=now, count=1)
            return True
        elapsed = now - self.rate_window.started_at
        if elapsed >= 1.0:
            self.rate_window = _RateWindow(started_at=now, count=1)
            return True
        if self.rate_window.count >= MAX_MESSAGES_PER_SECOND:
            return False
        self.rate_window.count += 1
        return True


def _json_bytes(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def _safe_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    if not metadata:
        return {}
    result: dict[str, Any] = {}
    for key, value in metadata.items():
        if not isinstance(key, str) or len(key) > 128:
            continue
        if value is None or isinstance(value, (str, int, float, bool)):
            result[key] = value
    return result


async def _send_json(websocket: WebSocket, payload: Mapping[str, Any]) -> None:
    if websocket.client_state != WebSocketState.CONNECTED:
        return
    encoded = _json_bytes(payload)
    if len(encoded) > MAX_JSON_MESSAGE_BYTES:
        raise RuntimeError("server generated oversized realtime message")
    await websocket.send_text(encoded.decode("utf-8"))


async def _send_error(
    websocket: WebSocket,
    *,
    code: RealtimeErrorCode,
    message: str,
    retryable: bool = False,
) -> None:
    try:
        await _send_json(
            websocket,
            {
                "type": ServerMessageType.ERROR.value,
                "protocol_version": PROTOCOL_VERSION,
                "code": code.value,
                "message": message,
                "retryable": retryable,
            },
        )
    except Exception:
        logger.debug("failed to send realtime error", exc_info=True)


def _decode_json_message(raw: str) -> dict[str, Any]:
    encoded = raw.encode("utf-8")
    if len(encoded) > MAX_JSON_MESSAGE_BYTES:
        raise ValueError("message exceeds protocol size limit")
    try:
        decoded = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON message") from exc
    if not isinstance(decoded, dict):
        raise ValueError("realtime message must be a JSON object")
    return decoded


def _message_type(message: Mapping[str, Any]) -> str:
    value = message.get("type")
    if not isinstance(value, str):
        raise ValueError("message type is required")
    value = value.strip().lower()
    if not value:
        raise ValueError("message type is required")
    return value


def _validate_sequence(
    connection: _RealtimeConnection,
    message: Mapping[str, Any],
) -> None:
    if "sequence" not in message:
        return
    sequence = message["sequence"]
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
        raise ValueError("sequence must be a non-negative integer")
    if sequence != connection.expected_sequence:
        raise ValueError("invalid realtime message sequence")
    connection.expected_sequence += 1


def _validate_text_input(message: Mapping[str, Any]) -> str:
    value = message.get("text")
    if not isinstance(value, str):
        raise ValueError("text must be a string")
    text = value.strip()
    if not text:
        raise ValueError("text cannot be empty")
    if len(text.encode("utf-8")) > MAX_TEXT_MESSAGE_BYTES:
        raise ValueError("text exceeds protocol size limit")
    return text


def _decode_audio_base64(message: Mapping[str, Any]) -> bytes:
    value = message.get("audio")
    if not isinstance(value, str):
        raise ValueError("audio must be a base64 string")
    try:
        audio = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("audio is not valid base64") from exc
    if not audio:
        raise ValueError("audio payload is empty")
    if len(audio) > MAX_AUDIO_FRAME_BYTES:
        raise ValueError("audio frame exceeds protocol size limit")
    return audio


async def _resolve_session(websocket: WebSocket) -> AuthorizationContext:
    resolver = _session_resolver
    if resolver is None:
        raise RuntimeError("realtime session resolver is not configured")
    context = await resolver.resolve(websocket)
    if context is None:
        raise PermissionError("authenticated realtime session is required")
    if not isinstance(context, AuthorizationContext):
        raise PermissionError("realtime session resolver returned invalid context")
    context.require_trusted()
    return context


async def _call_interrupt(connection: _RealtimeConnection) -> None:
    engine = _conversation_engine
    if engine is None:
        return
    try:
        await engine.interrupt(
            authorization_context=connection.authorization_context,
            conversation_id=connection.conversation_id,
            turn_id=connection.active_turn_id,
        )
    except Exception:
        logger.warning(
            "JURIX realtime interrupt failed",
            extra={
                "connection_id": str(connection.connection_id),
                "conversation_id": str(connection.conversation_id),
            },
            exc_info=True,
        )


async def _cancel_active_turn(connection: _RealtimeConnection) -> None:
    task = connection.active_turn_task
    if task is not None and not task.done():
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    connection.active_turn_task = None
    connection.active_turn_id = None


async def _stream_turn(
    connection: _RealtimeConnection,
    *,
    text: str | None,
    audio: bytes | None,
) -> None:
    engine = _conversation_engine
    if engine is None:
        await _send_error(
            connection.websocket,
            code=RealtimeErrorCode.RUNTIME_UNAVAILABLE,
            message="JURIX realtime runtime is unavailable.",
            retryable=True,
        )
        return

    turn_id = uuid4()
    connection.active_turn_id = turn_id

    try:
        await _send_json(
            connection.websocket,
            {
                "type": ServerMessageType.RESPONSE_START.value,
                "protocol_version": PROTOCOL_VERSION,
                "conversation_id": str(connection.conversation_id),
                "turn_id": str(turn_id),
            },
        )

        async for output in engine.stream(
            authorization_context=connection.authorization_context,
            text=text,
            audio=audio,
            conversation_id=connection.conversation_id,
            turn_id=turn_id,
        ):
            if connection.closed:
                return

            if not isinstance(output, RealtimeOutput):
                logger.error("realtime engine emitted invalid output type")
                await _send_error(
                    connection.websocket,
                    code=RealtimeErrorCode.INTERNAL_ERROR,
                    message="JURIX realtime runtime returned invalid output.",
                )
                return

            await _send_output(
                connection,
                output,
                turn_id=turn_id,
            )

    except asyncio.CancelledError:
        raise
    except Exception:
        logger.exception("JURIX realtime turn failed")
        await _send_error(
            connection.websocket,
            code=RealtimeErrorCode.INTERNAL_ERROR,
            message="JURIX could not complete the realtime turn.",
            retryable=True,
        )
    finally:
        connection.active_turn_id = None
        connection.active_turn_task = None


async def _send_output(
    connection: _RealtimeConnection,
    output: RealtimeOutput,
    *,
    turn_id: UUID,
) -> None:
    output_type = output.type

    if output_type == RealtimeOutputType.TRANSCRIPT:
        if not isinstance(output.text, str):
            raise ValueError("transcript output requires text")
        await _send_json(
            connection.websocket,
            {
                "type": ServerMessageType.TRANSCRIPT.value,
                "protocol_version": PROTOCOL_VERSION,
                "conversation_id": str(connection.conversation_id),
                "turn_id": str(turn_id),
                "text": output.text,
                "metadata": _safe_metadata(output.metadata),
            },
        )
        return

    if output_type == RealtimeOutputType.RESPONSE_START:
        await _send_json(
            connection.websocket,
            {
                "type": ServerMessageType.RESPONSE_START.value,
                "protocol_version": PROTOCOL_VERSION,
                "conversation_id": str(connection.conversation_id),
                "turn_id": str(turn_id),
                "metadata": _safe_metadata(output.metadata),
            },
        )
        return

    if output_type == RealtimeOutputType.RESPONSE_DELTA:
        if not isinstance(output.text, str):
            raise ValueError("response_delta output requires text")
        await _send_json(
            connection.websocket,
            {
                "type": ServerMessageType.RESPONSE_DELTA.value,
                "protocol_version": PROTOCOL_VERSION,
                "conversation_id": str(connection.conversation_id),
                "turn_id": str(turn_id),
                "text": output.text,
            },
        )
        return

    if output_type == RealtimeOutputType.AUDIO:
        if not isinstance(output.audio, bytes):
            raise ValueError("audio output requires bytes")
        if not output.audio:
            return
        if len(output.audio) > MAX_AUDIO_FRAME_BYTES:
            raise ValueError("engine emitted oversized audio frame")

        await _send_json(
            connection.websocket,
            {
                "type": ServerMessageType.AUDIO.value,
                "protocol_version": PROTOCOL_VERSION,
                "conversation_id": str(connection.conversation_id),
                "turn_id": str(turn_id),
                "audio": base64.b64encode(output.audio).decode("ascii"),
                "metadata": _safe_metadata(output.metadata),
            },
        )
        return

    if output_type == RealtimeOutputType.RESPONSE_DONE:
        await _send_json(
            connection.websocket,
            {
                "type": ServerMessageType.RESPONSE_DONE.value,
                "protocol_version": PROTOCOL_VERSION,
                "conversation_id": str(connection.conversation_id),
                "turn_id": str(turn_id),
                "metadata": _safe_metadata(output.metadata),
            },
        )
        return

    raise ValueError("unsupported realtime output type")


async def _send_ready(connection: _RealtimeConnection) -> None:
    await _send_json(
        connection.websocket,
        {
            "type": ServerMessageType.READY.value,
            "protocol_version": PROTOCOL_VERSION,
            "connection_id": str(connection.connection_id),
            "conversation_id": str(connection.conversation_id),
            "capabilities": {
                "text": True,
                "audio_input": True,
                "audio_output": True,
                "interrupt": True,
                "streaming": True,
            },
        },
    )


async def _handle_hello(
    connection: _RealtimeConnection,
    message: Mapping[str, Any],
) -> None:
    if connection.hello_received:
        raise ValueError("hello has already been received")

    protocol_version = message.get("protocol_version")
    if protocol_version is None:
        protocol_version = PROTOCOL_VERSION
    if isinstance(protocol_version, bool) or not isinstance(protocol_version, int):
        raise ValueError("protocol_version must be an integer")
    if protocol_version != PROTOCOL_VERSION:
        raise ValueError("unsupported realtime protocol version")

    requested_conversation_id = message.get("conversation_id")
    if requested_conversation_id is not None:
        if not isinstance(requested_conversation_id, str):
            raise ValueError("conversation_id must be a UUID string")
        try:
            requested_uuid = UUID(requested_conversation_id)
        except ValueError as exc:
            raise ValueError("conversation_id must be a UUID string") from exc
        connection.conversation_id = requested_uuid

    connection.hello_received = True
    await _send_ready(connection)


async def _handle_audio_start(connection: _RealtimeConnection) -> None:
    if connection.audio_active:
        raise ValueError("audio input is already active")
    connection.audio_buffer = bytearray()
    connection.audio_active = True


async def _handle_audio_end(connection: _RealtimeConnection) -> None:
    if not connection.audio_active:
        raise ValueError("audio input is not active")
    audio = bytes(connection.audio_buffer or b"")
    connection.audio_buffer = None
    connection.audio_active = False

    if not audio:
        raise ValueError("audio input is empty")
    if len(audio) > MAX_AUDIO_BUFFER_BYTES:
        raise ValueError("audio input exceeds connection limit")

    await _start_turn(
        connection,
        text=None,
        audio=audio,
    )


async def _handle_binary_audio(
    connection: _RealtimeConnection,
    audio: bytes,
) -> None:
    if not connection.audio_active:
        raise ValueError("binary audio received outside audio_start")
    if len(audio) > MAX_AUDIO_FRAME_BYTES:
        raise ValueError("audio frame exceeds protocol size limit")
    if connection.audio_buffer is None:
        connection.audio_buffer = bytearray()
    if len(connection.audio_buffer) + len(audio) > MAX_AUDIO_BUFFER_BYTES:
        connection.audio_buffer = None
        connection.audio_active = False
        raise ValueError("audio input exceeds connection limit")
    connection.audio_buffer.extend(audio)


async def _start_turn(
    connection: _RealtimeConnection,
    *,
    text: str | None,
    audio: bytes | None,
) -> None:
    existing = connection.active_turn_task
    if existing is not None and not existing.done():
        await _send_error(
            connection.websocket,
            code=RealtimeErrorCode.RUNTIME_UNAVAILABLE, message="another realtime turn is already active",
            retryable=True,
        )
        return

    task = asyncio.create_task(
        _stream_turn(
            connection,
            text=text,
            audio=audio,
        )
    )
    connection.active_turn_task = task


async def _handle_text(
    connection: _RealtimeConnection,
    message: Mapping[str, Any],
) -> None:
    text = _validate_text_input(message)
    await _start_turn(
        connection,
        text=text,
        audio=None,
    )


async def _handle_interrupt(connection: _RealtimeConnection) -> None:
    await _call_interrupt(connection)
    await _cancel_active_turn(connection)
    await _send_json(
        connection.websocket,
        {
            "type": ServerMessageType.INTERRUPTED.value,
            "protocol_version": PROTOCOL_VERSION,
            "conversation_id": str(connection.conversation_id),
        },
    )


async def _handle_ping(connection: _RealtimeConnection) -> None:
    await _send_json(
        connection.websocket,
        {
            "type": ServerMessageType.PONG.value,
            "protocol_version": PROTOCOL_VERSION,
        },
    )


@router.websocket("/v1/jurix/stream")
async def jurix_stream(websocket: WebSocket) -> None:
    connection: _RealtimeConnection | None = None

    try:
        try:
            authorization_context = await _resolve_session(websocket)
        except PermissionError:
            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION,
                reason="authenticated realtime session required",
            )
            return
        except RuntimeError:
            await websocket.close(
                code=status.WS_1013_TRY_AGAIN_LATER,
                reason="realtime runtime unavailable",
            )
            return

        await websocket.accept()

        connection = _RealtimeConnection(
            websocket=websocket,
            connection_id=uuid4(),
            conversation_id=uuid4(),
            authorization_context=authorization_context,
            last_activity=time.monotonic(),
        )

        while not connection.closed:
            if (
                time.monotonic() - connection.last_activity
                > IDLE_TIMEOUT_SECONDS
            ):
                await _send_error(
                    websocket,
                    code=RealtimeErrorCode.INVALID_SEQUENCE,
                    message="realtime connection timed out due to inactivity",
                    retryable=True,
                )
                break

            try:
                raw_message = await asyncio.wait_for(
                    websocket.receive(),
                    timeout=IDLE_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                await _send_error(
                    websocket,
                    code=RealtimeErrorCode.INVALID_SEQUENCE,
                    message="realtime connection timed out due to inactivity",
                    retryable=True,
                )
                break

            connection.touch()

            if not connection.check_rate():
                await _send_error(
                    websocket,
                    code=RealtimeErrorCode.RATE_LIMITED,
                    message="realtime message rate limit exceeded",
                    retryable=True,
                )
                await websocket.close(
                    code=status.WS_1013_TRY_AGAIN_LATER,
                    reason="rate limit exceeded",
                )
                return

            if raw_message.get("bytes") is not None:
                if not connection.hello_received:
                    await _send_error(
                        websocket,
                        code=RealtimeErrorCode.INVALID_SEQUENCE,
                        message="hello is required before audio input",
                    )
                    continue

                audio = raw_message["bytes"]
                if not isinstance(audio, bytes):
                    await _send_error(
                        websocket,
                        code=RealtimeErrorCode.AUDIO_INVALID,
                        message="invalid binary audio frame",
                    )
                    continue

                try:
                    await _handle_binary_audio(connection, audio)
                except ValueError as exc:
                    await _send_error(
                        websocket,
                        code=RealtimeErrorCode.AUDIO_INVALID,
                        message=str(exc),
                    )
                continue

            raw_text = raw_message.get("text")
            if raw_text is None:
                await _send_error(
                    websocket,
                    code=RealtimeErrorCode.INVALID_MESSAGE,
                    message="unsupported WebSocket message",
                )
                continue

            if not isinstance(raw_text, str):
                await _send_error(
                    websocket,
                    code=RealtimeErrorCode.INVALID_MESSAGE,
                    message="invalid WebSocket text message",
                )
                continue

            if len(raw_text.encode("utf-8")) > MAX_JSON_MESSAGE_BYTES:
                await _send_error(
                    websocket,
                    code=RealtimeErrorCode.MESSAGE_TOO_LARGE,
                    message="realtime message exceeds protocol size limit",
                )
                continue

            try:
                message = _decode_json_message(raw_text)
                _validate_sequence(connection, message)
                message_type = _message_type(message)

                if message_type == ClientMessageType.HELLO.value:
                    await _handle_hello(connection, message)
                    continue

                if not connection.hello_received:
                    raise ValueError(
                        "hello is required before realtime messages"
                    )

                if message_type == ClientMessageType.TEXT.value:
                    await _handle_text(connection, message)
                    continue

                if message_type == ClientMessageType.AUDIO_START.value:
                    await _handle_audio_start(connection)
                    continue

                if message_type == ClientMessageType.AUDIO_END.value:
                    await _handle_audio_end(connection)
                    continue

                if message_type == ClientMessageType.INTERRUPT.value:
                    await _handle_interrupt(connection)
                    continue

                if message_type == ClientMessageType.PING.value:
                    await _handle_ping(connection)
                    continue

                if message_type == ClientMessageType.CLOSE.value:
                    connection.closed = True
                    break

                raise ValueError(
                    f"unsupported realtime message type: {message_type}"
                )

            except ValueError as exc:
                await _send_error(
                    websocket,
                    code=RealtimeErrorCode.INVALID_MESSAGE,
                    message=str(exc),
                )
            except RuntimeError as exc:
                await _send_error(
                    websocket,
                    code=RealtimeErrorCode.RUNTIME_UNAVAILABLE,
                    message=str(exc),
                    retryable=True,
                )
            except Exception:
                logger.exception("unexpected JURIX realtime protocol error")
                await _send_error(
                    websocket,
                    code=RealtimeErrorCode.INTERNAL_ERROR,
                    message="JURIX realtime transport failed.",
                    retryable=True,
                )

    except WebSocketDisconnect:
        logger.info("JURIX realtime client disconnected")
    except Exception:
        logger.exception("JURIX realtime connection failed")
        if websocket.client_state == WebSocketState.CONNECTED:
            try:
                await _send_error(
                    websocket,
                    code=RealtimeErrorCode.INTERNAL_ERROR,
                    message="JURIX realtime transport failed.",
                    retryable=True,
                )
            finally:
                try:
                    await websocket.close(
                        code=status.WS_1011_INTERNAL_ERROR,
                        reason="internal realtime failure",
                    )
                except Exception:
                    pass
    finally:
        if connection is not None:
            connection.closed = True
            if connection.active_turn_task is not None:
                await _call_interrupt(connection)
                await _cancel_active_turn(connection)
            connection.audio_buffer = None
            connection.audio_active = False

            if websocket.client_state == WebSocketState.CONNECTED:
                try:
                    await _send_json(
                        websocket,
                        {
                            "type": ServerMessageType.CLOSED.value,
                            "protocol_version": PROTOCOL_VERSION,
                        },
                    )
                except Exception:
                    pass

