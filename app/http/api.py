"""Ovela Foundation - HTTP transport adapters for the runtime.

This module is a thin ASGI transport layer. It does exactly four things:

1. Routes an already-verified request to one runtime operation.
2. Parses and strictly validates the JSON body into the runtime DTOs.
3. Calls the runtime with server-authoritative facts taken only from the
   ``VerifiedRequestContext`` (session, tenant, subject, verification time).
4. Maps every outcome to a deterministic status code, error code and response
   carrying the hardened security headers.

Invariants
----------
* No business logic and no ledger access: this module never touches SQL, the
  database connection or the audit chain directly. Every decision is made by
  ``OvelaRuntime``.
* Identity comes only from the verified context. Request bodies cannot carry
  ``tenant_id``, ``subject_id``, ``session_id`` or a spending limit; unknown
  fields are rejected, never ignored.
* The spending limit is server policy, supplied through an injected provider.
* ``simulate_rail_timeout`` is never exposed to clients.
* A client-supplied approval evidence id is only forwarded to the runtime after
  an injected verifier confirms it. Without a verifier it is always refused.
* Routing uses the exact raw path the security boundary verified. No decoding,
  no normalisation, no trailing-slash tolerance.
* Every route requires a verified context. Mounted without the security
  middleware, every request fails closed with 401.
* Error bodies contain only a stable error code; no exception text is leaked.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    FrozenSet,
    List,
    MutableMapping,
    Optional,
    Tuple,
)
from urllib.parse import quote
from uuid import UUID

from app.http.security_boundary import (
    AuthenticationRequired,
    DPoPNonceRequired,
    DPoPReplayStore,
    DPoPVerificationError,
    NonceProvider,
    ReplayDetectedError,
    RequestLimitExceeded,
    SecurityBoundaryConfig,
    SecurityBoundaryError,
    SecurityBoundaryMiddleware,
    SessionResolver,
    UntrustedProxyError,
    VerifiedRequestContext,
    apply_security_headers,
    get_verified_context,
)
from app.runtime import (
    ActionType,
    ApprovalRequired,
    AuditVerifyResponse,
    AuthenticationFailure,
    AuthorizationDenied,
    IdempotencyConflict,
    OvelaRuntime,
    OvelaRuntimeError,
    PaymentExecuteRequest,
    PaymentExecuteResponse,
    PaymentProposeRequest,
    PaymentProposeResponse,
    RailTimeout,
    TenantBoundaryViolation,
)

logger = logging.getLogger(__name__)

__all__ = [
    "ApiConfig",
    "ApprovalEvidenceVerifier",
    "OvelaApi",
    "SpendingLimitProvider",
    "create_app",
    "map_exception",
]

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

SpendingLimitProvider = Callable[[VerifiedRequestContext], Decimal]
"""Returns the server-side spending limit for the verified caller."""

ApprovalEvidenceVerifier = Callable[[VerifiedRequestContext, UUID, UUID], bool]
"""Called as ``(context, request_id, evidence_id)``; must return ``True`` only for valid evidence."""

_Result = Tuple[int, Dict[str, Any], Dict[str, str]]
_Handler = Callable[[VerifiedRequestContext, Scope, Receive], Awaitable[_Result]]

# ---------------------------------------------------------------------------
# Input shapes
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_AMOUNT_RE = re.compile(r"[0-9]{1,18}(?:\.[0-9]{1,8})?")
_CURRENCY_RE = re.compile(r"[A-Za-z]{3}")
# Identifiers end up inside the runtime's "key=value|key=value" audit payloads,
# so the separators "|" and "=" are excluded to prevent field injection.
_IDENT_RE = re.compile(r"[A-Za-z0-9._:@/-]{1,128}")
_META_VALUE_RE = re.compile(
    r"[A-Za-z0-9._:@/-](?:[A-Za-z0-9._:@/ -]{0,126}[A-Za-z0-9._:@/-])?"
)
_HEADER_SAFE_RE = re.compile(r"[!-~]{1,256}")

_PROPOSE_REQUIRED: FrozenSet[str] = frozenset(
    {"action_type", "amount", "currency", "destination_id"}
)
_PROPOSE_OPTIONAL: FrozenSet[str] = frozenset({"metadata"})
_EXECUTE_REQUIRED: FrozenSet[str] = frozenset(
    {"request_id", "action_type", "amount", "currency", "destination_id"}
)
_EXECUTE_OPTIONAL: FrozenSet[str] = frozenset({"approval_evidence_id"})


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ApiConfig:
    """Static configuration of the transport adapters.

    ``offload_to_thread`` runs the synchronous runtime in a worker thread so it
    never blocks the event loop. Set it to ``False`` when the runtime was built
    around a single shared ``sqlite3.Connection`` (which is bound to its thread).
    """

    max_body_bytes: int = 64 * 1024
    max_metadata_entries: int = 16
    offload_to_thread: bool = True
    hsts_max_age: int = 63072000

    def __post_init__(self) -> None:
        for name in ("max_body_bytes", "max_metadata_entries"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if not isinstance(self.offload_to_thread, bool):
            raise ValueError("offload_to_thread must be a boolean")
        if (
            isinstance(self.hsts_max_age, bool)
            or not isinstance(self.hsts_max_age, int)
            or self.hsts_max_age < 0
        ):
            raise ValueError("hsts_max_age must be a non-negative integer")


# ---------------------------------------------------------------------------
# Transport errors and deterministic exception mapping
# ---------------------------------------------------------------------------


class _ApiError(Exception):
    """A transport-level failure with a fixed status and error code."""

    def __init__(
        self,
        status: int,
        code: str,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.headers: Dict[str, str] = dict(headers or {})


def _invalid() -> _ApiError:
    return _ApiError(422, "invalid_request")


_ERROR_MESSAGES: Dict[str, str] = {
    "invalid_request": "The request is invalid.",
    "invalid_json": "The request body is not valid JSON.",
    "unsupported_media_type": "The request content type is not supported.",
    "request_too_large": "The request body is too large.",
    "not_found": "The requested resource was not found.",
    "method_not_allowed": "The HTTP method is not allowed for this resource.",
    "authentication_required": "Authentication is required.",
    "authentication_failed": "Authentication failed.",
    "invalid_dpop_proof": "The request proof is invalid.",
    "use_dpop_nonce": "A valid DPoP nonce is required.",
    "untrusted_proxy": "The request origin is not trusted.",
    "bad_request": "The request could not be accepted.",
    "approval_required": "Additional approval is required for this action.",
    "forbidden": "The requested operation is not permitted.",
    "idempotency_conflict": "The request conflicts with an existing operation.",
    "rail_timeout": "The payment rail did not respond in time.",
    "approval_evidence_invalid": "The approval evidence is invalid.",
    "internal_error": "The request could not be completed.",
}


def _error_message(code: str) -> str:
    return _ERROR_MESSAGES.get(code, "The request could not be completed.")


def map_exception(exc: BaseException) -> Tuple[int, str, Dict[str, str]]:
    """Map any failure to ``(status, error code, extra headers)``.

    The mapping is total and deterministic: the same exception type always
    yields the same response, and anything unrecognised becomes a generic 500.
    ``AuthorizationDenied`` and ``TenantBoundaryViolation`` share one response
    so a caller cannot probe which resources exist in other tenants.
    """
    if isinstance(exc, _ApiError):
        return exc.status, exc.code, dict(exc.headers)

    if isinstance(exc, DPoPNonceRequired):
        headers = {"WWW-Authenticate": 'DPoP error="use_dpop_nonce"'}
        if isinstance(exc.nonce, str) and _HEADER_SAFE_RE.fullmatch(exc.nonce):
            headers["DPoP-Nonce"] = exc.nonce
        return 401, "use_dpop_nonce", headers
    if isinstance(exc, AuthenticationRequired):
        return 401, "authentication_required", {"WWW-Authenticate": "DPoP"}
    if isinstance(exc, (DPoPVerificationError, ReplayDetectedError)):
        return (
            401,
            "invalid_dpop_proof",
            {"WWW-Authenticate": 'DPoP error="invalid_dpop_proof"'},
        )
    if isinstance(exc, UntrustedProxyError):
        return 400, "untrusted_proxy", {}
    if isinstance(exc, RequestLimitExceeded):
        return exc.status_code, "request_too_large", {}
    if isinstance(exc, SecurityBoundaryError):
        return 400, "bad_request", {}

    if isinstance(exc, AuthenticationFailure):
        return (
            401,
            "authentication_failed",
            {"WWW-Authenticate": 'DPoP error="invalid_token"'},
        )
    if isinstance(exc, ApprovalRequired):
        return 403, "approval_required", {}
    if isinstance(exc, (AuthorizationDenied, TenantBoundaryViolation)):
        return 403, "forbidden", {}
    if isinstance(exc, IdempotencyConflict):
        return 409, "idempotency_conflict", {}
    if isinstance(exc, RailTimeout):
        return 504, "rail_timeout", {}
    if isinstance(exc, OvelaRuntimeError):
        return 500, "internal_error", {}

    return 500, "internal_error", {}


# ---------------------------------------------------------------------------
# Request helpers
# ---------------------------------------------------------------------------


def _request_path(scope: Scope) -> str:
    """Return the raw request path (no query string), exactly as the boundary verified it."""
    raw = scope.get("raw_path")
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("latin-1")
    else:
        text = quote(str(scope.get("path", "")), safe="/-._~!$&'()*+,;=:@%")
    return text.split("?", 1)[0]


def _header_values(scope: Scope, name: bytes) -> List[str]:
    values: List[str] = []
    for item in scope.get("headers") or []:
        try:
            header_name, header_value = item
        except (TypeError, ValueError):
            continue
        if not isinstance(header_name, (bytes, bytearray)):
            continue
        if not isinstance(header_value, (bytes, bytearray)):
            continue
        if bytes(header_name).lower() == name:
            values.append(bytes(header_value).decode("latin-1").strip())
    return values


def _require_json_content_type(scope: Scope) -> None:
    values = _header_values(scope, b"content-type")
    if len(values) != 1:
        raise _ApiError(415, "unsupported_media_type")
    parts = [part.strip() for part in values[0].split(";")]
    if parts[0].lower() != "application/json":
        raise _ApiError(415, "unsupported_media_type")
    for parameter in parts[1:]:
        if parameter.lower().replace(" ", "") != "charset=utf-8":
            raise _ApiError(415, "unsupported_media_type")


def _reject_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite JSON constant: {name}")


def _parse_json_object(raw: bytes) -> Dict[str, Any]:
    if not raw:
        raise _ApiError(400, "invalid_json")
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise _ApiError(400, "invalid_json") from None
    if not isinstance(data, dict):
        raise _invalid()
    return data


# ---------------------------------------------------------------------------
# Body validation (syntax only; every business rule stays in the runtime)
# ---------------------------------------------------------------------------


def _check_fields(
    data: Dict[str, Any], required: FrozenSet[str], optional: FrozenSet[str]
) -> None:
    keys = set(data)
    if not required <= keys or not keys <= (required | optional):
        raise _invalid()


def _text_field(data: Dict[str, Any], key: str, pattern: "re.Pattern[str]") -> str:
    value = data.get(key)
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise _invalid()
    return value


def _uuid_value(value: Any) -> UUID:
    if not isinstance(value, str) or not _UUID_RE.fullmatch(value):
        raise _invalid()
    return UUID(value)


def _action_type(data: Dict[str, Any]) -> ActionType:
    value = data.get("action_type")
    if not isinstance(value, str):
        raise _invalid()
    try:
        return ActionType(value)
    except ValueError:
        raise _invalid() from None


def _amount(data: Dict[str, Any]) -> Decimal:
    text = _text_field(data, "amount", _AMOUNT_RE)
    amount = Decimal(text)
    if amount <= Decimal("0"):
        raise _invalid()
    return amount


def _metadata(data: Dict[str, Any], max_entries: int) -> Dict[str, str]:
    if "metadata" not in data:
        return {}
    raw = data["metadata"]
    if not isinstance(raw, dict) or len(raw) > max_entries:
        raise _invalid()
    result: Dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not _IDENT_RE.fullmatch(key):
            raise _invalid()
        if not isinstance(value, str) or not _META_VALUE_RE.fullmatch(value):
            raise _invalid()
        result[key] = value
    return result


def _parse_propose(
    data: Dict[str, Any], max_metadata_entries: int
) -> PaymentProposeRequest:
    _check_fields(data, _PROPOSE_REQUIRED, _PROPOSE_OPTIONAL)
    return PaymentProposeRequest(
        action_type=_action_type(data),
        amount=_amount(data),
        currency=_text_field(data, "currency", _CURRENCY_RE),
        destination_id=_text_field(data, "destination_id", _IDENT_RE),
        metadata=_metadata(data, max_metadata_entries),
    )


def _parse_execute(data: Dict[str, Any]) -> PaymentExecuteRequest:
    _check_fields(data, _EXECUTE_REQUIRED, _EXECUTE_OPTIONAL)
    evidence_raw = data.get("approval_evidence_id")
    evidence_id: Optional[UUID] = None
    if evidence_raw is not None:
        evidence_id = _uuid_value(evidence_raw)
    return PaymentExecuteRequest(
        request_id=_uuid_value(data.get("request_id")),
        action_type=_action_type(data),
        amount=_amount(data),
        currency=_text_field(data, "currency", _CURRENCY_RE),
        destination_id=_text_field(data, "destination_id", _IDENT_RE),
        approval_evidence_id=evidence_id,
    )


# ---------------------------------------------------------------------------
# Response bodies
# ---------------------------------------------------------------------------


def _propose_body(response: PaymentProposeResponse) -> Dict[str, Any]:
    return {
        "request_id": str(response.request_id),
        "decision": response.decision.value,
        "approval_required": bool(response.approval_required),
        "reason": response.reason,
    }


def _execute_body(response: PaymentExecuteResponse) -> Dict[str, Any]:
    return {
        "transaction_id": str(response.transaction_id),
        "state": response.state.value,
        "outbox_id": str(response.outbox_id),
        "audit_sequence": int(response.audit_sequence),
    }


def _audit_body(response: AuditVerifyResponse) -> Dict[str, Any]:
    return {
        "valid": bool(response.valid),
        "tenant_id": str(response.tenant_id),
        "records_verified": int(response.records_verified),
        "head_sequence": response.head_sequence,
        "first_failure": response.first_failure,
    }


# ---------------------------------------------------------------------------
# The ASGI application
# ---------------------------------------------------------------------------


class OvelaApi:
    """Thin ASGI adapter exposing the runtime's session-authenticated operations.

    Routes
    ------
    ``POST /v1/payments/propose``  -> ``OvelaRuntime.propose_payment``  (201)
    ``POST /v1/payments/execute``  -> ``OvelaRuntime.execute_payment``  (202)
    ``GET  /v1/audit/verify``      -> ``OvelaRuntime.verify_audit_chain`` (200)
    """

    def __init__(
        self,
        runtime: OvelaRuntime,
        *,
        spending_limit_provider: SpendingLimitProvider,
        approval_verifier: Optional[ApprovalEvidenceVerifier] = None,
        config: Optional[ApiConfig] = None,
    ) -> None:
        if not callable(spending_limit_provider):
            raise TypeError("spending_limit_provider must be callable")
        if approval_verifier is not None and not callable(approval_verifier):
            raise TypeError("approval_verifier must be callable or None")
        self._runtime = runtime
        self._spending_limit_provider = spending_limit_provider
        self._approval_verifier = approval_verifier
        self._config = config if config is not None else ApiConfig()
        self._routes: Dict[str, Dict[str, _Handler]] = {
            "/v1/payments/propose": {"POST": self._handle_propose},
            "/v1/payments/execute": {"POST": self._handle_execute},
            "/v1/audit/verify": {"GET": self._handle_audit_verify},
        }

    # -- ASGI entry point --------------------------------------------------------

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope_type = scope.get("type")
        if scope_type == "lifespan":
            await self._lifespan(receive, send)
            return
        if scope_type == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope_type != "http":
            return

        request_id: Optional[str] = None
        try:
            context = scope.get("ovela.verified_request_context")
            if context is None:
                context = get_verified_context(scope)
            request_id = getattr(context, "request_id", None)
            status, payload, headers = await self._dispatch(context, scope, receive)
        except Exception as exc:
            status, code, headers = map_exception(exc)
            payload = {"error": code, "message": _error_message(code)}
            if status >= 500:
                logger.error("request failed: %s", type(exc).__name__)
            else:
                logger.warning("request rejected: %s", type(exc).__name__)

        await self._send_json(send, status, payload, headers, request_id)

    # -- internals ---------------------------------------------------------------

    @staticmethod
    async def _lifespan(receive: Receive, send: Send) -> None:
        while True:
            message = await receive()
            message_type = message.get("type")
            if message_type == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message_type == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return

    async def _dispatch(
        self, context: VerifiedRequestContext, scope: Scope, receive: Receive
    ) -> _Result:
        try:
            route = self._routes.get(_request_path(scope))
            if route is None:
                raise _ApiError(404, "not_found")
            method = scope.get("method")
            handler = route.get(method) if isinstance(method, str) else None
            if handler is None:
                raise _ApiError(
                    405,
                    "method_not_allowed",
                    {"Allow": ", ".join(sorted(route))},
                )
            return await handler(context, scope, receive)
        except (
            _ApiError,
            ApprovalRequired,
            TenantBoundaryViolation,
            AuthorizationDenied,
            IdempotencyConflict,
            RailTimeout,
            OvelaRuntimeError,
        ) as exc:
            status, code, headers = map_exception(exc)
            if status >= 500:
                logger.error("request failed: %s", type(exc).__name__)
            else:
                logger.warning("request rejected: %s", type(exc).__name__)
            return (
                status,
                {"error": code, "message": _error_message(code)},
                headers,
            )

    async def _run(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        if self._config.offload_to_thread:
            return await asyncio.to_thread(func, *args, **kwargs)
        return func(*args, **kwargs)

    async def _read_body(self, receive: Receive) -> bytes:
        chunks: List[bytes] = []
        total = 0
        while True:
            message = await receive()
            if message.get("type") != "http.request":
                raise _ApiError(400, "invalid_request")
            chunk = message.get("body", b"")
            if not isinstance(chunk, (bytes, bytearray)):
                raise _ApiError(400, "invalid_request")
            total += len(chunk)
            if total > self._config.max_body_bytes:
                raise _ApiError(413, "request_too_large")
            chunks.append(bytes(chunk))
            if not message.get("more_body", False):
                return b"".join(chunks)

    async def _read_json_object(
        self, scope: Scope, receive: Receive
    ) -> Dict[str, Any]:
        _require_json_content_type(scope)
        return _parse_json_object(await self._read_body(receive))

    async def _spending_limit(self, context: VerifiedRequestContext) -> Decimal:
        limit = await self._run(self._spending_limit_provider, context)
        if not isinstance(limit, Decimal):
            raise TypeError("spending limit provider must return a Decimal")
        return limit

    async def _require_approval_evidence(
        self,
        context: VerifiedRequestContext,
        request_id: UUID,
        evidence_id: UUID,
    ) -> None:
        verifier = self._approval_verifier
        if verifier is None:
            raise _ApiError(403, "approval_evidence_invalid")
        verified = await self._run(verifier, context, request_id, evidence_id)
        if verified is not True:
            raise _ApiError(403, "approval_evidence_invalid")

    # -- route handlers (transport only) -----------------------------------------

    async def _handle_propose(
        self, context: VerifiedRequestContext, scope: Scope, receive: Receive
    ) -> _Result:
        data = await self._read_json_object(scope, receive)
        request = _parse_propose(data, self._config.max_metadata_entries)
        limit = await self._spending_limit(context)
        response = await self._run(
            self._runtime.propose_payment,
            context.session_id,
            request,
            limit,
            context.verified_at,
        )
        return 201, _propose_body(response), {}

    async def _handle_execute(
        self, context: VerifiedRequestContext, scope: Scope, receive: Receive
    ) -> _Result:
        data = await self._read_json_object(scope, receive)
        request = _parse_execute(data)
        evidence_id = request.approval_evidence_id
        if evidence_id is not None:
            await self._require_approval_evidence(
                context, request.request_id, evidence_id
            )
        limit = await self._spending_limit(context)
        response = await self._run(
            self._runtime.execute_payment,
            context.session_id,
            request,
            limit,
            simulate_rail_timeout=False,
            now=context.verified_at,
        )
        return 202, _execute_body(response), {}

    async def _handle_audit_verify(
        self, context: VerifiedRequestContext, scope: Scope, receive: Receive
    ) -> _Result:
        response = await self._run(
            self._runtime.verify_audit_chain, context.tenant_id
        )
        return 200, _audit_body(response), {}

    # -- response ----------------------------------------------------------------

    async def _send_json(
        self,
        send: Send,
        status: int,
        payload: Dict[str, Any],
        extra_headers: Dict[str, str],
        request_id: Optional[str],
    ) -> None:
        body = json.dumps(
            payload,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        headers: List[Tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        for name, value in extra_headers.items():
            headers.append(
                (
                    name.lower().encode("latin-1"),
                    value.encode("latin-1"),
                )
            )
        if request_id is not None:
            headers.append((b"x-request-id", request_id.encode("ascii")))
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": apply_security_headers(
                    headers,
                    hsts_max_age=self._config.hsts_max_age,
                ),
            }
        )
        await send({"type": "http.response.body", "body": body})


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_app(
    runtime: OvelaRuntime,
    *,
    boundary_config: SecurityBoundaryConfig,
    session_resolver: SessionResolver,
    replay_store: DPoPReplayStore,
    spending_limit_provider: SpendingLimitProvider,
    approval_verifier: Optional[ApprovalEvidenceVerifier] = None,
    nonce_provider: Optional[NonceProvider] = None,
    api_config: Optional[ApiConfig] = None,
    clock: Callable[[], datetime] = _utcnow,
) -> ASGIApp:
    """Build the production ASGI application: the security boundary around the API.

    No path is public, so every route is DPoP-verified before it is reached and
    every response, including rejections, carries the security headers.
    """
    resolved_api_config = (
        api_config
        if api_config is not None
        else ApiConfig(hsts_max_age=boundary_config.hsts_max_age)
    )
    api = OvelaApi(
        runtime,
        spending_limit_provider=spending_limit_provider,
        approval_verifier=approval_verifier,
        config=resolved_api_config,
    )
    return SecurityBoundaryMiddleware(
        api,
        config=boundary_config,
        session_resolver=session_resolver,
        replay_store=replay_store,
        nonce_provider=nonce_provider,
        public_paths=frozenset(),
        clock=clock,
    )