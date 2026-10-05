from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from starlette.types import Receive, Scope, Send

from .ledger import AppendOnlyLedger, LedgerConflict
from .models import ActionRequest, FinancialEvent
from .security import authorize_action


APP_VERSION = "0.1.1"

_BASE_DIR = Path(__file__).resolve().parent.parent
_STATIC_INDEX = _BASE_DIR / "static" / "index.html"

MAX_REQUEST_BODY_BYTES = 256 * 1024


def _apply_security_headers(response) -> None:
    """
    Apply the Ovela security response-header policy.

    This helper is shared by normal application responses and by the
    request-size middleware's early rejection responses so that security
    failures do not accidentally receive weaker headers.
    """

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'unsafe-inline'; "
        "script-src 'none'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "frame-ancestors 'none'"
    )


class RequestSizeLimitMiddleware:
    """
    Enforce a hard maximum HTTP request-body size.

    Security properties:
    - Rejects declared bodies larger than the limit before buffering them.
    - Handles chunked bodies without buffering an unbounded request.
    - Buffers at most MAX_REQUEST_BODY_BYTES plus one detected overflow
      chunk before rejecting the request.
    - Replays accepted request messages unchanged to the application.
    - Does not apply request-body parsing rules to non-HTTP scopes.
    - Applies the same security response headers to early rejection
      responses as the normal application response path.
    """

    def __init__(self, app: Any):
        self.app = app

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_lengths = [
            value
            for name, value in scope.get("headers", [])
            if name.lower() == b"content-length"
        ]

        if len(content_lengths) > 1:
            try:
                parsed_lengths = {
                    int(value.decode("ascii").strip())
                    for value in content_lengths
                }
            except (UnicodeDecodeError, ValueError):
                response = JSONResponse(
                    {
                        "detail": "invalid Content-Length header",
                    },
                    status_code=400,
                )
                _apply_security_headers(response)
                await response(scope, receive, send)
                return

            if len(parsed_lengths) != 1:
                response = JSONResponse(
                    {
                        "detail": "conflicting Content-Length headers",
                    },
                    status_code=400,
                )
                _apply_security_headers(response)
                await response(scope, receive, send)
                return

        elif len(content_lengths) == 1:
            try:
                declared_length = int(
                    content_lengths[0].decode("ascii").strip()
                )
            except (UnicodeDecodeError, ValueError):
                response = JSONResponse(
                    {
                        "detail": "invalid Content-Length header",
                    },
                    status_code=400,
                )
                _apply_security_headers(response)
                await response(scope, receive, send)
                return

            if declared_length < 0:
                response = JSONResponse(
                    {
                        "detail": "invalid Content-Length header",
                    },
                    status_code=400,
                )
                _apply_security_headers(response)
                await response(scope, receive, send)
                return

            if declared_length > MAX_REQUEST_BODY_BYTES:
                response = JSONResponse(
                    {
                        "detail": "request body is too large",
                    },
                    status_code=413,
                )
                _apply_security_headers(response)
                await response(scope, receive, send)
                return

        buffered_messages: list[dict[str, Any]] = []
        total_bytes = 0

        while True:
            message = await receive()

            if message["type"] != "http.request":
                buffered_messages.append(message)
                break

            body = message.get("body", b"")
            total_bytes += len(body)

            if total_bytes > MAX_REQUEST_BODY_BYTES:
                response = JSONResponse(
                    {
                        "detail": "request body is too large",
                    },
                    status_code=413,
                )
                _apply_security_headers(response)
                await response(scope, receive, send)
                return

            buffered_messages.append(message)

            if not message.get("more_body", False):
                break

        message_index = 0

        async def replay_receive() -> dict[str, Any]:
            nonlocal message_index

            if message_index < len(buffered_messages):
                message = buffered_messages[message_index]
                message_index += 1
                return message

            return await receive()

        await self.app(
            scope,
            replay_receive,
            send,
        )


app = FastAPI(
    title="Ovela Foundation",
    version=APP_VERSION,
)

app.add_middleware(
    RequestSizeLimitMiddleware,
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)

    _apply_security_headers(response)

    return response


def require_internal_key(
    x_ovela_internal_key: str | None = Header(default=None),
) -> None:
    """
    Protect internal endpoints with a server-side secret.

    Security properties:
    - Missing configuration disables the internal API.
    - Missing credentials are rejected.
    - Credential comparison uses constant-time comparison.
    - The configured secret is never returned to the caller.
    """
    expected = os.getenv("OVELA_INTERNAL_KEY")

    if not expected:
        raise HTTPException(
            status_code=503,
            detail="internal API disabled until an internal key is configured",
        )

    if x_ovela_internal_key is None:
        raise HTTPException(
            status_code=403,
            detail="internal authorization failed",
        )

    if not hmac.compare_digest(
        x_ovela_internal_key.encode("utf-8"),
        expected.encode("utf-8"),
    ):
        raise HTTPException(
            status_code=403,
            detail="internal authorization failed",
        )


ledger = AppendOnlyLedger()


@app.get("/")
def home():
    if not _STATIC_INDEX.is_file():
        raise HTTPException(
            status_code=503,
            detail="application frontend is unavailable",
        )

    return FileResponse(
        path=_STATIC_INDEX,
        media_type="text/html",
    )


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "ovela-foundation",
        "version": APP_VERSION,
    }


@app.post(
    "/internal/events",
    response_model=FinancialEvent,
    status_code=201,
)
def append_event(
    event: FinancialEvent,
    _: None = Depends(require_internal_key),
):
    try:
        return ledger.append(event)
    except LedgerConflict as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc


@app.get(
    "/internal/events",
    response_model=list[FinancialEvent],
)
def list_events(
    _: None = Depends(require_internal_key),
):
    return ledger.all()


@app.post("/internal/security/authorize")
def check_authorization(
    action: ActionRequest,
    _: None = Depends(require_internal_key),
):
    decision = authorize_action(action)

    return {
        "action_id": str(action.action_id),
        "allowed": decision.allowed,
        "requires_step_up": decision.requires_step_up,
        "reason": decision.reason,
    }