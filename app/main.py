from __future__ import annotations

import hmac
import os
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from starlette.types import Receive, Scope, Send

from .http.api import ApiConfig, OvelaApi
from .ledger import AppendOnlyLedger, LedgerConflict
from .models import ActionRequest, FinancialEvent
from .runtime import OvelaRuntime


APP_VERSION = "0.1.1"

_BASE_DIR = Path(__file__).resolve().parent.parent
_STATIC_INDEX = _BASE_DIR / "static" / "index.html"

MAX_REQUEST_BODY_BYTES = 256 * 1024


def _apply_security_headers(response: Any) -> None:
    """Apply the Ovela security response-header policy.

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
    """Enforce a hard maximum HTTP request-body size.

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

        path = scope.get("path", "")
        if path.startswith("/v1"):
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
                    {"detail": "invalid Content-Length header"},
                    status_code=400,
                )
                _apply_security_headers(response)
                await response(scope, receive, send)
                return

            if len(parsed_lengths) != 1:
                response = JSONResponse(
                    {"detail": "conflicting Content-Length headers"},
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
                    {"detail": "invalid Content-Length header"},
                    status_code=400,
                )
                _apply_security_headers(response)
                await response(scope, receive, send)
                return

            if declared_length < 0:
                response = JSONResponse(
                    {"detail": "invalid Content-Length header"},
                    status_code=400,
                )
                _apply_security_headers(response)
                await response(scope, receive, send)
                return

            if declared_length > MAX_REQUEST_BODY_BYTES:
                response = JSONResponse(
                    {"detail": "request body is too large"},
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
                    {"detail": "request body is too large"},
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
                msg = buffered_messages[message_index]
                message_index += 1
                return msg

            return await receive()

        await self.app(scope, replay_receive, send)


def _default_spending_limit_provider(_context: Any) -> Decimal:
    """Default spending limit provider for live runtime execution."""
    return Decimal("100000.00")


ledger = AppendOnlyLedger()


def require_internal_key(
    x_ovela_internal_key: str | None = Header(default=None),
) -> None:
    """Protect legacy internal endpoints with a server-side secret."""
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


def create_application(
    runtime: OvelaRuntime | None = None,
    api_config: ApiConfig | None = None,
) -> FastAPI:
    """Create and configure the production ASGI FastAPI application."""
    app_instance = FastAPI(
        title="Ovela Foundation",
        version=APP_VERSION,
    )

    cors_env = os.getenv("OVELA_CORS_ORIGINS", "")
    if cors_env.strip():
        allowed_origins = [
            origin.strip() for origin in cors_env.split(",") if origin.strip()
        ]
    else:
        allowed_origins = [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]

    app_instance.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    app_instance.add_middleware(RequestSizeLimitMiddleware)

    @app_instance.middleware("http")
    async def security_headers_middleware(request: Any, call_next: Any) -> Any:
        response = await call_next(request)
        _apply_security_headers(response)
        return response

    @app_instance.get("/")
    def home() -> Any:
        if not _STATIC_INDEX.is_file():
            raise HTTPException(
                status_code=503,
                detail="application frontend is unavailable",
            )

        return FileResponse(
            path=_STATIC_INDEX,
            media_type="text/html",
        )

    @app_instance.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": "ovela-foundation",
            "version": APP_VERSION,
            "kernel": "active",
        }

    @app_instance.post(
        "/internal/events",
        response_model=FinancialEvent,
        status_code=201,
    )
    def append_event(
        event: FinancialEvent,
        _: None = Depends(require_internal_key),
    ) -> Any:
        try:
            return ledger.append(event)
        except LedgerConflict as exc:
            raise HTTPException(
                status_code=409,
                detail=str(exc),
            ) from exc

    @app_instance.get(
        "/internal/events",
        response_model=list[FinancialEvent],
    )
    def list_events(
        _: None = Depends(require_internal_key),
    ) -> list[FinancialEvent]:
        return ledger.all()

    @app_instance.post("/internal/security/authorize")
    def check_authorization(
        action: ActionRequest,
        _: None = Depends(require_internal_key),
    ) -> None:
        raise HTTPException(
            status_code=503,
            detail="trusted authorization context is unavailable",
        )

    # Initialize runtime and mount OvelaApi ASGI application
    app_runtime = runtime if runtime is not None else OvelaRuntime()
    ovela_api = OvelaApi(
        runtime=app_runtime,
        spending_limit_provider=_default_spending_limit_provider,
        config=api_config,
    )

    app_instance.mount("/v1", ovela_api)

    return app_instance


app = create_application()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)