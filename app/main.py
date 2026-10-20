from __future__ import annotations

import hmac
import os
import re
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.types import Receive, Scope, Send

from .http.api import ApiConfig, OvelaApi
from .ingest_router import register_ingest_endpoints
from .ledger import AppendOnlyLedger, LedgerConflict
from .models import ActionRequest, FinancialEvent
from .runtime import OvelaRuntime
from .supabase_client import (
    fetch_account_summary,
    fetch_recent_transactions,
    insert_financial_event,
)


APP_VERSION = "0.1.1"

_BASE_DIR = Path(__file__).resolve().parent.parent
_STATIC_INDEX = _BASE_DIR / "static" / "index.html"

MAX_REQUEST_BODY_BYTES = 256 * 1024


class FinancialEventCreate(BaseModel):
    account_id: str
    source_id: str = "RENDER_CLI"
    source_event_id: str
    event_type: str = "EXPENSE"
    amount: float = Field(..., gt=0)
    currency: str = "INR"
    direction: str = "DEBIT"
    merchant: str = "Unknown"
    note: str = ""


class RawSmsPayload(BaseModel):
    message: str
    account_id: str = "PRIMARY-ACC"


def _apply_security_headers(response: Any) -> None:
    """Apply the Ovela security response-header policy."""
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
    """Enforce a hard maximum HTTP request-body size."""

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

    # Mount OvelaApi ASGI application
    app_runtime = runtime if runtime is not None else OvelaRuntime()
    ovela_api = OvelaApi(
        runtime=app_runtime,
        spending_limit_provider=_default_spending_limit_provider,
        config=api_config,
    )

    @app_instance.get("/api/transactions")
    def get_live_transactions(limit: int = 50) -> Any:
        try:
            return fetch_recent_transactions(limit=limit)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app_instance.post("/api/transactions", status_code=201)
    def create_live_transaction(payload: FinancialEventCreate) -> Any:
        try:
            return insert_financial_event(
                account_id=payload.account_id,
                source_id=payload.source_id,
                source_event_id=payload.source_event_id,
                event_type=payload.event_type,
                amount=payload.amount,
                currency=payload.currency,
                direction=payload.direction,
                merchant=payload.merchant,
                note=payload.note,
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app_instance.post("/api/ingest/sms", status_code=201)
    def auto_ingest_sms(payload: RawSmsPayload) -> Any:
        """Parse raw bank SMS notifications and commit directly to Supabase."""
        text = payload.message

        # 1. Regex to extract numeric amount (supports Rs., INR, with or without decimals/commas)
        amt_match = re.search(r"(?:Rs\.?|INR)\s*([\d,]+(?:\.\d{1,2})?)", text, re.IGNORECASE)
        if not amt_match:
            raise HTTPException(status_code=400, detail="No currency or amount detected in message")
        amount = float(amt_match.group(1).replace(",", ""))

        # 2. Identify transaction direction and event category
        is_debit = bool(re.search(r"\b(debited|spent|sent|paid|withdrawn|purchase)\b", text, re.IGNORECASE))
        direction = "DEBIT" if is_debit else "CREDIT"
        event_type = "EXPENSE" if is_debit else "INCOME"

        # 3. Extract beneficiary or merchant
        merchant_match = re.search(
            r"(?:to|at|info|vpa|transferred to)\s+([A-Za-z0-9\s\.\-_]+?)(?=\s+(?:on|ref|via|avl|bal|upi|dated)|\.|$)",
            text,
            re.IGNORECASE,
        )
        merchant = merchant_match.group(1).strip() if merchant_match else "Unknown"

        # 4. Save parsed record directly to Supabase
        timestamp_id = int(datetime.utcnow().timestamp())
        try:
            return insert_financial_event(
                account_id=payload.account_id,
                source_id="PHONE_SMS_AUTO",
                source_event_id=f"AUTO-{timestamp_id}",
                event_type=event_type,
                amount=amount,
                currency="INR",
                direction=direction,
                merchant=merchant,
                note=text[:150],
            )
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    @app_instance.get("/api/summary")
    def get_live_summary() -> Any:
        try:
            return fetch_account_summary()
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    register_ingest_endpoints(app_instance, ledger)
    app_instance.mount("/v1", ovela_api)

    return app_instance


app = create_application()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)