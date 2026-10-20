from __future__ import annotations

import hmac
import os
import re
from datetime import date, datetime
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

APP_VERSION = "0.1.2"

_BASE_DIR = Path(__file__).resolve().parent.parent
_STATIC_INDEX = _BASE_DIR / "static" / "index.html"

MAX_REQUEST_BODY_BYTES = 256 * 1024


# --- USER PROFILE & NET WORTH CONFIGURATION ---
USER_PROFILE = {
    "name": "Chetan Papnay",
    "dob": "2006-01-01",  # Placeholder: Updated when you share your exact details
    "base_currency": "INR",
    "assets": {
        "offline_cash": 0.0,
        "mutual_funds": 0.0,
        "gold": 0.0,
        "fixed_deposits": 0.0,
        "crypto": 0.0,
    }
}


def calculate_dynamic_age(dob_str: str) -> dict[str, Any]:
    """Calculates age in years, months, and days dynamically without third-party libraries."""
    birth_date = date.fromisoformat(dob_str)
    today = date.today()

    years = today.year - birth_date.year
    months = today.month - birth_date.month
    days = today.day - birth_date.day

    if days < 0:
        months -= 1
        # Previous month day count approximation
        prev_month = 12 if today.month == 1 else today.month - 1
        year_for_month = today.year - 1 if today.month == 1 else today.year
        days_in_prev_month = (date(year_for_month, prev_month % 12 + 1, 1) - date(year_for_month, prev_month, 1)).days if prev_month != 12 else 31
        days += days_in_prev_month

    if months < 0:
        years -= 1
        months += 12

    return {
        "dob": dob_str,
        "as_of_date": today.isoformat(),
        "years": years,
        "months": months,
        "days": days,
        "formatted_age": f"{years} years, {months} months, {days} days"
    }


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
    account_id: str = "AUTO_DETECT"


def _apply_security_headers(response: Any) -> None:
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
    return Decimal("100000.00")


ledger = AppendOnlyLedger()


def require_internal_key(
    x_ovela_internal_key: str | None = Header(default=None),
) -> None:
    expected = os.getenv("OVELA_INTERNAL_KEY")
    if not expected:
        raise HTTPException(
            status_code=503,
            detail="internal API disabled until an internal key is configured",
        )
    if x_ovela_internal_key is None or not hmac.compare_digest(
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
    app_instance = FastAPI(
        title="Ovela Foundation",
        version=APP_VERSION,
    )

    cors_env = os.getenv("OVELA_CORS_ORIGINS", "")
    allowed_origins = (
        [origin.strip() for origin in cors_env.split(",") if origin.strip()]
        if cors_env.strip()
        else ["http://localhost:5173", "http://127.0.0.1:5173"]
    )

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
        return FileResponse(path=_STATIC_INDEX, media_type="text/html")

    @app_instance.get("/health")
    def health() -> dict[str, str]:
        return {
            "status": "ok",
            "service": "ovela-foundation",
            "version": APP_VERSION,
            "kernel": "active",
        }

    @app_instance.get("/api/profile")
    def get_profile() -> Any:
        age_data = calculate_dynamic_age(USER_PROFILE["dob"])
        return {
            "name": USER_PROFILE["name"],
            "dob": USER_PROFILE["dob"],
            "dynamic_age": age_data,
            "base_currency": USER_PROFILE["base_currency"],
        }

    @app_instance.get("/api/networth")
    def get_networth() -> Any:
        summary = fetch_account_summary()
        online_liquid = 0.0
        for item in summary:
            inc = float(item.get("total_income", 0.0))
            exp = float(item.get("total_expenses", 0.0))
            online_liquid += (inc - exp)

        offline_cash = float(USER_PROFILE["assets"]["offline_cash"])
        mutual_funds = float(USER_PROFILE["assets"]["mutual_funds"])
        gold = float(USER_PROFILE["assets"]["gold"])
        fixed_deposits = float(USER_PROFILE["assets"]["fixed_deposits"])

        total_net_worth = online_liquid + offline_cash + mutual_funds + gold + fixed_deposits

        return {
            "net_worth_inr": round(total_net_worth, 2),
            "breakdown": {
                "liquid_online_cash": round(online_liquid, 2),
                "offline_cash_in_hand": round(offline_cash, 2),
                "mutual_funds": round(mutual_funds, 2),
                "gold": round(gold, 2),
                "fixed_deposits": round(fixed_deposits, 2),
            },
            "bank_accounts": summary,
        }

    @app_instance.post("/internal/events", response_model=FinancialEvent, status_code=201)
    def append_event(
        event: FinancialEvent,
        _: None = Depends(require_internal_key),
    ) -> Any:
        try:
            return ledger.append(event)
        except LedgerConflict as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app_instance.get("/internal/events", response_model=list[FinancialEvent])
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
        text = payload.message
        upper = text.upper()

        amt_match = re.search(r"(?:Rs\.?|INR|₹)\s*([\d,]+(?:\.\d{1,2})?)", text, re.IGNORECASE)
        if not amt_match:
            raise HTTPException(status_code=400, detail="No currency or amount detected in message")
        amount = float(amt_match.group(1).replace(",", ""))

        is_debit = bool(
            re.search(
                r"\b(debited|spent|sent|paid|withdrawn|purchase|transferred to|deducted)\b",
                text,
                re.IGNORECASE,
            )
        )
        direction = "DEBIT" if is_debit else "CREDIT"
        event_type = "EXPENSE" if is_debit else "INCOME"

        account_id = payload.account_id
        if account_id == "AUTO_DETECT":
            if "NAVI" in upper:
                account_id = "NAVI_UPI"
            elif "GPAY" in upper or "GOOGLE PAY" in upper:
                account_id = "GOOGLE_PAY"
            elif "KOTAK" in upper:
                account_id = "KOTAK_BANK"
            elif "BARODA" in upper or "BOB" in upper:
                account_id = "BOB_BANK"
            elif "HDFC" in upper:
                account_id = "HDFC_BANK"
            elif "SBI" in upper or "STATE BANK" in upper:
                account_id = "SBI_BANK"
            elif "ICICI" in upper:
                account_id = "ICICI_BANK"
            elif "AXIS" in upper:
                account_id = "AXIS_BANK"
            elif "PAYTM" in upper:
                account_id = "PAYTM_UPI"
            elif "PHONEPE" in upper:
                account_id = "PHONEPE_UPI"
            else:
                account_id = "PRIMARY_UPI_ACCOUNT"

        vpa_match = re.search(r"\b([a-zA-Z0-9.\-_]{2,35}@[a-zA-Z]{2,15})\b", text)
        merchant_match = re.search(
            r"(?:to|at|info|vpa|transferred to|paid to|remitter\s*(?:name)?[:\s]+)\s+([A-Za-z0-9\s\.\-_&]+?)(?=\s+(?:on|ref|via|avl|bal|upi|dated|from|for)|\.|$)",
            text,
            re.IGNORECASE,
        )

        if vpa_match and not any(k in vpa_match.group(1).lower() for k in ["kotak", "bankofbaroda"]):
            merchant = vpa_match.group(1).strip()
        elif merchant_match:
            candidate = merchant_match.group(1).strip()
            candidate = re.sub(r"^(vpa|info|mr\.|ms\.)\s+", "", candidate, flags=re.IGNORECASE).strip()
            merchant = candidate if len(candidate) >= 2 else "Unknown"
        else:
            merchant = "UPI Transaction"

        timestamp_id = int(datetime.utcnow().timestamp())
        try:
            return insert_financial_event(
                account_id=account_id,
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
