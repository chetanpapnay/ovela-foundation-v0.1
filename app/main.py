from __future__ import annotations

import hmac
import os
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse

from .ledger import AppendOnlyLedger, LedgerConflict
from .models import ActionRequest, FinancialEvent
from .security import authorize_action


APP_VERSION = "0.1.1"

_BASE_DIR = Path(__file__).resolve().parent.parent
_STATIC_INDEX = _BASE_DIR / "static" / "index.html"

app = FastAPI(
    title="Ovela Foundation",
    version=APP_VERSION,
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)

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
