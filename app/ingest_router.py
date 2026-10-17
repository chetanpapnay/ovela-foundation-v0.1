from __future__ import annotations

from datetime import datetime, timezone
import re
import uuid
from decimal import Decimal
from typing import Any, Optional

from fastapi import HTTPException
from pydantic import BaseModel, Field

from .ledger import AppendOnlyLedger, LedgerConflict
from .models import EventType, FinancialEvent


class OnlineWebhookPayload(BaseModel):
    message: str = Field(..., description="Raw SMS or notification string")
    source: str = Field(default="SMS_SYNC", description="Source identifier")
    reference_id: Optional[str] = None


class CashLogPayload(BaseModel):
    amount: Decimal = Field(..., gt=0, description="Amount in INR")
    category: str = Field(default="Cash / General", description="Expense category")
    notes: Optional[str] = None


def parse_indian_bank_sms(text: str) -> dict[str, Any]:
    cleaned = text.replace(",", "")
    amount = Decimal("0.00")

    # Match Rs, INR, or direct debit numbers like "debited by 100", "sent Rs 100", "paid INR 100"
    amt_match = re.search(r'(?:Rs\.?|INR|debited\s+by|paid|sent)\s*(?:Rs\.?|INR)?\s*([0-9]+(?:\.[0-9]{1,2})?)', cleaned, re.IGNORECASE)
    if amt_match:
        try:
            amount = Decimal(amt_match.group(1))
        except Exception:
            amount = Decimal("0.00")

    merchants = [
        "METRO", "AIRTEL", "DMRC", "NAVI", "SWIGGY", "ZOMATO", "UBER", 
        "OLA", "AMAZON", "FLIPKART", "BLINKIT", "ZEPTO", "BIGBASKET", "STARBUCKS"
    ]
    found_merchant = "Online / UPI Merchant"
    upper_text = text.upper()
    for m in merchants:
        if m in upper_text:
            found_merchant = m.title()
            break

    # Account mapping: prioritize Kotak Bank
    account = "KOTAK_BANK" if ("KOTAK" in upper_text or "NAVI" in upper_text) else "BANK_ACCOUNT"
    if "HDFC" in upper_text:
        account = "HDFC_BANK"
    elif "SBI" in upper_text:
        account = "SBI_BANK"
    elif "ICICI" in upper_text:
        account = "ICICI_BANK"
    elif "AXIS" in upper_text:
        account = "AXIS_BANK"

    return {
        "amount": amount,
        "merchant": found_merchant,
        "account_id": account,
    }


def register_ingest_endpoints(app_instance: Any, ledger: AppendOnlyLedger) -> None:
    @app_instance.post("/v1/transactions/webhook")
    def receive_online_transaction(payload: OnlineWebhookPayload) -> dict[str, Any]:
        parsed = parse_indian_bank_sms(payload.message)
        if parsed["amount"] <= Decimal("0.00"):
            raise HTTPException(status_code=400, detail="Could not parse valid INR amount.")

        source_event_id = payload.reference_id or f"sms_{uuid.uuid4().hex[:12]}"

        event = FinancialEvent(
            account_id=parsed["account_id"],
            source_id=payload.source,
            source_event_id=source_event_id,
            event_type=EventType.EXPENSE,
            amount=parsed["amount"],
            currency="INR",
            direction="DEBIT",
            event_date=datetime.now(timezone.utc),
        )

        try:
            ledger.append(event)
        except LedgerConflict as exc:
            raise HTTPException(status_code=409, detail=f"Duplicate transaction: {exc}")

        return {
            "status": "success",
            "type": "ONLINE_AUTOMATED",
            "amount": float(parsed["amount"]),
            "merchant": parsed["merchant"],
            "account": parsed["account_id"],
            "event_id": str(event.event_id),
        }

    @app_instance.post("/v1/transactions/cash")
    def receive_cash_transaction(payload: CashLogPayload) -> dict[str, Any]:
        source_event_id = f"cash_{uuid.uuid4().hex[:12]}"

        event = FinancialEvent(
            account_id="CASH_WALLET",
            source_id="VOICE_MANUAL",
            source_event_id=source_event_id,
            event_type=EventType.EXPENSE,
            direction="DEBIT",
            event_date=datetime.now(timezone.utc),
            amount=payload.amount,
            currency="INR",
        )

        try:
            ledger.append(event)
        except LedgerConflict as exc:
            raise HTTPException(status_code=409, detail=f"Duplicate transaction: {exc}")

        return {
            "status": "success",
            "type": "CASH_MANUAL",
            "amount": float(payload.amount),
            "category": payload.category,
            "account": "CASH_WALLET",
            "event_id": str(event.event_id),
        }

    @app_instance.get("/v1/ledger/summary")
    def get_ledger_summary() -> dict[str, Any]:
        all_events = ledger.all()
        total_expense = Decimal("0.00")
        cash_expense = Decimal("0.00")
        bank_expense = Decimal("0.00")

        for ev in all_events:
            if ev.event_type == EventType.EXPENSE:
                total_expense += ev.amount
                if ev.account_id == "CASH_WALLET":
                    cash_expense += ev.amount
                else:
                    bank_expense += ev.amount

        daily_cap = Decimal("4000.00")
        remaining = max(Decimal("0.00"), daily_cap - total_expense)

        return {
            "total_expense": float(total_expense),
            "cash_expense": float(cash_expense),
            "bank_expense": float(bank_expense),
            "daily_cap": float(daily_cap),
            "remaining_budget": float(remaining),
            "transaction_count": len(all_events),
        }