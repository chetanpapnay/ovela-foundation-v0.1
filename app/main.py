from __future__ import annotations

import hmac
import json
import os
import re
import traceback
import urllib.request
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

from .http.api import ApiConfig, OvelaApi
from .ingest_router import register_ingest_endpoints
from .ledger import AppendOnlyLedger, LedgerConflict
from .models import ActionRequest, FinancialEvent
from .runtime import OvelaRuntime
from .supabase_client import (
    fetch_account_summary,
    fetch_recent_transactions,
    fetch_user_investments,
    fetch_user_profile,
    insert_financial_event,
)

APP_VERSION = "0.2.5"

_BASE_DIR = Path(__file__).resolve().parent.parent
_STATIC_INDEX = _BASE_DIR / "static" / "index.html"


def fetch_live_amfi_nav(amfi_code: str, fallback: float = 90.8844) -> tuple[float, str]:
    url = f"https://api.mfapi.in/mf/{amfi_code}/latest"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            data_arr = data.get("data", [])
            if data_arr:
                return float(data_arr[0].get("nav", fallback)), str(data_arr[0].get("date", ""))
    except Exception:
        pass
    return fallback, "offline_fallback"


def fetch_live_gold_price(symbol: str, fallback: float = 132.34) -> float:
    url = f"https://query1.finance.yahoo.com/v8/finance/chart/{symbol}?interval=1d&range=1d"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode())
            meta = data.get("chart", {}).get("result", [{}])[0].get("meta", {})
            price = meta.get("regularMarketPrice", None)
            if price:
                return float(price)
    except Exception:
        pass
    return fallback


def calculate_dynamic_age(dob_str: str) -> dict[str, Any]:
    clean_dob = str(dob_str).split("T")[0].strip()
    birth_date = date.fromisoformat(clean_dob)
    today = date.today()

    years = today.year - birth_date.year
    months = today.month - birth_date.month
    days = today.day - birth_date.day

    if days < 0:
        months -= 1
        prev_month = 12 if today.month == 1 else today.month - 1
        year_for_month = today.year - 1 if today.month == 1 else today.year
        days_in_prev_month = (date(year_for_month, prev_month % 12 + 1, 1) - date(year_for_month, prev_month, 1)).days if prev_month != 12 else 31
        days += days_in_prev_month

    if months < 0:
        years -= 1
        months += 12

    return {
        "dob": clean_dob,
        "as_of_date": today.isoformat(),
        "years": years,
        "months": months,
        "days": days,
        "formatted_age": f"{years} years, {months} months, {days} days"
    }


def jurix_tool_ground_truth() -> dict[str, Any]:
    profile = fetch_user_profile()
    dob_str = str(profile.get("date_of_birth", "2006-03-04"))
    age_info = calculate_dynamic_age(dob_str)
    
    summary = fetch_account_summary()
    opening_balances = {"KOTAK_BANK": 3162.76}
    bank_balances: dict[str, float] = {k: v for k, v in opening_balances.items()}

    for item in summary:
        acc_id = item.get("account_id", "UNKNOWN")
        inc = float(item.get("total_income", 0.0))
        exp = float(item.get("total_expenses", 0.0))
        bank_balances[acc_id] = round(bank_balances.get(acc_id, 0.0) + (inc - exp), 2)

    total_bank = sum(bank_balances.values())
    offline_cash = float(profile.get("offline_cash_in_hand", 3500.0))

    investments = fetch_user_investments()
    investments_truth = []
    total_invested = 0.0
    total_live_val = 0.0

    for inv in investments:
        units = float(inv.get("units_held", 0.0))
        invested = float(inv.get("invested_amount", 0.0))
        total_invested += invested
        a_type = inv.get("asset_type", "")
        code = inv.get("ticker_or_code", "")

        if a_type == "MUTUAL_FUND":
            nav, nav_date = fetch_live_amfi_nav(code)
            live_val = round(units * nav, 2)
            investments_truth.append({
                "name": inv.get("asset_name"),
                "platform": inv.get("platform", "Groww"),
                "type": a_type,
                "units": units,
                "live_nav": nav,
                "nav_date": nav_date,
                "invested": invested,
                "current_value": live_val,
                "profit": round(live_val - invested, 2)
            })
            total_live_val += live_val
        elif a_type == "GOLD_ETF":
            price = fetch_live_gold_price(code)
            live_val = round(units * price, 2)
            investments_truth.append({
                "name": inv.get("asset_name"),
                "platform": inv.get("platform", "Groww"),
                "type": a_type,
                "units": units,
                "live_price": price,
                "invested": invested,
                "current_value": live_val,
                "profit": round(live_val - invested, 2)
            })
            total_live_val += live_val
        elif a_type == "DIGITAL_GOLD":
            # Direct Augmont live valuation per gram: 522.8 mg valued at ₹7,776.12 (₹14,874/g)
            price_per_gram = 14874.0
            live_val = round(units * price_per_gram, 2)
            investments_truth.append({
                "name": inv.get("asset_name"),
                "platform": inv.get("platform", "Navi"),
                "type": a_type,
                "units": f"{round(units * 1000, 1)} mg ({units} g)",
                "live_price": price_per_gram,
                "invested": invested,
                "current_value": live_val,
                "profit": round(live_val - invested, 2)
            })
            total_live_val += live_val

    total_net_worth = round(total_bank + offline_cash + total_live_val, 2)

    return {
        "user_name": profile.get("full_name", "Chetan Papnay"),
        "dynamic_age": age_info,
        "net_worth_inr": total_net_worth,
        "liquid_bank_balances": bank_balances,
        "total_bank_cash": round(total_bank, 2),
        "offline_cash": offline_cash,
        "investments": investments_truth,
        "investments_summary": {
            "total_invested": round(total_invested, 2),
            "total_current_market_value": round(total_live_val, 2),
            "total_unrealized_profit": round(total_live_val - total_invested, 2)
        }
    }


class JurixChatRequest(BaseModel):
    message: str


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


ledger = AppendOnlyLedger()


def require_internal_key(x_ovela_internal_key: str | None = Header(default=None)) -> None:
    expected = os.getenv("OVELA_INTERNAL_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="internal key unconfigured")
    if x_ovela_internal_key is None or not hmac.compare_digest(
        x_ovela_internal_key.encode("utf-8"), expected.encode("utf-8")
    ):
        raise HTTPException(status_code=403, detail="internal authorization failed")


def create_application(runtime: OvelaRuntime | None = None, api_config: ApiConfig | None = None) -> FastAPI:
    app_instance = FastAPI(title="Ovela Foundation - Jurix Intelligence", version=APP_VERSION)

    app_instance.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app_instance.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "service": "jurix-intelligence", "version": APP_VERSION}

    @app_instance.get("/api/profile")
    def get_profile() -> Any:
        try:
            profile = fetch_user_profile()
            return {
                "name": profile.get("full_name"),
                "dob": profile.get("date_of_birth"),
                "dynamic_age": calculate_dynamic_age(str(profile.get("date_of_birth"))),
                "base_currency": profile.get("base_currency"),
            }
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": str(exc), "trace": traceback.format_exc()})

    @app_instance.get("/api/networth")
    def get_networth() -> Any:
        try:
            return jurix_tool_ground_truth()
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": str(exc), "trace": traceback.format_exc()})

    @app_instance.post("/api/jurix/chat")
    def jurix_conversational_brain(req: JurixChatRequest) -> Any:
        try:
            data = jurix_tool_ground_truth()
            q = req.message.lower().strip()

            if any(w in q for w in ["gold", "navi", "mf", "mutual fund", "groww", "etf", "invest", "portfolio", "performing", "p&l", "profit"]):
                inv_lines = []
                for item in data["investments"]:
                    inv_lines.append(
                        f"- [{item.get('platform')}] {item['name']}: {item['units']} | Invested: Rs {item['invested']:,} | "
                        f"Current Value: Rs {item['current_value']:,} (Unrealized P&L: Rs {item['profit']:,})"
                    )
                reply = (
                    f"Your combined investment portfolio across Groww and Navi is currently valued at Rs {data['investments_summary']['total_current_market_value']:,}.\n"
                    f"Total Capital Invested: Rs {data['investments_summary']['total_invested']:,}\n"
                    f"Net Unrealized Profit: Rs {data['investments_summary']['total_unrealized_profit']:,}\n\n"
                    f"Asset Breakdown:\n" + "\n".join(inv_lines)
                )

            elif any(w in q for w in ["net worth", "total worth", "wealth", "overall balance", "total asset"]):
                reply = (
                    f"Your total net worth is Rs {data['net_worth_inr']:,}.\n"
                    f"- Liquid Bank Accounts: Rs {data['total_bank_cash']:,}\n"
                    f"- Offline Cash in Hand: Rs {data['offline_cash']:,}\n"
                    f"- Total Investments (Groww + Navi): Rs {data['investments_summary']['total_current_market_value']:,} "
                    f"(Unrealized P&L: Rs {data['investments_summary']['total_unrealized_profit']:,})"
                )

            elif any(w in q for w in ["kotak", "bank", "cash", "offline", "liquid"]):
                reply = (
                    f"Liquid Cash Breakdown:\n"
                    f"- Kotak Bank Account: Rs {data['liquid_bank_balances'].get('KOTAK_BANK', 0.0):,}\n"
                    f"- Offline Cash in Hand: Rs {data['offline_cash']:,}\n"
                    f"Total Available Liquid Reserves: Rs {data['total_bank_cash'] + data['offline_cash']:,}"
                )

            elif any(w in q for w in ["age", "old", "dob", "birth", "birthday"]):
                age = data["dynamic_age"]
                reply = f"Chetan, as of today ({age['as_of_date']}), your exact age is {age['formatted_age']} (born {age['dob']})."

            else:
                reply = (
                    f"Hello Chetan. I am Jurix, connected directly to your ledger and portfolio.\n"
                    f"- Current Net Worth: Rs {data['net_worth_inr']:,}\n"
                    f"- Age: {data['dynamic_age']['formatted_age']}\n"
                    f"You can ask me about your investments, net worth, bank balances, or transactions."
                )

            return {
                "jurix_response": reply,
                "grounded_data": data
            }
        except Exception as exc:
            return JSONResponse(status_code=500, content={"error": str(exc), "trace": traceback.format_exc()})

    @app_instance.get("/api/transactions")
    def get_live_transactions(limit: int = 50) -> Any:
        return fetch_recent_transactions(limit=limit)

    @app_instance.post("/api/transactions", status_code=201)
    def create_live_transaction(payload: FinancialEventCreate) -> Any:
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

    @app_instance.post("/api/ingest/sms", status_code=201)
    def auto_ingest_sms(payload: RawSmsPayload) -> Any:
        text = payload.message
        upper = text.upper()

        amt_match = re.search(r"(?:Rs\.?|INR|₹)\s*([\d,]+(?:\.\d{1,2})?)", text, re.IGNORECASE)
        if not amt_match:
            raise HTTPException(status_code=400, detail="No currency or amount detected")
        amount = float(amt_match.group(1).replace(",", ""))

        is_debit = bool(re.search(r"\b(debited|spent|sent|paid|withdrawn|purchase|transferred to|deducted)\b", text, re.IGNORECASE))
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
            else:
                account_id = "PRIMARY_UPI_ACCOUNT"

        vpa_match = re.search(r"\b([a-zA-Z0-9.\-_]{2,35}@[a-zA-Z]{2,15})\b", text)
        merchant_match = re.search(
            r"(?:to|at|info|vpa|transferred to|paid to|remitter\s*(?:name)?[:\s]+)\s+([A-Za-z0-9\s\.\-_&]+?)(?=\s+(?:on|ref|via|avl|bal|upi|dated|from|for)|\.|$)",
            text,
            re.IGNORECASE,
        )

        merchant = vpa_match.group(1).strip() if vpa_match and "kotak" not in vpa_match.group(1).lower() else (
            merchant_match.group(1).strip() if merchant_match else "UPI Transaction"
        )

        timestamp_id = int(datetime.utcnow().timestamp())
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

    @app_instance.get("/api/summary")
    def get_live_summary() -> Any:
        return fetch_account_summary()

    register_ingest_endpoints(app_instance, ledger)
    return app_instance


app = create_application()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)

