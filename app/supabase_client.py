from __future__ import annotations

import os
from typing import Any
from supabase import create_client, Client

_SUPABASE_URL = os.getenv("SUPABASE_URL", "")
_SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY", "")

_client: Client | None = None


def get_client() -> Client:
    global _client
    if _client is None:
        if not _SUPABASE_URL or not _SUPABASE_KEY:
            raise RuntimeError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be configured")
        _client = create_client(_SUPABASE_URL, _SUPABASE_KEY)
    return _client


def insert_financial_event(
    account_id: str,
    source_id: str,
    source_event_id: str,
    event_type: str,
    amount: float,
    currency: str = "INR",
    direction: str = "DEBIT",
    merchant: str = "Unknown",
    note: str = "",
) -> dict[str, Any]:
    client = get_client()
    payload = {
        "account_id": account_id,
        "source_id": source_id,
        "source_event_id": source_event_id,
        "event_type": event_type,
        "amount": amount,
        "currency": currency,
        "direction": direction,
        "merchant": merchant,
        "note": note,
    }
    response = client.table("financial_events").insert(payload).execute()
    if not response.data:
        raise RuntimeError("Failed to insert financial event into Supabase")
    return response.data[0]


def fetch_recent_transactions(limit: int = 50) -> list[dict[str, Any]]:
    client = get_client()
    response = (
        client.table("financial_events")
        .select("*")
        .order("recorded_at", desc=True)
        .limit(limit)
        .execute()
    )
    return response.data or []


def fetch_account_summary() -> list[dict[str, Any]]:
    client = get_client()
    response = client.rpc("get_account_summary").execute()
    return response.data or []


def fetch_user_profile() -> dict[str, Any]:
    """Fetches user profile dynamically from user_profiles table."""
    client = get_client()
    response = client.table("user_profiles").select("*").eq("user_id", "primary_user").limit(1).execute()
    if response.data:
        return response.data[0]
    return {
        "full_name": "Chetan Papnay",
        "date_of_birth": "2006-03-04",
        "base_currency": "INR",
        "offline_cash_in_hand": 3500.0
    }


def fetch_user_investments() -> list[dict[str, Any]]:
    """Fetches real-time portfolio holdings directly from user_investments table."""
    client = get_client()
    response = client.table("user_investments").select("*").execute()
    return response.data or []
