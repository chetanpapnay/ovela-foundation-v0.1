from __future__ import annotations

import os
from decimal import Decimal
from typing import Any, Dict, List
import psycopg2
from psycopg2.extras import RealDictCursor

# Database configuration for Jurix-ledger
DB_HOST = os.getenv("SUPABASE_DB_HOST", "aws-0-ap-southeast-1.pooler.supabase.com")
DB_PORT = int(os.getenv("SUPABASE_DB_PORT", "6543"))
DB_NAME = os.getenv("SUPABASE_DB_NAME", "postgres")
DB_USER = os.getenv("SUPABASE_DB_USER", "postgres.gjtsivfbrqlyltmjejrt")
DB_PASSWORD = os.getenv("SUPABASE_DB_PASSWORD", "JurixLedger2026!")


def get_db_connection():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        sslmode="require",
        cursor_factory=RealDictCursor,
    )


def _serialize_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert non-JSON-serializable types like Decimal and Datetime to standard Python types."""
    clean = {}
    for key, value in row.items():
        if isinstance(value, Decimal):
            clean[key] = float(value)
        elif hasattr(value, "isoformat"):
            clean[key] = value.isoformat()
        else:
            clean[key] = value
    return clean


def ensure_table_exists(conn) -> None:
    """Ensure the financial_events table exists before querying."""
    create_table_sql = """
        CREATE TABLE IF NOT EXISTS financial_events (
            event_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            account_id TEXT NOT NULL,
            source_id TEXT,
            source_event_id TEXT,
            event_type TEXT NOT NULL,
            amount NUMERIC(12, 2) NOT NULL,
            currency TEXT DEFAULT 'INR',
            direction TEXT NOT NULL,
            merchant TEXT DEFAULT 'Unknown',
            note TEXT,
            event_date TIMESTAMPTZ DEFAULT NOW(),
            recorded_at TIMESTAMPTZ DEFAULT NOW(),
            evidence_status TEXT DEFAULT 'UNVERIFIED'
        );
    """
    with conn.cursor() as cur:
        cur.execute(create_table_sql)
    conn.commit()


def fetch_recent_transactions(limit: int = 50) -> List[Dict[str, Any]]:
    query = """
        SELECT
            event_id,
            account_id,
            source_id,
            source_event_id,
            event_type,
            amount,
            currency,
            direction,
            merchant,
            note,
            event_date,
            recorded_at
        FROM financial_events
        ORDER BY event_date DESC
        LIMIT %s;
    """
    conn = get_db_connection()
    try:
        ensure_table_exists(conn)
        with conn.cursor() as cur:
            cur.execute(query, (limit,))
            records = cur.fetchall()
            return [_serialize_row(dict(row)) for row in records]
    finally:
        conn.close()


def fetch_account_summary() -> List[Dict[str, Any]]:
    query = """
        SELECT
            account_id,
            COUNT(*) AS total_transactions,
            COALESCE(SUM(CASE WHEN direction = 'CREDIT' THEN amount ELSE 0 END), 0) AS total_income,
            COALESCE(SUM(CASE WHEN direction = 'DEBIT' THEN amount ELSE 0 END), 0) AS total_expenses
        FROM financial_events
        GROUP BY account_id;
    """
    conn = get_db_connection()
    try:
        ensure_table_exists(conn)
        with conn.cursor() as cur:
            cur.execute(query)
            records = cur.fetchall()
            return [_serialize_row(dict(row)) for row in records]
    finally:
        conn.close()


def insert_financial_event(
    account_id: str,
    source_id: str,
    source_event_id: str,
    event_type: str,
    amount: float,
    currency: str,
    direction: str,
    merchant: str = "Unknown",
    note: str = ""
) -> Dict[str, Any]:
    insert_sql = """
        INSERT INTO financial_events (
            event_id,
            account_id,
            source_id,
            source_event_id,
            event_type,
            amount,
            currency,
            direction,
            merchant,
            note,
            event_date,
            recorded_at,
            evidence_status
        ) VALUES (
            gen_random_uuid(),
            %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW(), 'UNVERIFIED'
        )
        RETURNING event_id, account_id, amount, direction, merchant;
    """
    conn = get_db_connection()
    try:
        ensure_table_exists(conn)
        with conn.cursor() as cur:
            cur.execute(insert_sql, (
                account_id,
                source_id,
                source_event_id,
                event_type,
                amount,
                currency,
                direction,
                merchant,
                note
            ))
            inserted = cur.fetchone()
            conn.commit()
            return _serialize_row(dict(inserted)) if inserted else {}
    finally:
        conn.close()