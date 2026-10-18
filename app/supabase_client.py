from __future__ import annotations

from typing import Any, Dict, List
import psycopg2
from psycopg2.extras import RealDictCursor

SUPABASE_DB_URI = (
    "postgresql://postgres.iigjhqbsloelcwvhknzy:Chetan%20197640"
    "@aws-0-ap-south-1.pooler.supabase.com:6543/postgres"
)

def get_db_connection():
    return psycopg2.connect(SUPABASE_DB_URI, cursor_factory=RealDictCursor)

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
        with conn.cursor() as cur:
            cur.execute(query, (limit,))
            records = cur.fetchall()
            return [dict(row) for row in records]
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
        with conn.cursor() as cur:
            cur.execute(query)
            records = cur.fetchall()
            return [dict(row) for row in records]
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
            return dict(inserted)
    finally:
        conn.close()
