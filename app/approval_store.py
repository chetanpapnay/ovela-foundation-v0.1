"""
Single-use consumption stores for trusted approval evidence.

A store answers one question atomically: "is this the first time this
approval ID has been consumed?"

- InMemoryApprovalConsumptionStore: process-local (default behavior).
- SqlServerApprovalConsumptionStore: shared across processes and restarts.
  A PRIMARY KEY on approval_id makes the insert atomic; a duplicate-key
  error means the approval was already consumed.

Any store failure raises ApprovalStoreError so callers fail closed.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from contextlib import closing
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Final
from uuid import UUID


ENV_VAR: Final[str] = "OVELA_APPROVAL_DB_CONNECTION"


class ApprovalStoreError(Exception):
    """Raised when a consumption store cannot give a reliable answer."""


class ApprovalConsumptionStore(ABC):
    """Atomic first-use tracking for approval IDs."""

    @abstractmethod
    def try_consume(self, approval_id: UUID, expires_at: datetime) -> bool:
        """Return True only for the first consumption of approval_id."""

    @abstractmethod
    def is_consumed(self, approval_id: UUID) -> bool:
        """Return whether approval_id has been consumed."""


class InMemoryApprovalConsumptionStore(ApprovalConsumptionStore):
    """Process-local store. Not shared between workers or restarts."""

    def __init__(self) -> None:
        self._consumed: set[UUID] = set()
        self._lock = RLock()

    def try_consume(self, approval_id: UUID, expires_at: datetime) -> bool:
        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        with self._lock:
            if approval_id in self._consumed:
                return False

            self._consumed.add(approval_id)
            return True

    def is_consumed(self, approval_id: UUID) -> bool:
        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        with self._lock:
            return approval_id in self._consumed


class SqlServerApprovalConsumptionStore(ApprovalConsumptionStore):
    """
    SQL Server store. Each call uses its own short-lived connection, so
    concurrent threads and processes never share connection state.
    """

    def __init__(self, connection_string: str) -> None:
        if not isinstance(connection_string, str) or not connection_string.strip():
            raise ApprovalStoreError("a SQL Server connection string is required")

        try:
            import pyodbc
        except ImportError as exc:
            raise ApprovalStoreError("pyodbc is not installed") from exc

        self._pyodbc: Any = pyodbc
        self._connection_string = connection_string

    def _connect(self):
        return self._pyodbc.connect(self._connection_string, timeout=5)

    def create_schema(self) -> None:
        """Create the ConsumedApprovals table if it does not exist."""
        try:
            with closing(self._connect()) as conn:
                conn.cursor().execute(
                    """
                    IF OBJECT_ID(N'dbo.ConsumedApprovals', N'U') IS NULL
                    CREATE TABLE dbo.ConsumedApprovals (
                        approval_id UNIQUEIDENTIFIER NOT NULL
                            CONSTRAINT PK_ConsumedApprovals PRIMARY KEY,
                        consumed_at DATETIME2(3) NOT NULL,
                        expires_at DATETIME2(3) NOT NULL
                    )
                    """
                )
                conn.commit()
        except Exception as exc:
            raise ApprovalStoreError(
                f"could not create approval store schema: {type(exc).__name__}"
            ) from exc

    def try_consume(self, approval_id: UUID, expires_at: datetime) -> bool:
        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        if not isinstance(expires_at, datetime) or expires_at.tzinfo is None:
            raise TypeError("expires_at must be a timezone-aware datetime")

        expires_naive_utc = expires_at.astimezone(timezone.utc).replace(
            tzinfo=None
        )

        try:
            with closing(self._connect()) as conn:
                cursor = conn.cursor()

                try:
                    cursor.execute(
                        "INSERT INTO dbo.ConsumedApprovals "
                        "(approval_id, consumed_at, expires_at) "
                        "VALUES (?, SYSUTCDATETIME(), ?)",
                        (str(approval_id), expires_naive_utc),
                    )
                    conn.commit()
                    return True
                except self._pyodbc.IntegrityError:
                    # Primary key violation: already consumed.
                    conn.rollback()
                    return False
        except Exception as exc:
            raise ApprovalStoreError(
                f"approval store failure: {type(exc).__name__}"
            ) from exc

    def is_consumed(self, approval_id: UUID) -> bool:
        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        try:
            with closing(self._connect()) as conn:
                row = (
                    conn.cursor()
                    .execute(
                        "SELECT 1 FROM dbo.ConsumedApprovals "
                        "WHERE approval_id = ?",
                        (str(approval_id),),
                    )
                    .fetchone()
                )
                return row is not None
        except Exception as exc:
            raise ApprovalStoreError(
                f"approval store failure: {type(exc).__name__}"
            ) from exc


def store_from_environment() -> ApprovalConsumptionStore | None:
    """
    Return a SQL Server store when OVELA_APPROVAL_DB_CONNECTION is set,
    otherwise None (callers then use in-memory consumption only).
    """
    connection_string = os.environ.get(ENV_VAR, "").strip()

    if not connection_string:
        return None

    return SqlServerApprovalConsumptionStore(connection_string)