"""
Server-side session storage.

A session record holds only a SHA-256 hash of the session secret, never the
secret itself. Stores implement atomic revoke/rotate so concurrent use of one
session token cannot produce two live sessions.

- InMemorySessionStore: process-local, for tests and local development.
- SqlServerSessionStore: shared across processes and restarts.

Any store failure raises SessionStoreError so callers fail closed.
"""

from __future__ import annotations

import dataclasses
import os
from abc import ABC, abstractmethod
from contextlib import closing
from dataclasses import dataclass, field
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Final
from uuid import UUID


ENV_VAR: Final[str] = "OVELA_SESSION_DB_CONNECTION"


class SessionError(Exception):
    """Base error for session handling."""


class SessionStoreError(SessionError):
    """Raised when a session store cannot give a reliable answer."""


@dataclass(frozen=True, slots=True)
class SessionRecord:
    """Server-side session state. The raw secret is never stored."""

    session_id: UUID
    subject_id: UUID
    secret_hash: bytes = field(repr=False)
    issued_at: datetime
    expires_at: datetime
    idle_expires_at: datetime
    last_seen_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, UUID):
            raise TypeError("session_id must be a UUID")

        if not isinstance(self.subject_id, UUID):
            raise TypeError("subject_id must be a UUID")

        if not isinstance(self.secret_hash, bytes) or len(self.secret_hash) != 32:
            raise TypeError("secret_hash must be a 32-byte SHA-256 digest")

        for name in (
            "issued_at",
            "expires_at",
            "idle_expires_at",
            "last_seen_at",
        ):
            value = getattr(self, name)

            if not isinstance(value, datetime) or value.tzinfo is None:
                raise TypeError(f"{name} must be a timezone-aware datetime")

        if self.revoked_at is not None and (
            not isinstance(self.revoked_at, datetime)
            or self.revoked_at.tzinfo is None
        ):
            raise TypeError("revoked_at must be a timezone-aware datetime or None")


class SessionStore(ABC):
    """Persistence boundary for session records."""

    @abstractmethod
    def insert(self, record: SessionRecord) -> None:
        """Insert a new record. Raise SessionStoreError on duplicate/failure."""

    @abstractmethod
    def get(self, session_id: UUID) -> SessionRecord | None:
        """Return the record, or None if it does not exist."""

    @abstractmethod
    def touch(
        self,
        session_id: UUID,
        last_seen_at: datetime,
        idle_expires_at: datetime,
    ) -> bool:
        """Update activity times of a non-revoked session. False if not updated."""

    @abstractmethod
    def revoke(self, session_id: UUID, revoked_at: datetime) -> bool:
        """Revoke a non-revoked session. True only if this call revoked it."""

    @abstractmethod
    def rotate(
        self,
        old_session_id: UUID,
        new_record: SessionRecord,
        now: datetime,
    ) -> bool:
        """
        Atomically revoke the old (non-revoked) session and insert the new one.
        Return False, changing nothing, if the old session was not live.
        """


class InMemorySessionStore(SessionStore):
    """Process-local store. Not shared between workers or restarts."""

    def __init__(self) -> None:
        self._records: dict[UUID, SessionRecord] = {}
        self._lock = RLock()

    def insert(self, record: SessionRecord) -> None:
        if not isinstance(record, SessionRecord):
            raise TypeError("record must be a SessionRecord")

        with self._lock:
            if record.session_id in self._records:
                raise SessionStoreError("session already exists")

            self._records[record.session_id] = record

    def get(self, session_id: UUID) -> SessionRecord | None:
        if not isinstance(session_id, UUID):
            raise TypeError("session_id must be a UUID")

        with self._lock:
            return self._records.get(session_id)

    def touch(
        self,
        session_id: UUID,
        last_seen_at: datetime,
        idle_expires_at: datetime,
    ) -> bool:
        with self._lock:
            record = self._records.get(session_id)

            if record is None or record.revoked_at is not None:
                return False

            self._records[session_id] = dataclasses.replace(
                record,
                last_seen_at=last_seen_at,
                idle_expires_at=idle_expires_at,
            )
            return True

    def revoke(self, session_id: UUID, revoked_at: datetime) -> bool:
        with self._lock:
            record = self._records.get(session_id)

            if record is None or record.revoked_at is not None:
                return False

            self._records[session_id] = dataclasses.replace(
                record,
                revoked_at=revoked_at,
            )
            return True

    def rotate(
        self,
        old_session_id: UUID,
        new_record: SessionRecord,
        now: datetime,
    ) -> bool:
        if not isinstance(new_record, SessionRecord):
            raise TypeError("new_record must be a SessionRecord")

        with self._lock:
            old = self._records.get(old_session_id)

            if old is None or old.revoked_at is not None:
                return False

            if new_record.session_id in self._records:
                raise SessionStoreError("session already exists")

            self._records[old_session_id] = dataclasses.replace(
                old,
                revoked_at=now,
            )
            self._records[new_record.session_id] = new_record
            return True


def _to_db(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _from_db(value: datetime | None) -> datetime | None:
    if value is None:
        return None

    return value.replace(tzinfo=timezone.utc)


class SqlServerSessionStore(SessionStore):
    """
    SQL Server store. Each call uses its own short-lived connection, so
    concurrent threads and processes never share connection state.
    """

    _INSERT_SQL = (
        "INSERT INTO dbo.Sessions "
        "(session_id, subject_id, secret_hash, issued_at, expires_at, "
        "idle_expires_at, last_seen_at, revoked_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )

    def __init__(self, connection_string: str) -> None:
        if not isinstance(connection_string, str) or not connection_string.strip():
            raise SessionStoreError("a SQL Server connection string is required")

        try:
            import pyodbc
        except ImportError as exc:
            raise SessionStoreError("pyodbc is not installed") from exc

        self._pyodbc: Any = pyodbc
        self._connection_string = connection_string

    def _connect(self):
        return self._pyodbc.connect(self._connection_string, timeout=5)

    @classmethod
    def _insert_row(cls, cursor, record: SessionRecord) -> None:
        cursor.execute(
            cls._INSERT_SQL,
            (
                str(record.session_id),
                str(record.subject_id),
                record.secret_hash,
                _to_db(record.issued_at),
                _to_db(record.expires_at),
                _to_db(record.idle_expires_at),
                _to_db(record.last_seen_at),
                None if record.revoked_at is None else _to_db(record.revoked_at),
            ),
        )

    @staticmethod
    def _fail(exc: Exception) -> SessionStoreError:
        return SessionStoreError(f"session store failure: {type(exc).__name__}")

    def create_schema(self) -> None:
        """Create the Sessions table if it does not exist."""
        try:
            with closing(self._connect()) as conn:
                conn.cursor().execute(
                    """
                    IF OBJECT_ID(N'dbo.Sessions', N'U') IS NULL
                    CREATE TABLE dbo.Sessions (
                        session_id UNIQUEIDENTIFIER NOT NULL
                            CONSTRAINT PK_Sessions PRIMARY KEY,
                        subject_id UNIQUEIDENTIFIER NOT NULL,
                        secret_hash BINARY(32) NOT NULL,
                        issued_at DATETIME2(3) NOT NULL,
                        expires_at DATETIME2(3) NOT NULL,
                        idle_expires_at DATETIME2(3) NOT NULL,
                        last_seen_at DATETIME2(3) NOT NULL,
                        revoked_at DATETIME2(3) NULL
                    )
                    """
                )
                conn.commit()
        except Exception as exc:
            raise self._fail(exc) from exc

    def insert(self, record: SessionRecord) -> None:
        if not isinstance(record, SessionRecord):
            raise TypeError("record must be a SessionRecord")

        try:
            with closing(self._connect()) as conn:
                self._insert_row(conn.cursor(), record)
                conn.commit()
        except Exception as exc:
            raise self._fail(exc) from exc

    def get(self, session_id: UUID) -> SessionRecord | None:
        if not isinstance(session_id, UUID):
            raise TypeError("session_id must be a UUID")

        try:
            with closing(self._connect()) as conn:
                row = (
                    conn.cursor()
                    .execute(
                        "SELECT session_id, subject_id, secret_hash, issued_at, "
                        "expires_at, idle_expires_at, last_seen_at, revoked_at "
                        "FROM dbo.Sessions WHERE session_id = ?",
                        (str(session_id),),
                    )
                    .fetchone()
                )

                if row is None:
                    return None

                return SessionRecord(
                    session_id=UUID(str(row[0])),
                    subject_id=UUID(str(row[1])),
                    secret_hash=bytes(row[2]),
                    issued_at=_from_db(row[3]),
                    expires_at=_from_db(row[4]),
                    idle_expires_at=_from_db(row[5]),
                    last_seen_at=_from_db(row[6]),
                    revoked_at=_from_db(row[7]),
                )
        except Exception as exc:
            raise self._fail(exc) from exc

    def touch(
        self,
        session_id: UUID,
        last_seen_at: datetime,
        idle_expires_at: datetime,
    ) -> bool:
        try:
            with closing(self._connect()) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE dbo.Sessions SET last_seen_at = ?, idle_expires_at = ? "
                    "WHERE session_id = ? AND revoked_at IS NULL",
                    (
                        _to_db(last_seen_at),
                        _to_db(idle_expires_at),
                        str(session_id),
                    ),
                )
                updated = cursor.rowcount == 1
                conn.commit()
                return updated
        except Exception as exc:
            raise self._fail(exc) from exc

    def revoke(self, session_id: UUID, revoked_at: datetime) -> bool:
        try:
            with closing(self._connect()) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE dbo.Sessions SET revoked_at = ? "
                    "WHERE session_id = ? AND revoked_at IS NULL",
                    (_to_db(revoked_at), str(session_id)),
                )
                updated = cursor.rowcount == 1
                conn.commit()
                return updated
        except Exception as exc:
            raise self._fail(exc) from exc

    def rotate(
        self,
        old_session_id: UUID,
        new_record: SessionRecord,
        now: datetime,
    ) -> bool:
        if not isinstance(new_record, SessionRecord):
            raise TypeError("new_record must be a SessionRecord")

        try:
            with closing(self._connect()) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE dbo.Sessions SET revoked_at = ? "
                    "WHERE session_id = ? AND revoked_at IS NULL",
                    (_to_db(now), str(old_session_id)),
                )

                if cursor.rowcount != 1:
                    conn.rollback()
                    return False

                self._insert_row(cursor, new_record)
                conn.commit()
                return True
        except Exception as exc:
            raise self._fail(exc) from exc


def session_store_from_environment() -> SessionStore | None:
    """
    Return a SQL Server store when OVELA_SESSION_DB_CONNECTION is set,
    otherwise None.
    """
    connection_string = os.environ.get(ENV_VAR, "").strip()

    if not connection_string:
        return None

    return SqlServerSessionStore(connection_string)