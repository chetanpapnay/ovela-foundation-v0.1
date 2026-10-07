"""
Durable, tenant-scoped approval store with atomic single-use consumption.

``DurableApprovalStore`` persists approval evidence in a relational table and
consumes it with ONE conditional UPDATE statement. The database, not Python,
decides the winner, so exactly one consumer succeeds across threads,
processes, workers and restarts:

    UPDATE approval_evidence
    SET consumed_at = :now, consumed_by = :executor_id, version = version + 1
    WHERE approval_id = :approval_id
      AND tenant_id = :tenant_id
      AND consumed_at IS NULL
      AND expires_at > :now;

``rowcount == 1`` means this call consumed the approval; ``rowcount == 0``
means it did not (unknown, wrong tenant, already consumed, or expired).
Any other rowcount is treated as a store failure and rolled back.

Security invariants
-------------------
- No implicit tenant: ``evidence.tenant_id is None`` or ``tenant_id is None``
  is rejected before any database work. There is no system-tenant fallback.
- The evidence tenant must equal the consuming tenant.
- Only trusted, unexpired, not-future-dated evidence is registered/consumed.
- Isolation is READ COMMITTED. The single-statement UPDATE is atomic at that
  level, so no stronger isolation is required for correctness.
- Every driver or connection failure raises ``ApprovalStoreError`` (fail
  closed). Driver messages are not propagated, only the exception type name.

Connections
-----------
Provide a DB-API 2.0 connection, or a zero-argument factory returning one.

- A factory is called once per operation and the connection is closed
  afterwards. Preferred for multi-threaded use.
- A single connection is shared and serialized with a lock, because DB-API
  connections are generally not safe for concurrent use. The lock is
  process-local; cross-process atomicity comes from the UPDATE itself.

SQLAlchemy sessions are not DB-API connections. Pass
``engine.raw_connection`` as the factory instead.

Parameter styles
----------------
The canonical SQL uses ``:name`` placeholders. ``paramstyle="named"`` passes
them through (sqlite3, oracledb). ``paramstyle="qmark"`` (default) rewrites
them to ``?`` with ordered parameters (pyodbc, SQL Server).
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import datetime, timezone
from typing import Any, Final, Literal, Protocol, TypeVar
from uuid import UUID

from .approval_evidence import (
    ApprovalEvidence,
    ApprovalEvidenceInvalid,
    ApprovalStore,
)
from .approval_store import ApprovalStoreError


T = TypeVar("T")

ParamStyle = Literal["named", "qmark"]

DEFAULT_ISOLATION_STATEMENT: Final[str] = (
    "SET TRANSACTION ISOLATION LEVEL READ COMMITTED"
)

CONSUME_SQL: Final[str] = """
UPDATE approval_evidence
SET consumed_at = :now, consumed_by = :executor_id, version = version + 1
WHERE approval_id = :approval_id
  AND tenant_id = :tenant_id
  AND consumed_at IS NULL
  AND expires_at > :now
"""

REGISTER_SQL: Final[str] = """
INSERT INTO approval_evidence (
    approval_id, tenant_id, action_id, session_id, subject_id,
    destination_id, amount, currency, approved_at, expires_at,
    consumed_at, consumed_by, version
)
SELECT
    :approval_id, :tenant_id, :action_id, :session_id, :subject_id,
    :destination_id, :amount, :currency, :approved_at, :expires_at,
    NULL, NULL, 0
WHERE NOT EXISTS (
    SELECT 1 FROM approval_evidence WHERE approval_id = :approval_id
)
"""

IS_CONSUMED_SQL: Final[str] = """
SELECT consumed_at FROM approval_evidence WHERE approval_id = :approval_id
"""

SQL_SERVER_SCHEMA: Final[str] = """
IF OBJECT_ID(N'dbo.approval_evidence', N'U') IS NULL
CREATE TABLE dbo.approval_evidence (
    approval_id    UNIQUEIDENTIFIER NOT NULL
        CONSTRAINT PK_approval_evidence PRIMARY KEY,
    tenant_id      UNIQUEIDENTIFIER NOT NULL,
    action_id      UNIQUEIDENTIFIER NOT NULL,
    session_id     UNIQUEIDENTIFIER NOT NULL,
    subject_id     UNIQUEIDENTIFIER NOT NULL,
    destination_id NVARCHAR(256)    NOT NULL,
    amount         DECIMAL(38, 10)  NOT NULL,
    currency       CHAR(3)          NOT NULL,
    approved_at    DATETIME2(6)     NOT NULL,
    expires_at     DATETIME2(6)     NOT NULL,
    consumed_at    DATETIME2(6)     NULL,
    consumed_by    UNIQUEIDENTIFIER NULL,
    version        INT              NOT NULL
        CONSTRAINT DF_approval_evidence_version DEFAULT 0
)
"""

_PLACEHOLDER: Final[re.Pattern[str]] = re.compile(r":([A-Za-z_][A-Za-z0-9_]*)")


class DatabaseCursor(Protocol):
    """Subset of the DB-API 2.0 cursor interface used by the store."""

    rowcount: int

    def execute(self, operation: str, parameters: Any = ..., /) -> Any: ...

    def fetchone(self) -> Any: ...

    def close(self) -> Any: ...


class DatabaseConnection(Protocol):
    """Subset of the DB-API 2.0 connection interface used by the store."""

    def cursor(self) -> DatabaseCursor: ...

    def commit(self) -> None: ...

    def rollback(self) -> None: ...

    def close(self) -> None: ...


ConnectionSource = DatabaseConnection | Callable[[], DatabaseConnection]


def _to_db(value: datetime) -> datetime:
    """Convert an aware datetime to naive UTC, the stored representation."""
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def _render(
    sql: str,
    parameters: Mapping[str, Any],
    paramstyle: ParamStyle,
) -> tuple[str, Mapping[str, Any] | tuple[Any, ...]]:
    """
    Render canonical ``:name`` SQL for the configured parameter style.

    For ``qmark`` each placeholder becomes ``?`` and parameters are ordered
    by first appearance, so a placeholder used twice is bound twice.
    """
    if paramstyle == "named":
        return sql, dict(parameters)

    names = _PLACEHOLDER.findall(sql)
    ordered = tuple(parameters[name] for name in names)

    return _PLACEHOLDER.sub("?", sql), ordered


def _validate_isolation_statement(statement: str | None) -> str | None:
    """
    Allow only a READ COMMITTED statement (or None to rely on the engine
    default). Prevents accidental weakening to READ UNCOMMITTED or chained
    statements through configuration.
    """
    if statement is None:
        return None

    if not isinstance(statement, str):
        raise TypeError("isolation_statement must be a string or None")

    normalized = " ".join(statement.upper().split())

    if ";" in normalized or not normalized.endswith("READ COMMITTED"):
        raise ValueError(
            "isolation_statement must set READ COMMITTED and nothing else"
        )

    return statement.strip()


class DurableApprovalStore(ApprovalStore):
    """
    Tenant-scoped, durable ``ApprovalStore`` backed by a SQL table.

    Thread-safe. Atomic across processes through a single-statement UPDATE
    under READ COMMITTED. Fail-closed on every error path.
    """

    __slots__ = (
        "_connection",
        "_factory",
        "_isolation_statement",
        "_lock",
        "_paramstyle",
    )

    def __init__(
        self,
        connection: ConnectionSource,
        *,
        paramstyle: ParamStyle = "qmark",
        isolation_statement: str | None = DEFAULT_ISOLATION_STATEMENT,
    ) -> None:
        if paramstyle not in ("named", "qmark"):
            raise ValueError("paramstyle must be 'named' or 'qmark'")

        if hasattr(connection, "cursor"):
            self._connection: DatabaseConnection | None = connection  # type: ignore[assignment]
            self._factory: Callable[[], DatabaseConnection] | None = None
        elif callable(connection):
            self._connection = None
            self._factory = connection
        else:
            raise TypeError(
                "connection must be a DB-API connection or a connection factory"
            )

        self._paramstyle: ParamStyle = paramstyle
        self._isolation_statement = _validate_isolation_statement(
            isolation_statement
        )
        self._lock = threading.RLock()

    # -- ApprovalStore ---------------------------------------------------

    def register(self, evidence: ApprovalEvidence) -> None:
        """
        Persist trusted, tenant-bound evidence.

        Raises ApprovalEvidenceInvalid for untrusted evidence, missing
        tenant, or an already-registered approval. Store failures raise
        ApprovalStoreError.
        """
        if not isinstance(evidence, ApprovalEvidence):
            raise ApprovalEvidenceInvalid(
                "approval evidence is missing or invalid"
            )

        if evidence.tenant_id is None:
            raise ApprovalEvidenceInvalid(
                "durable approval store requires tenant-bound evidence"
            )

        evidence.require_trusted()

        parameters: dict[str, Any] = {
            "approval_id": str(evidence.approval_id),
            "tenant_id": str(evidence.tenant_id),
            "action_id": str(evidence.action_id),
            "session_id": str(evidence.session_id),
            "subject_id": str(evidence.subject_id),
            "destination_id": evidence.destination_id,
            "amount": evidence.amount,
            "currency": evidence.currency,
            "approved_at": _to_db(evidence.approved_at),
            "expires_at": _to_db(evidence.expires_at),
        }

        def work(cursor: DatabaseCursor) -> bool:
            sql, args = _render(REGISTER_SQL, parameters, self._paramstyle)
            cursor.execute(sql, args)
            return self._single_row_outcome(cursor.rowcount)

        if not self._run(work):
            raise ApprovalEvidenceInvalid(
                "approval evidence is already registered"
            )

    def consume(
        self,
        evidence: ApprovalEvidence,
        now: datetime,
        *,
        tenant_id: UUID | None = None,
        executor_id: UUID | None = None,
    ) -> bool:
        """
        Atomically consume evidence for ``tenant_id``.

        Returns True when this call consumed the approval and False when the
        database matched no row (unknown, other tenant, already consumed, or
        expired). Raises, without touching the database, when the evidence is
        invalid, untrusted, expired, lacks a tenant, or the tenants differ.
        """
        validated = self._require_tenant_binding(evidence, tenant_id)

        validated.require_valid_at(now)

        if executor_id is not None and not isinstance(executor_id, UUID):
            raise TypeError("executor_id must be a UUID or None")

        parameters: dict[str, Any] = {
            "now": _to_db(now),
            "executor_id": None if executor_id is None else str(executor_id),
            "approval_id": str(validated.approval_id),
            "tenant_id": str(tenant_id),
        }

        def work(cursor: DatabaseCursor) -> bool:
            sql, args = _render(CONSUME_SQL, parameters, self._paramstyle)
            cursor.execute(sql, args)
            return self._single_row_outcome(cursor.rowcount)

        return self._run(work)

    def is_consumed(self, approval_id: UUID) -> bool:
        """
        Return whether the approval has been consumed.

        Unknown approvals report False. Note: the locked protocol signature
        has no tenant parameter, so this reveals consumption status across
        tenants. Treat it as diagnostic, never as an authorization input.
        """
        if not isinstance(approval_id, UUID):
            raise TypeError("approval_id must be a UUID")

        parameters = {"approval_id": str(approval_id)}

        def work(cursor: DatabaseCursor) -> bool:
            sql, args = _render(IS_CONSUMED_SQL, parameters, self._paramstyle)
            cursor.execute(sql, args)
            row = cursor.fetchone()
            return row is not None and row[0] is not None

        return self._run(work)

    # -- internals -------------------------------------------------------

    @staticmethod
    def _require_tenant_binding(
        evidence: object,
        tenant_id: UUID | None,
    ) -> ApprovalEvidence:
        """Reject, before any database work, anything not tenant-bound."""
        if not isinstance(evidence, ApprovalEvidence):
            raise ApprovalEvidenceInvalid(
                "approval evidence is missing or invalid"
            )

        if evidence.tenant_id is None or tenant_id is None:
            raise ApprovalEvidenceInvalid(
                "tenant-bound evidence and a tenant_id are both required"
            )

        if not isinstance(tenant_id, UUID):
            raise TypeError("tenant_id must be a UUID")

        if evidence.tenant_id != tenant_id:
            raise ApprovalEvidenceInvalid(
                "approval evidence tenant does not match the consuming tenant"
            )

        return evidence

    @staticmethod
    def _single_row_outcome(rowcount: int) -> bool:
        """Map a DML rowcount to a result; anything unexpected fails closed."""
        if rowcount == 1:
            return True

        if rowcount == 0:
            return False

        raise ApprovalStoreError(
            f"unexpected affected-row count: {rowcount!r}"
        )

    def _run(self, work: Callable[[DatabaseCursor], T]) -> T:
        """
        Run ``work`` in one transaction on a connection.

        Commits on success and rolls back on any failure. Domain errors
        raised inside ``work`` propagate unchanged; every other exception
        becomes ApprovalStoreError with only the exception type name.
        """
        try:
            if self._factory is not None:
                connection = self._factory()

                try:
                    return self._transact(connection, work)
                finally:
                    with suppress(Exception):
                        connection.close()

            assert self._connection is not None

            with self._lock:
                return self._transact(self._connection, work)
        except (ApprovalStoreError, ApprovalEvidenceInvalid):
            raise
        except Exception as exc:
            raise ApprovalStoreError(
                f"approval store failure: {type(exc).__name__}"
            ) from exc

    def _transact(
        self,
        connection: DatabaseConnection,
        work: Callable[[DatabaseCursor], T],
    ) -> T:
        if not hasattr(connection, "cursor"):
            raise ApprovalStoreError("connection factory returned no connection")

        cursor = connection.cursor()

        try:
            if self._isolation_statement is not None:
                cursor.execute(self._isolation_statement)

            result = work(cursor)
            connection.commit()
            return result
        except BaseException:
            with suppress(Exception):
                connection.rollback()
            raise
        finally:
            with suppress(Exception):
                cursor.close()