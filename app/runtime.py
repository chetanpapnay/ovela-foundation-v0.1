from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Callable
from uuid import UUID, uuid4


class OvelaRuntimeError(Exception):
    pass


class AuthenticationFailure(OvelaRuntimeError):
    pass


class AuthorizationDenied(OvelaRuntimeError):
    pass


class TenantBoundaryViolation(OvelaRuntimeError):
    pass


class ApprovalRequired(OvelaRuntimeError):
    pass


class IdempotencyConflict(OvelaRuntimeError):
    pass


class RailTimeout(OvelaRuntimeError):
    pass


class ActionType(StrEnum):
    PAYMENT_INITIATE = "PAYMENT_INITIATE"
    TRANSFER_INITIATE = "TRANSFER_INITIATE"
    BILL_PAYMENT = "BILL_PAYMENT"


class Decision(StrEnum):
    PERMIT = "PERMIT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"


class ExecutionState(StrEnum):
    PENDING = "PENDING"
    SUBMITTED = "SUBMITTED"
    SETTLED = "SETTLED"
    UNKNOWN = "UNKNOWN"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class AuthRequest:
    tenant_id: UUID
    subject_id: UUID
    device_key_thumbprint: str
    password: str


@dataclass(frozen=True, slots=True)
class AuthResponse:
    session_id: UUID
    tenant_id: UUID
    subject_id: UUID
    access_token: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class PaymentProposeRequest:
    action_type: ActionType
    amount: Decimal
    currency: str
    destination_id: str
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class PaymentProposeResponse:
    request_id: UUID
    decision: Decision
    approval_required: bool
    reason: str


@dataclass(frozen=True, slots=True)
class PaymentExecuteRequest:
    request_id: UUID
    action_type: ActionType
    amount: Decimal
    currency: str
    destination_id: str
    approval_evidence_id: UUID | None = None


@dataclass(frozen=True, slots=True)
class PaymentExecuteResponse:
    transaction_id: UUID
    state: ExecutionState
    outbox_id: UUID
    audit_sequence: int


@dataclass(frozen=True, slots=True)
class AuditVerifyResponse:
    valid: bool
    tenant_id: UUID
    records_verified: int
    head_sequence: int | None
    first_failure: str | None


class OvelaRuntime:
    SESSION_TTL = timedelta(minutes=30)

    def __init__(
        self,
        connection: sqlite3.Connection | None = None,
        db_factory: Callable[[], sqlite3.Connection] | None = None,
    ) -> None:
        if connection is not None and db_factory is not None:
            raise ValueError("provide either connection or db_factory, not both")

        self._connection = connection
        self._db_factory = db_factory
        self._owns_connection = False
        self._temporary_database_path: str | None = None
        self._closed = False

        if connection is None and db_factory is None:
            file_descriptor, path = tempfile.mkstemp(
                prefix="ovela_runtime_",
                suffix=".sqlite3",
            )
            os.close(file_descriptor)
            self._temporary_database_path = path

        if self._connection is not None:
            self._configure_connection(self._connection)

        self.ensure_schema()

    @staticmethod
    def _configure_connection(connection: sqlite3.Connection) -> None:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")

    def _connect(self) -> sqlite3.Connection:
        if self._closed:
            raise OvelaRuntimeError("runtime is closed")

        if self._connection is not None:
            self._configure_connection(self._connection)
            return self._connection

        if self._db_factory is not None:
            connection = self._db_factory()
            self._configure_connection(connection)
            return connection

        if self._temporary_database_path is None:
            raise OvelaRuntimeError("database path is unavailable")

        connection = sqlite3.connect(self._temporary_database_path)
        self._configure_connection(connection)
        return connection

    def _close_connection(self, connection: sqlite3.Connection) -> None:
        if connection is self._connection:
            return
        try:
            connection.close()
        except sqlite3.Error:
            pass

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True

        if self._connection is not None and self._owns_connection:
            try:
                self._connection.close()
            except sqlite3.Error:
                pass

        self._connection = self._connection if not self._owns_connection else None

        if self._temporary_database_path is not None:
            path = self._temporary_database_path
            self._temporary_database_path = None
            try:
                os.remove(path)
            except FileNotFoundError:
                pass
            except OSError:
                pass

    def __enter__(self) -> OvelaRuntime:
        if self._closed:
            raise OvelaRuntimeError("runtime is closed")
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    @staticmethod
    def _utc(value: datetime) -> datetime:
        if not isinstance(value, datetime):
            raise TypeError("now must be a datetime")
        if value.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _uuid(value: UUID | str) -> UUID:
        if isinstance(value, UUID):
            return value
        return UUID(str(value))

    @staticmethod
    def _decimal(value: Decimal | str | int | float) -> Decimal:
        try:
            amount = Decimal(value)
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError("amount must be a valid Decimal") from exc

        if not amount.is_finite():
            raise ValueError("amount must be finite")

        if amount <= Decimal("0"):
            raise ValueError("amount must be greater than zero")

        return amount

    @staticmethod
    def _currency(value: str) -> str:
        if not isinstance(value, str):
            raise TypeError("currency must be a string")

        currency = value.strip().upper()

        if len(currency) != 3 or not currency.isalpha():
            raise ValueError("currency must be a three-letter code")

        return currency

    @staticmethod
    def _nonempty(value: str, field_name: str) -> str:
        if not isinstance(value, str):
            raise TypeError(f"{field_name} must be a string")

        normalized = value.strip()

        if not normalized:
            raise ValueError(f"{field_name} must not be empty")

        return normalized

    @staticmethod
    def _timestamp(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _canonical_payload(payload: str) -> bytes:
        return payload.encode("utf-8")

    @classmethod
    def _payload_digest(cls, payload: str) -> str:
        return hashlib.sha256(cls._canonical_payload(payload)).hexdigest()

    @classmethod
    def _record_hash(
        cls,
        tenant_id: UUID,
        sequence: int,
        previous_hash: bytes,
        event_type: str,
        payload: str,
        recorded_at: datetime,
    ) -> bytes:
        payload_digest = bytes.fromhex(cls._payload_digest(payload))
        material = (
            previous_hash
            + tenant_id.bytes
            + sequence.to_bytes(8, "big", signed=False)
            + event_type.encode("utf-8")
            + payload_digest
            + cls._timestamp(recorded_at).encode("utf-8")
        )
        return hashlib.sha256(material).digest()

    @staticmethod
    def _audit_payload(**values: object) -> str:
        parts: list[str] = []

        for key in sorted(values):
            value = values[key]

            if isinstance(value, UUID):
                rendered = str(value)
            elif isinstance(value, Decimal):
                rendered = format(value, "f")
            elif isinstance(value, bool):
                rendered = "true" if value else "false"
            elif value is None:
                rendered = "null"
            else:
                rendered = str(value)

            parts.append(f"{key}={rendered}")

        return "|".join(parts)

    def ensure_schema(self) -> None:
        connection = self._connect()

        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    device_key_thumbprint TEXT NOT NULL,
                    password_digest TEXT NOT NULL,
                    access_token_digest TEXT NOT NULL UNIQUE,
                    issued_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_tenant
                    ON sessions(tenant_id);

                CREATE TABLE IF NOT EXISTS payment_proposals (
                    request_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    amount TEXT NOT NULL,
                    currency TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    metadata TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    approval_required INTEGER NOT NULL,
                    reason TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_payment_proposals_tenant
                    ON payment_proposals(tenant_id);

                CREATE TABLE IF NOT EXISTS transactions (
                    transaction_id TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL UNIQUE,
                    tenant_id TEXT NOT NULL,
                    subject_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    amount TEXT NOT NULL,
                    currency TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    state TEXT NOT NULL,
                    approval_evidence_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_transactions_tenant
                    ON transactions(tenant_id);

                CREATE TABLE IF NOT EXISTS outbox (
                    outbox_id TEXT PRIMARY KEY,
                    transaction_id TEXT NOT NULL UNIQUE,
                    tenant_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    dispatched INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    dispatched_at TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_outbox_pending
                    ON outbox(dispatched, tenant_id);

                CREATE TABLE IF NOT EXISTS audit_events (
                    tenant_id TEXT NOT NULL,
                    sequence_number INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    recorded_at TEXT NOT NULL,
                    prev_record_hash BLOB NOT NULL,
                    record_hash BLOB NOT NULL,
                    PRIMARY KEY (tenant_id, sequence_number),
                    UNIQUE (tenant_id, record_hash)
                );

                CREATE INDEX IF NOT EXISTS idx_audit_tenant_sequence
                    ON audit_events(tenant_id, sequence_number);
                """
            )
            connection.commit()
        finally:
            self._close_connection(connection)

    def _session(
        self,
        connection: sqlite3.Connection,
        session_id: UUID,
        now: datetime,
    ) -> sqlite3.Row:
        row = connection.execute(
            """
            SELECT
                session_id,
                tenant_id,
                subject_id,
                expires_at,
                revoked
            FROM sessions
            WHERE session_id = ?
            """,
            (str(session_id),),
        ).fetchone()

        if row is None:
            raise AuthenticationFailure("session does not exist")

        if bool(row["revoked"]):
            raise AuthenticationFailure("session has been revoked")

        expires_at = datetime.fromisoformat(row["expires_at"])

        if self._utc(now) >= expires_at.astimezone(timezone.utc):
            raise AuthenticationFailure("session has expired")

        return row

    def _append_audit(
        self,
        connection: sqlite3.Connection,
        tenant_id: UUID,
        event_type: str,
        payload: str,
        recorded_at: datetime,
    ) -> int:
        tenant_text = str(tenant_id)

        row = connection.execute(
            """
            SELECT
                sequence_number,
                record_hash
            FROM audit_events
            WHERE tenant_id = ?
            ORDER BY sequence_number DESC
            LIMIT 1
            """,
            (tenant_text,),
        ).fetchone()

        if row is None:
            sequence = 0
            previous_hash = b"\x00" * 32
        else:
            sequence = int(row["sequence_number"]) + 1
            previous_hash = bytes(row["record_hash"])

        record_hash = self._record_hash(
            tenant_id=tenant_id,
            sequence=sequence,
            previous_hash=previous_hash,
            event_type=event_type,
            payload=payload,
            recorded_at=recorded_at,
        )

        connection.execute(
            """
            INSERT INTO audit_events (
                tenant_id,
                sequence_number,
                event_type,
                payload,
                recorded_at,
                prev_record_hash,
                record_hash
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_text,
                sequence,
                event_type,
                payload,
                self._timestamp(recorded_at),
                previous_hash,
                record_hash,
            ),
        )

        return sequence

    def authenticate_session(
        self,
        req: AuthRequest,
        now: datetime,
    ) -> AuthResponse:
        current = self._utc(now)

        if not isinstance(req.tenant_id, UUID):
            raise AuthenticationFailure("tenant_id must be a UUID")

        if not isinstance(req.subject_id, UUID):
            raise AuthenticationFailure("subject_id must be a UUID")

        thumbprint = self._nonempty(
            req.device_key_thumbprint,
            "device_key_thumbprint",
        )
        password = self._nonempty(req.password, "password")

        connection = self._connect()

        session_id = uuid4()
        access_token = secrets.token_urlsafe(48)
        expires_at = current + self.SESSION_TTL

        password_digest = hashlib.sha256(
            password.encode("utf-8")
        ).hexdigest()

        access_token_digest = hashlib.sha256(
            access_token.encode("utf-8")
        ).hexdigest()

        try:
            connection.execute("BEGIN")

            connection.execute(
                """
                INSERT INTO sessions (
                    session_id,
                    tenant_id,
                    subject_id,
                    device_key_thumbprint,
                    password_digest,
                    access_token_digest,
                    issued_at,
                    expires_at,
                    revoked
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    str(session_id),
                    str(req.tenant_id),
                    str(req.subject_id),
                    thumbprint,
                    password_digest,
                    access_token_digest,
                    self._timestamp(current),
                    self._timestamp(expires_at),
                ),
            )

            self._append_audit(
                connection=connection,
                tenant_id=req.tenant_id,
                event_type="SESSION_AUTHENTICATED",
                payload=self._audit_payload(
                    session_id=session_id,
                    subject_id=req.subject_id,
                    device_key_thumbprint=thumbprint,
                ),
                recorded_at=current,
            )

            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            self._close_connection(connection)

        return AuthResponse(
            session_id=session_id,
            tenant_id=req.tenant_id,
            subject_id=req.subject_id,
            access_token=access_token,
            expires_at=expires_at,
        )

    def propose_payment(
        self,
        session_id: UUID,
        req: PaymentProposeRequest,
        spending_limit: Decimal,
        now: datetime,
    ) -> PaymentProposeResponse:
        current = self._utc(now)

        if not isinstance(session_id, UUID):
            raise AuthenticationFailure("session_id must be a UUID")

        if not isinstance(req.action_type, ActionType):
            raise AuthorizationDenied("unsupported action type")

        amount = self._decimal(req.amount)
        currency = self._currency(req.currency)
        destination_id = self._nonempty(
            req.destination_id,
            "destination_id",
        )
        limit = self._decimal(spending_limit)

        connection = self._connect()

        try:
            session = self._session(connection, session_id, current)

            tenant_id = UUID(session["tenant_id"])
            subject_id = UUID(session["subject_id"])
            request_id = uuid4()

            metadata_parts: list[str] = []

            for key in sorted(req.metadata):
                metadata_key = self._nonempty(key, "metadata key")
                metadata_value = self._nonempty(
                    req.metadata[key],
                    f"metadata value for {metadata_key}",
                )
                metadata_parts.append(
                    f"{metadata_key}={metadata_value}"
                )

            metadata = "|".join(metadata_parts)

            if amount > limit:
                decision = Decision.REQUIRE_APPROVAL
                approval_required = True
                reason = (
                    "payment exceeds the configured spending limit"
                )
            else:
                decision = Decision.PERMIT
                approval_required = False
                reason = (
                    "payment is within the configured spending limit"
                )

            payload = self._audit_payload(
                request_id=request_id,
                session_id=session_id,
                subject_id=subject_id,
                action_type=req.action_type.value,
                amount=amount,
                currency=currency,
                destination_id=destination_id,
                decision=decision.value,
                approval_required=approval_required,
            )

            connection.execute("BEGIN")

            connection.execute(
                """
                INSERT INTO payment_proposals (
                    request_id,
                    tenant_id,
                    subject_id,
                    session_id,
                    action_type,
                    amount,
                    currency,
                    destination_id,
                    metadata,
                    decision,
                    approval_required,
                    reason,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(request_id),
                    str(tenant_id),
                    str(subject_id),
                    str(session_id),
                    req.action_type.value,
                    format(amount, "f"),
                    currency,
                    destination_id,
                    metadata,
                    decision.value,
                    int(approval_required),
                    reason,
                    self._timestamp(current),
                ),
            )

            self._append_audit(
                connection=connection,
                tenant_id=tenant_id,
                event_type="PAYMENT_PROPOSED",
                payload=payload,
                recorded_at=current,
            )

            connection.commit()

            return PaymentProposeResponse(
                request_id=request_id,
                decision=decision,
                approval_required=approval_required,
                reason=reason,
            )
        except Exception:
            connection.rollback()
            raise
        finally:
            self._close_connection(connection)

    def execute_payment(
        self,
        session_id: UUID,
        req: PaymentExecuteRequest,
        spending_limit: Decimal,
        simulate_rail_timeout: bool = False,
        now: datetime | None = None,
    ) -> PaymentExecuteResponse:
        current = self._utc(
            now or datetime.now(timezone.utc)
        )

        if not isinstance(session_id, UUID):
            raise AuthenticationFailure("session_id must be a UUID")

        if not isinstance(req.request_id, UUID):
            raise IdempotencyConflict("request_id must be a UUID")

        if not isinstance(req.action_type, ActionType):
            raise AuthorizationDenied("unsupported action type")

        amount = self._decimal(req.amount)
        currency = self._currency(req.currency)
        destination_id = self._nonempty(
            req.destination_id,
            "destination_id",
        )
        limit = self._decimal(spending_limit)

        connection = self._connect()

        try:
            session = self._session(
                connection,
                session_id,
                current,
            )

            session_tenant_id = UUID(session["tenant_id"])
            subject_id = UUID(session["subject_id"])

            proposal = connection.execute(
                """
                SELECT
                    request_id,
                    tenant_id,
                    subject_id,
                    session_id,
                    action_type,
                    amount,
                    currency,
                    destination_id,
                    decision,
                    approval_required
                FROM payment_proposals
                WHERE request_id = ?
                """,
                (str(req.request_id),),
            ).fetchone()

            if proposal is None:
                raise AuthorizationDenied(
                    "payment proposal does not exist"
                )

            proposal_tenant_id = UUID(proposal["tenant_id"])

            if proposal_tenant_id != session_tenant_id:
                raise TenantBoundaryViolation(
                    "session tenant does not match proposal tenant"
                )

            proposal_subject_id = UUID(proposal["subject_id"])
            proposal_session_id = UUID(proposal["session_id"])

            if proposal_subject_id != subject_id:
                raise TenantBoundaryViolation(
                    "session subject does not match proposal subject"
                )

            if proposal_session_id != session_id:
                raise AuthorizationDenied(
                    "session does not own the payment proposal"
                )

            proposal_action_type = ActionType(
                proposal["action_type"]
            )
            proposal_amount = Decimal(proposal["amount"])
            proposal_currency = proposal["currency"]
            proposal_destination_id = proposal["destination_id"]

            if proposal_action_type is not req.action_type:
                raise IdempotencyConflict(
                    "execution action type does not match proposal"
                )

            if proposal_amount != amount:
                raise IdempotencyConflict(
                    "execution amount does not match proposal"
                )

            if proposal_currency != currency:
                raise IdempotencyConflict(
                    "execution currency does not match proposal"
                )

            if proposal_destination_id != destination_id:
                raise IdempotencyConflict(
                    "execution destination does not match proposal"
                )

            if amount > limit and req.approval_evidence_id is None:
                raise ApprovalRequired(
                    "valid approval evidence is required for this payment"
                )

            existing = connection.execute(
                """
                SELECT
                    transaction_id,
                    request_id,
                    tenant_id,
                    subject_id,
                    session_id,
                    action_type,
                    amount,
                    currency,
                    destination_id,
                    state,
                    approval_evidence_id
                FROM transactions
                WHERE request_id = ?
                """,
                (str(req.request_id),),
            ).fetchone()

            if existing is not None:
                existing_tenant_id = UUID(existing["tenant_id"])

                if existing_tenant_id != session_tenant_id:
                    raise TenantBoundaryViolation(
                        "session tenant does not match transaction tenant"
                    )

                existing_identity = (
                    existing["session_id"],
                    existing["subject_id"],
                    existing["action_type"],
                    existing["amount"],
                    existing["currency"],
                    existing["destination_id"],
                    existing["approval_evidence_id"],
                )

                requested_identity = (
                    str(session_id),
                    str(subject_id),
                    req.action_type.value,
                    format(amount, "f"),
                    currency,
                    destination_id,
                    (
                        str(req.approval_evidence_id)
                        if req.approval_evidence_id is not None
                        else None
                    ),
                )

                if existing_identity != requested_identity:
                    raise IdempotencyConflict(
                        "request_id has already been used with "
                        "different parameters"
                    )

                outbox = connection.execute(
                    """
                    SELECT outbox_id
                    FROM outbox
                    WHERE transaction_id = ?
                      AND tenant_id = ?
                    """,
                    (
                        existing["transaction_id"],
                        str(session_tenant_id),
                    ),
                ).fetchone()

                if outbox is None:
                    raise OvelaRuntimeError(
                        "transaction exists without its durable outbox"
                    )

                audit = connection.execute(
                    """
                    SELECT sequence_number
                    FROM audit_events
                    WHERE tenant_id = ?
                      AND event_type = 'TRANSACTION_CREATED'
                      AND payload LIKE ?
                    ORDER BY sequence_number DESC
                    LIMIT 1
                    """,
                    (
                        str(session_tenant_id),
                        f"%transaction_id={existing['transaction_id']}%",
                    ),
                ).fetchone()

                if audit is None:
                    raise OvelaRuntimeError(
                        "transaction exists without creation audit evidence"
                    )

                return PaymentExecuteResponse(
                    transaction_id=UUID(
                        existing["transaction_id"]
                    ),
                    state=ExecutionState(existing["state"]),
                    outbox_id=UUID(outbox["outbox_id"]),
                    audit_sequence=int(
                        audit["sequence_number"]
                    ),
                )

            transaction_id = uuid4()
            outbox_id = uuid4()

            transaction_payload = self._audit_payload(
                transaction_id=transaction_id,
                request_id=req.request_id,
                subject_id=subject_id,
                session_id=session_id,
                action_type=req.action_type.value,
                amount=amount,
                currency=currency,
                destination_id=destination_id,
            )

            connection.execute("BEGIN")

            connection.execute(
                """
                INSERT INTO transactions (
                    transaction_id,
                    request_id,
                    tenant_id,
                    subject_id,
                    session_id,
                    action_type,
                    amount,
                    currency,
                    destination_id,
                    state,
                    approval_evidence_id,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(transaction_id),
                    str(req.request_id),
                    str(session_tenant_id),
                    str(subject_id),
                    str(session_id),
                    req.action_type.value,
                    format(amount, "f"),
                    currency,
                    destination_id,
                    ExecutionState.PENDING.value,
                    (
                        str(req.approval_evidence_id)
                        if req.approval_evidence_id is not None
                        else None
                    ),
                    self._timestamp(current),
                    self._timestamp(current),
                ),
            )

            connection.execute(
                """
                INSERT INTO outbox (
                    outbox_id,
                    transaction_id,
                    tenant_id,
                    payload,
                    dispatched,
                    created_at,
                    dispatched_at
                )
                VALUES (?, ?, ?, ?, 0, ?, NULL)
                """,
                (
                    str(outbox_id),
                    str(transaction_id),
                    str(session_tenant_id),
                    transaction_payload,
                    self._timestamp(current),
                ),
            )

            audit_sequence = self._append_audit(
                connection=connection,
                tenant_id=session_tenant_id,
                event_type="TRANSACTION_CREATED",
                payload=transaction_payload,
                recorded_at=current,
            )

            connection.commit()

            if simulate_rail_timeout:
                connection.execute("BEGIN")

                connection.execute(
                    """
                    UPDATE transactions
                    SET state = ?, updated_at = ?
                    WHERE transaction_id = ?
                      AND tenant_id = ?
                    """,
                    (
                        ExecutionState.UNKNOWN.value,
                        self._timestamp(current),
                        str(transaction_id),
                        str(session_tenant_id),
                    ),
                )

                self._append_audit(
                    connection=connection,
                    tenant_id=session_tenant_id,
                    event_type="RAIL_TIMEOUT",
                    payload=self._audit_payload(
                        transaction_id=transaction_id,
                        request_id=req.request_id,
                        state=ExecutionState.UNKNOWN.value,
                    ),
                    recorded_at=current,
                )

                connection.execute(
                    """
                    UPDATE outbox
                    SET dispatched = 1, dispatched_at = ?
                    WHERE outbox_id = ?
                      AND tenant_id = ?
                    """,
                    (
                        self._timestamp(current),
                        str(outbox_id),
                        str(session_tenant_id),
                    ),
                )

                connection.commit()

                return PaymentExecuteResponse(
                    transaction_id=transaction_id,
                    state=ExecutionState.UNKNOWN,
                    outbox_id=outbox_id,
                    audit_sequence=audit_sequence,
                )

            connection.execute("BEGIN")

            connection.execute(
                """
                UPDATE transactions
                SET state = ?, updated_at = ?
                WHERE transaction_id = ?
                  AND tenant_id = ?
                """,
                (
                    ExecutionState.SUBMITTED.value,
                    self._timestamp(current),
                    str(transaction_id),
                    str(session_tenant_id),
                ),
            )

            connection.execute(
                """
                UPDATE outbox
                SET dispatched = 1, dispatched_at = ?
                WHERE outbox_id = ?
                  AND tenant_id = ?
                """,
                (
                    self._timestamp(current),
                    str(outbox_id),
                    str(session_tenant_id),
                ),
            )

            connection.commit()

            return PaymentExecuteResponse(
                transaction_id=transaction_id,
                state=ExecutionState.SUBMITTED,
                outbox_id=outbox_id,
                audit_sequence=audit_sequence,
            )
        except sqlite3.IntegrityError as exc:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass

            existing = connection.execute(
                """
                SELECT
                    transaction_id,
                    tenant_id
                FROM transactions
                WHERE request_id = ?
                """,
                (str(req.request_id),),
            ).fetchone()

            if existing is not None:
                if UUID(existing["tenant_id"]) != UUID(
                    session["tenant_id"]
                ):
                    raise TenantBoundaryViolation(
                        "session tenant does not match transaction tenant"
                    ) from exc

                raise IdempotencyConflict(
                    "request_id has already been committed"
                ) from exc

            raise
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            self._close_connection(connection)

    def ingest_rail_webhook(
        self,
        tenant_id: UUID,
        transaction_id: UUID,
        status: str,
        now: datetime,
    ) -> bool:
        current = self._utc(now)

        if not isinstance(tenant_id, UUID):
            raise TenantBoundaryViolation("tenant_id must be a UUID")

        if not isinstance(transaction_id, UUID):
            raise ValueError("transaction_id must be a UUID")

        normalized_status = self._nonempty(
            status,
            "status",
        ).upper()

        if normalized_status not in {"SETTLED", "FAILED"}:
            raise ValueError("status must be SETTLED or FAILED")

        connection = self._connect()

        try:
            row = connection.execute(
                """
                SELECT
                    transaction_id,
                    tenant_id,
                    state
                FROM transactions
                WHERE transaction_id = ?
                """,
                (str(transaction_id),),
            ).fetchone()

            if row is None:
                raise AuthorizationDenied(
                    "transaction does not exist"
                )

            transaction_tenant_id = UUID(row["tenant_id"])

            if transaction_tenant_id != tenant_id:
                raise TenantBoundaryViolation(
                    "transaction belongs to a different tenant"
                )

            current_state = ExecutionState(row["state"])

            if current_state in {
                ExecutionState.SETTLED,
                ExecutionState.FAILED,
            }:
                return (
                    current_state.value == normalized_status
                )

            target_state = (
                ExecutionState.SETTLED
                if normalized_status == "SETTLED"
                else ExecutionState.FAILED
            )

            connection.execute("BEGIN")

            connection.execute(
                """
                UPDATE transactions
                SET state = ?, updated_at = ?
                WHERE transaction_id = ?
                  AND tenant_id = ?
                """,
                (
                    target_state.value,
                    self._timestamp(current),
                    str(transaction_id),
                    str(tenant_id),
                ),
            )

            self._append_audit(
                connection=connection,
                tenant_id=tenant_id,
                event_type="WEBHOOK_SETTLED",
                payload=self._audit_payload(
                    transaction_id=transaction_id,
                    status=normalized_status,
                    previous_state=current_state.value,
                    new_state=target_state.value,
                ),
                recorded_at=current,
            )

            connection.commit()
            return True
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            self._close_connection(connection)

    def reconcile_statement(
        self,
        tenant_id: UUID,
        transaction_id: UUID,
        matched: bool,
        now: datetime,
    ) -> bool:
        current = self._utc(now)

        if not isinstance(tenant_id, UUID):
            raise TenantBoundaryViolation("tenant_id must be a UUID")

        if not isinstance(transaction_id, UUID):
            raise ValueError("transaction_id must be a UUID")

        if not isinstance(matched, bool):
            raise TypeError("matched must be a boolean")

        connection = self._connect()

        try:
            row = connection.execute(
                """
                SELECT
                    transaction_id,
                    tenant_id,
                    state
                FROM transactions
                WHERE transaction_id = ?
                """,
                (str(transaction_id),),
            ).fetchone()

            if row is None:
                raise AuthorizationDenied(
                    "transaction does not exist"
                )

            transaction_tenant_id = UUID(row["tenant_id"])

            if transaction_tenant_id != tenant_id:
                raise TenantBoundaryViolation(
                    "transaction belongs to a different tenant"
                )

            current_state = ExecutionState(row["state"])

            if not matched:
                return False

            if current_state is ExecutionState.SETTLED:
                return True

            if current_state is not ExecutionState.UNKNOWN:
                return False

            connection.execute("BEGIN")

            connection.execute(
                """
                UPDATE transactions
                SET state = ?, updated_at = ?
                WHERE transaction_id = ?
                  AND tenant_id = ?
                  AND state = ?
                """,
                (
                    ExecutionState.SETTLED.value,
                    self._timestamp(current),
                    str(transaction_id),
                    str(tenant_id),
                    ExecutionState.UNKNOWN.value,
                ),
            )

            self._append_audit(
                connection=connection,
                tenant_id=tenant_id,
                event_type="RECONCILIATION_MATCHED",
                payload=self._audit_payload(
                    transaction_id=transaction_id,
                    previous_state=current_state.value,
                    new_state=ExecutionState.SETTLED.value,
                ),
                recorded_at=current,
            )

            connection.commit()
            return True
        except Exception:
            try:
                connection.rollback()
            except sqlite3.Error:
                pass
            raise
        finally:
            self._close_connection(connection)

    def verify_audit_chain(
        self,
        tenant_id: UUID,
    ) -> AuditVerifyResponse:
        if not isinstance(tenant_id, UUID):
            raise TenantBoundaryViolation(
                "tenant_id must be a UUID"
            )

        connection = self._connect()

        try:
            rows = connection.execute(
                """
                SELECT
                    tenant_id,
                    sequence_number,
                    event_type,
                    payload,
                    recorded_at,
                    prev_record_hash,
                    record_hash
                FROM audit_events
                WHERE tenant_id = ?
                ORDER BY sequence_number ASC
                """,
                (str(tenant_id),),
            ).fetchall()

            if not rows:
                return AuditVerifyResponse(
                    valid=True,
                    tenant_id=tenant_id,
                    records_verified=0,
                    head_sequence=None,
                    first_failure=None,
                )

            previous_hash = b"\x00" * 32
            expected_sequence = 0
            records_verified = 0
            first_failure: str | None = None

            for row in rows:
                sequence = int(row["sequence_number"])

                if sequence != expected_sequence:
                    first_failure = (
                        f"sequence discontinuity at sequence "
                        f"{sequence}: expected {expected_sequence}"
                    )
                    break

                if UUID(row["tenant_id"]) != tenant_id:
                    first_failure = (
                        f"tenant boundary violation at sequence "
                        f"{sequence}"
                    )
                    break

                stored_previous_hash = bytes(
                    row["prev_record_hash"]
                )

                if stored_previous_hash != previous_hash:
                    first_failure = (
                        f"previous hash mismatch at sequence "
                        f"{sequence}"
                    )
                    break

                recorded_at = datetime.fromisoformat(
                    row["recorded_at"]
                )

                expected_hash = self._record_hash(
                    tenant_id=tenant_id,
                    sequence=sequence,
                    previous_hash=previous_hash,
                    event_type=row["event_type"],
                    payload=row["payload"],
                    recorded_at=recorded_at,
                )

                actual_hash = bytes(row["record_hash"])

                if actual_hash != expected_hash:
                    first_failure = (
                        f"record hash mismatch at sequence "
                        f"{sequence}"
                    )
                    break

                records_verified += 1
                previous_hash = actual_hash
                expected_sequence += 1

            valid = first_failure is None
            head_sequence = int(rows[-1]["sequence_number"])

            return AuditVerifyResponse(
                valid=valid,
                tenant_id=tenant_id,
                records_verified=records_verified,
                head_sequence=head_sequence,
                first_failure=first_failure,
            )
        finally:
            self._close_connection(connection)