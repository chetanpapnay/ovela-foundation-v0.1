from __future__ import annotations

import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from typing import Any, Callable, Mapping
from uuid import UUID, uuid4


DOMAIN_SEPARATOR = b"OVELA-AUDIT-RECORD-v1"
ZERO_HASH = b"\x00" * 32


def _encode_field(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    return len(data).to_bytes(4, "big") + data


def canonicalize_payload(payload: dict | list | str | bytes) -> bytes:
    if isinstance(payload, bytes):
        return payload

    if isinstance(payload, (dict, list, str)):
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

    raise TypeError(
        "payload must be a dict, list, str, or bytes"
    )


def compute_payload_digest(payload: Any) -> bytes:
    return sha256(canonicalize_payload(payload)).digest()


def _utc_timestamp_micros(recorded_at: datetime) -> int:
    if recorded_at.tzinfo is None:
        raise ValueError("recorded_at must be timezone-aware")

    return int(
        recorded_at.astimezone(timezone.utc).timestamp() * 1_000_000
    )


def compute_record_hash(
    tenant_id: UUID,
    sequence_number: int,
    prev_record_hash: bytes,
    event_type: str,
    payload_digest: bytes,
    recorded_at: datetime,
) -> bytes:
    if not isinstance(tenant_id, UUID):
        raise TypeError("tenant_id must be UUID")

    if not isinstance(sequence_number, int):
        raise TypeError("sequence_number must be int")

    if sequence_number < 0:
        raise ValueError("sequence_number must be non-negative")

    if not isinstance(prev_record_hash, bytes):
        raise TypeError("prev_record_hash must be bytes")

    if len(prev_record_hash) != 32:
        raise ValueError("prev_record_hash must be exactly 32 bytes")

    if not isinstance(event_type, str):
        raise TypeError("event_type must be str")

    if not isinstance(payload_digest, bytes):
        raise TypeError("payload_digest must be bytes")

    if len(payload_digest) != 32:
        raise ValueError("payload_digest must be exactly 32 bytes")

    timestamp_micros = _utc_timestamp_micros(recorded_at)

    material = b"".join(
        (
            _encode_field(DOMAIN_SEPARATOR),
            _encode_field(tenant_id.bytes),
            _encode_field(sequence_number.to_bytes(8, "big")),
            _encode_field(prev_record_hash),
            _encode_field(event_type.encode("utf-8")),
            _encode_field(payload_digest),
            _encode_field(timestamp_micros.to_bytes(8, "big")),
        )
    )

    return sha256(material).digest()


@dataclass(frozen=True)
class AuditRecord:
    audit_id: UUID
    tenant_id: UUID
    sequence_number: int
    prev_record_hash: bytes
    event_type: str
    payload_digest: bytes
    payload_raw: bytes
    recorded_at: datetime
    record_hash: bytes
    protocol_version: int = 1


@dataclass(frozen=True)
class AuditCheckpoint:
    checkpoint_id: UUID
    tenant_id: UUID
    sequence_number: int
    record_hash: bytes
    created_at: datetime
    signature: bytes = b""


class VerificationStatus(StrEnum):
    VALID = "VALID"
    INVALID = "INVALID"
    INCOMPLETE = "INCOMPLETE"
    UNTRUSTED_GENESIS = "UNTRUSTED_GENESIS"


@dataclass(frozen=True)
class VerificationFailure:
    code: str
    tenant_id: UUID
    sequence_number: int | None
    expected: Any | None
    actual: Any | None
    message: str


@dataclass(frozen=True)
class VerificationResult:
    status: VerificationStatus
    tenant_id: UUID
    records_verified: int
    first_failure: VerificationFailure | None
    failures: tuple[VerificationFailure, ...]
    head_sequence: int | None
    head_hash: bytes | None


def _datetime_to_storage(value: datetime) -> int:
    return _utc_timestamp_micros(value)


def _datetime_from_storage(value: Any) -> datetime:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    return datetime.fromtimestamp(
        int(value) / 1_000_000,
        tz=timezone.utc,
    )


def _connection_is_sqlite(connection: Any) -> bool:
    module_name = type(connection).__module__.lower()
    class_name = type(connection).__name__.lower()

    return (
        "sqlite" in module_name
        or "sqlite" in class_name
        or isinstance(connection, sqlite3.Connection)
    )


class ForensicAuditStore:
    def __init__(
        self,
        connection_factory: Callable[[], Any],
    ) -> None:
        if not callable(connection_factory):
            raise TypeError("connection_factory must be callable")

        self._connection_factory = connection_factory
        self._locks_guard = threading.Lock()
        self._tenant_locks: dict[UUID, threading.RLock] = {}
        self.ensure_schema()

    def _tenant_lock(self, tenant_id: UUID) -> threading.RLock:
        with self._locks_guard:
            lock = self._tenant_locks.get(tenant_id)
            if lock is None:
                lock = threading.RLock()
                self._tenant_locks[tenant_id] = lock
            return lock

    @staticmethod
    def _begin_transaction(connection: Any) -> None:
        if _connection_is_sqlite(connection):
            connection.execute("BEGIN IMMEDIATE")
        else:
            cursor = connection.cursor()
            try:
                cursor.execute("BEGIN")
            finally:
                cursor.close()

    @staticmethod
    def _rollback_quietly(connection: Any) -> None:
        try:
            connection.rollback()
        except Exception:
            pass

    @staticmethod
    def _close_quietly(resource: Any) -> None:
        try:
            resource.close()
        except Exception:
            pass

    @staticmethod
    def _placeholder(connection: Any) -> str:
        return "?" if _connection_is_sqlite(connection) else "%s"

    @staticmethod
    def _blob_type(connection: Any) -> str:
        return "BLOB" if _connection_is_sqlite(connection) else "BYTEA"

    def ensure_schema(self) -> None:
        connection = self._connection_factory()
        try:
            blob_type = self._blob_type(connection)

            cursor = connection.cursor()
            try:
                cursor.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS audit_records (
                        tenant_id TEXT NOT NULL,
                        sequence_number BIGINT NOT NULL,
                        audit_id TEXT NOT NULL,
                        prev_record_hash {blob_type} NOT NULL,
                        event_type TEXT NOT NULL,
                        payload_digest {blob_type} NOT NULL,
                        payload_raw {blob_type} NOT NULL,
                        recorded_at BIGINT NOT NULL,
                        record_hash {blob_type} NOT NULL,
                        protocol_version INTEGER NOT NULL DEFAULT 1,
                        PRIMARY KEY (tenant_id, sequence_number),
                        UNIQUE (tenant_id, record_hash)
                    )
                    """
                )

                cursor.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS tenant_chain_heads (
                        tenant_id TEXT PRIMARY KEY,
                        sequence_number BIGINT NOT NULL,
                        current_hash {blob_type} NOT NULL,
                        updated_at BIGINT NOT NULL
                    )
                    """
                )

                connection.commit()
            except Exception:
                self._rollback_quietly(connection)
                raise
            finally:
                cursor.close()
        finally:
            self._close_quietly(connection)

    def initialize_genesis(
        self,
        tenant_id: UUID,
        now: datetime,
    ) -> AuditRecord:
        if not isinstance(tenant_id, UUID):
            raise TypeError("tenant_id must be UUID")

        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        lock = self._tenant_lock(tenant_id)

        with lock:
            connection = self._connection_factory()

            try:
                self._begin_transaction(connection)

                placeholder = self._placeholder(connection)

                cursor = connection.cursor()
                try:
                    cursor.execute(
                        f"""
                        SELECT
                            audit_id,
                            tenant_id,
                            sequence_number,
                            prev_record_hash,
                            event_type,
                            payload_digest,
                            payload_raw,
                            recorded_at,
                            record_hash,
                            protocol_version
                        FROM audit_records
                        WHERE tenant_id = {placeholder}
                          AND sequence_number = 0
                        """,
                        (str(tenant_id),),
                    )

                    existing = cursor.fetchone()

                    if existing is not None:
                        record = self._row_to_record(existing)

                        cursor.execute(
                            f"""
                            SELECT sequence_number, current_hash
                            FROM tenant_chain_heads
                            WHERE tenant_id = {placeholder}
                            """,
                            (str(tenant_id),),
                        )

                        head = cursor.fetchone()

                        if head is None:
                            cursor.execute(
                                f"""
                                INSERT INTO tenant_chain_heads
                                    (
                                        tenant_id,
                                        sequence_number,
                                        current_hash,
                                        updated_at
                                    )
                                VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder})
                                """,
                                (
                                    str(tenant_id),
                                    record.sequence_number,
                                    record.record_hash,
                                    _datetime_to_storage(now),
                                ),
                            )
                        elif (
                            int(head[0]) == record.sequence_number
                            and bytes(head[1]) == record.record_hash
                        ):
                            pass

                        connection.commit()
                        return record

                    payload_raw = canonicalize_payload({})
                    payload_digest = compute_payload_digest(payload_raw)

                    record_hash = compute_record_hash(
                        tenant_id=tenant_id,
                        sequence_number=0,
                        prev_record_hash=ZERO_HASH,
                        event_type="GENESIS",
                        payload_digest=payload_digest,
                        recorded_at=now,
                    )

                    record = AuditRecord(
                        audit_id=uuid4(),
                        tenant_id=tenant_id,
                        sequence_number=0,
                        prev_record_hash=ZERO_HASH,
                        event_type="GENESIS",
                        payload_digest=payload_digest,
                        payload_raw=payload_raw,
                        recorded_at=now.astimezone(timezone.utc),
                        record_hash=record_hash,
                        protocol_version=1,
                    )

                    self._insert_record(
                        connection,
                        record,
                    )

                    cursor.execute(
                        f"""
                        INSERT INTO tenant_chain_heads
                            (
                                tenant_id,
                                sequence_number,
                                current_hash,
                                updated_at
                            )
                        VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder})
                        """,
                        (
                            str(tenant_id),
                            0,
                            record_hash,
                            _datetime_to_storage(now),
                        ),
                    )

                    connection.commit()
                    return record

                except Exception:
                    self._rollback_quietly(connection)
                    raise
                finally:
                    cursor.close()
            finally:
                self._close_quietly(connection)

    def append_event(
        self,
        tenant_id: UUID,
        event_type: str,
        payload: Any,
        now: datetime,
    ) -> AuditRecord:
        if not isinstance(tenant_id, UUID):
            raise TypeError("tenant_id must be UUID")

        if not isinstance(event_type, str) or not event_type:
            raise ValueError("event_type must be a non-empty string")

        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")

        lock = self._tenant_lock(tenant_id)

        with lock:
            connection = self._connection_factory()

            try:
                self._begin_transaction(connection)

                placeholder = self._placeholder(connection)

                cursor = connection.cursor()
                try:
                    cursor.execute(
                        f"""
                        SELECT
                            sequence_number,
                            current_hash
                        FROM tenant_chain_heads
                        WHERE tenant_id = {placeholder}
                        """,
                        (str(tenant_id),),
                    )

                    head = cursor.fetchone()

                    if head is None:
                        raise RuntimeError(
                            "tenant chain has not been initialized"
                        )

                    current_sequence = int(head[0])
                    current_hash = bytes(head[1])

                    payload_raw = canonicalize_payload(payload)
                    payload_digest = compute_payload_digest(payload_raw)

                    sequence_number = current_sequence + 1

                    record_hash = compute_record_hash(
                        tenant_id=tenant_id,
                        sequence_number=sequence_number,
                        prev_record_hash=current_hash,
                        event_type=event_type,
                        payload_digest=payload_digest,
                        recorded_at=now,
                    )

                    record = AuditRecord(
                        audit_id=uuid4(),
                        tenant_id=tenant_id,
                        sequence_number=sequence_number,
                        prev_record_hash=current_hash,
                        event_type=event_type,
                        payload_digest=payload_digest,
                        payload_raw=payload_raw,
                        recorded_at=now.astimezone(timezone.utc),
                        record_hash=record_hash,
                        protocol_version=1,
                    )

                    self._insert_record(
                        connection,
                        record,
                    )

                    cursor.execute(
                        f"""
                        UPDATE tenant_chain_heads
                        SET
                            sequence_number = {placeholder},
                            current_hash = {placeholder},
                            updated_at = {placeholder}
                        WHERE tenant_id = {placeholder}
                        """,
                        (
                            sequence_number,
                            record_hash,
                            _datetime_to_storage(now),
                            str(tenant_id),
                        ),
                    )

                    if cursor.rowcount != 1:
                        raise RuntimeError(
                            "tenant chain head update failed"
                        )

                    connection.commit()
                    return record

                except Exception:
                    self._rollback_quietly(connection)
                    raise
                finally:
                    cursor.close()
            finally:
                self._close_quietly(connection)

    def get_record(
        self,
        tenant_id: UUID,
        sequence_number: int,
    ) -> AuditRecord | None:
        if not isinstance(tenant_id, UUID):
            raise TypeError("tenant_id must be UUID")

        if sequence_number < 0:
            raise ValueError("sequence_number must be non-negative")

        connection = self._connection_factory()

        try:
            placeholder = self._placeholder(connection)

            cursor = connection.cursor()
            try:
                cursor.execute(
                    f"""
                    SELECT
                        audit_id,
                        tenant_id,
                        sequence_number,
                        prev_record_hash,
                        event_type,
                        payload_digest,
                        payload_raw,
                        recorded_at,
                        record_hash,
                        protocol_version
                    FROM audit_records
                    WHERE tenant_id = {placeholder}
                      AND sequence_number = {placeholder}
                    """,
                    (str(tenant_id), sequence_number),
                )

                row = cursor.fetchone()
                return None if row is None else self._row_to_record(row)
            finally:
                cursor.close()
        finally:
            self._close_quietly(connection)

    def get_records(
        self,
        tenant_id: UUID,
    ) -> list[AuditRecord]:
        if not isinstance(tenant_id, UUID):
            raise TypeError("tenant_id must be UUID")

        connection = self._connection_factory()

        try:
            placeholder = self._placeholder(connection)

            cursor = connection.cursor()
            try:
                cursor.execute(
                    f"""
                    SELECT
                        audit_id,
                        tenant_id,
                        sequence_number,
                        prev_record_hash,
                        event_type,
                        payload_digest,
                        payload_raw,
                        recorded_at,
                        record_hash,
                        protocol_version
                    FROM audit_records
                    WHERE tenant_id = {placeholder}
                    ORDER BY sequence_number ASC
                    """,
                    (str(tenant_id),),
                )

                return [
                    self._row_to_record(row)
                    for row in cursor.fetchall()
                ]
            finally:
                cursor.close()
        finally:
            self._close_quietly(connection)

    def get_head(
        self,
        tenant_id: UUID,
    ) -> tuple[int, bytes] | None:
        if not isinstance(tenant_id, UUID):
            raise TypeError("tenant_id must be UUID")

        connection = self._connection_factory()

        try:
            placeholder = self._placeholder(connection)

            cursor = connection.cursor()
            try:
                cursor.execute(
                    f"""
                    SELECT sequence_number, current_hash
                    FROM tenant_chain_heads
                    WHERE tenant_id = {placeholder}
                    """,
                    (str(tenant_id),),
                )

                row = cursor.fetchone()

                if row is None:
                    return None

                return int(row[0]), bytes(row[1])
            finally:
                cursor.close()
        finally:
            self._close_quietly(connection)

    @staticmethod
    def _insert_record(
        connection: Any,
        record: AuditRecord,
    ) -> None:
        placeholder = "?" if _connection_is_sqlite(connection) else "%s"

        cursor = connection.cursor()
        try:
            cursor.execute(
                f"""
                INSERT INTO audit_records
                    (
                        tenant_id,
                        sequence_number,
                        audit_id,
                        prev_record_hash,
                        event_type,
                        payload_digest,
                        payload_raw,
                        recorded_at,
                        record_hash,
                        protocol_version
                    )
                VALUES
                    (
                        {placeholder},
                        {placeholder},
                        {placeholder},
                        {placeholder},
                        {placeholder},
                        {placeholder},
                        {placeholder},
                        {placeholder},
                        {placeholder},
                        {placeholder}
                    )
                """,
                (
                    str(record.tenant_id),
                    record.sequence_number,
                    str(record.audit_id),
                    record.prev_record_hash,
                    record.event_type,
                    record.payload_digest,
                    record.payload_raw,
                    _datetime_to_storage(record.recorded_at),
                    record.record_hash,
                    record.protocol_version,
                ),
            )
        finally:
            cursor.close()

    @staticmethod
    def _row_to_record(row: Any) -> AuditRecord:
        return AuditRecord(
            audit_id=UUID(str(row[0])),
            tenant_id=UUID(str(row[1])),
            sequence_number=int(row[2]),
            prev_record_hash=bytes(row[3]),
            event_type=str(row[4]),
            payload_digest=bytes(row[5]),
            payload_raw=bytes(row[6]),
            recorded_at=_datetime_from_storage(row[7]),
            record_hash=bytes(row[8]),
            protocol_version=int(row[9]),
        )


class ForensicAuditVerifier:
    @staticmethod
    def _failure(
        code: str,
        tenant_id: UUID,
        sequence_number: int | None,
        expected: Any | None,
        actual: Any | None,
        message: str,
    ) -> VerificationFailure:
        return VerificationFailure(
            code=code,
            tenant_id=tenant_id,
            sequence_number=sequence_number,
            expected=expected,
            actual=actual,
            message=message,
        )

    @classmethod
    def verify_chain(
        cls,
        tenant_id: UUID,
        records: list[AuditRecord],
        expected_head: AuditCheckpoint | None = None,
    ) -> VerificationResult:
        if not isinstance(tenant_id, UUID):
            raise TypeError("tenant_id must be UUID")

        failures: list[VerificationFailure] = []

        if expected_head is not None and expected_head.tenant_id != tenant_id:
            failures.append(
                cls._failure(
                    code="CHECKPOINT_TENANT_MISMATCH",
                    tenant_id=tenant_id,
                    sequence_number=None,
                    expected=tenant_id,
                    actual=expected_head.tenant_id,
                    message="checkpoint belongs to a different tenant",
                )
            )

        if not records:
            failures.append(
                cls._failure(
                    code="GENESIS_MISSING",
                    tenant_id=tenant_id,
                    sequence_number=None,
                    expected=0,
                    actual=None,
                    message="audit chain contains no records",
                )
            )

            status = (
                VerificationStatus.INVALID
                if expected_head is None
                else VerificationStatus.INCOMPLETE
            )

            return VerificationResult(
                status=status,
                tenant_id=tenant_id,
                records_verified=0,
                first_failure=failures[0],
                failures=tuple(failures),
                head_sequence=None,
                head_hash=None,
            )

        ordered_records = list(records)

        head_sequence = ordered_records[-1].sequence_number
        head_hash = ordered_records[-1].record_hash

        first = ordered_records[0]

        genesis_valid = True

        if first.tenant_id != tenant_id:
            genesis_valid = False
            failures.append(
                cls._failure(
                    code="TENANT_MISMATCH",
                    tenant_id=tenant_id,
                    sequence_number=first.sequence_number,
                    expected=tenant_id,
                    actual=first.tenant_id,
                    message="record belongs to a different tenant",
                )
            )

        if first.sequence_number != 0:
            genesis_valid = False
            failures.append(
                cls._failure(
                    code="GENESIS_SEQUENCE_INVALID",
                    tenant_id=tenant_id,
                    sequence_number=first.sequence_number,
                    expected=0,
                    actual=first.sequence_number,
                    message="first record is not sequence zero",
                )
            )

        if first.prev_record_hash != ZERO_HASH:
            genesis_valid = False
            failures.append(
                cls._failure(
                    code="GENESIS_PREV_HASH_INVALID",
                    tenant_id=tenant_id,
                    sequence_number=first.sequence_number,
                    expected=ZERO_HASH,
                    actual=first.prev_record_hash,
                    message="genesis predecessor hash is not ZERO_HASH",
                )
            )

        if first.event_type != "GENESIS":
            genesis_valid = False
            failures.append(
                cls._failure(
                    code="GENESIS_EVENT_TYPE_INVALID",
                    tenant_id=tenant_id,
                    sequence_number=first.sequence_number,
                    expected="GENESIS",
                    actual=first.event_type,
                    message="genesis event type is invalid",
                )
            )

        try:
            expected_genesis_payload_digest = compute_payload_digest(
                first.payload_raw
            )
        except Exception as exc:
            genesis_valid = False
            failures.append(
                cls._failure(
                    code="GENESIS_PAYLOAD_INVALID",
                    tenant_id=tenant_id,
                    sequence_number=first.sequence_number,
                    expected=None,
                    actual=type(exc).__name__,
                    message="genesis payload cannot be canonicalized",
                )
            )
            expected_genesis_payload_digest = None

        if (
            expected_genesis_payload_digest is not None
            and first.payload_digest != expected_genesis_payload_digest
        ):
            genesis_valid = False
            failures.append(
                cls._failure(
                    code="PAYLOAD_DIGEST_MISMATCH",
                    tenant_id=tenant_id,
                    sequence_number=first.sequence_number,
                    expected=expected_genesis_payload_digest,
                    actual=first.payload_digest,
                    message="genesis payload digest does not match payload",
                )
            )

        try:
            expected_genesis_hash = compute_record_hash(
                tenant_id=first.tenant_id,
                sequence_number=first.sequence_number,
                prev_record_hash=first.prev_record_hash,
                event_type=first.event_type,
                payload_digest=first.payload_digest,
                recorded_at=first.recorded_at,
            )
        except Exception as exc:
            genesis_valid = False
            failures.append(
                cls._failure(
                    code="GENESIS_HASH_COMPUTATION_FAILED",
                    tenant_id=tenant_id,
                    sequence_number=first.sequence_number,
                    expected=None,
                    actual=type(exc).__name__,
                    message="genesis record hash could not be recomputed",
                )
            )
            expected_genesis_hash = None

        if (
            expected_genesis_hash is not None
            and first.record_hash != expected_genesis_hash
        ):
            genesis_valid = False
            failures.append(
                cls._failure(
                    code="RECORD_HASH_MISMATCH",
                    tenant_id=tenant_id,
                    sequence_number=first.sequence_number,
                    expected=expected_genesis_hash,
                    actual=first.record_hash,
                    message="genesis record hash is invalid",
                )
            )

        if not genesis_valid:
            status = VerificationStatus.UNTRUSTED_GENESIS

            return VerificationResult(
                status=status,
                tenant_id=tenant_id,
                records_verified=0,
                first_failure=failures[0],
                failures=tuple(failures),
                head_sequence=head_sequence,
                head_hash=head_hash,
            )

        records_verified = 1

        previous = first

        for index in range(1, len(ordered_records)):
            record = ordered_records[index]

            if record.tenant_id != tenant_id:
                failures.append(
                    cls._failure(
                        code="TENANT_MISMATCH",
                        tenant_id=tenant_id,
                        sequence_number=record.sequence_number,
                        expected=tenant_id,
                        actual=record.tenant_id,
                        message="record belongs to a different tenant",
                    )
                )
                continue

            if record.sequence_number <= previous.sequence_number:
                failures.append(
                    cls._failure(
                        code="SEQUENCE_NOT_MONOTONIC",
                        tenant_id=tenant_id,
                        sequence_number=record.sequence_number,
                        expected=previous.sequence_number + 1,
                        actual=record.sequence_number,
                        message="sequence numbers are not strictly increasing",
                    )
                )
            elif record.sequence_number != previous.sequence_number + 1:
                failures.append(
                    cls._failure(
                        code="SEQUENCE_GAP",
                        tenant_id=tenant_id,
                        sequence_number=record.sequence_number,
                        expected=previous.sequence_number + 1,
                        actual=record.sequence_number,
                        message="audit chain contains a sequence gap",
                    )
                )

            if record.prev_record_hash != previous.record_hash:
                failures.append(
                    cls._failure(
                        code="HASH_LINK_MISMATCH",
                        tenant_id=tenant_id,
                        sequence_number=record.sequence_number,
                        expected=previous.record_hash,
                        actual=record.prev_record_hash,
                        message="record predecessor hash does not match prior record hash",
                    )
                )

            try:
                expected_payload_digest = compute_payload_digest(
                    record.payload_raw
                )

                if record.payload_digest != expected_payload_digest:
                    failures.append(
                        cls._failure(
                            code="PAYLOAD_DIGEST_MISMATCH",
                            tenant_id=tenant_id,
                            sequence_number=record.sequence_number,
                            expected=expected_payload_digest,
                            actual=record.payload_digest,
                            message="payload digest does not match payload",
                        )
                    )
            except Exception as exc:
                failures.append(
                    cls._failure(
                        code="PAYLOAD_INVALID",
                        tenant_id=tenant_id,
                        sequence_number=record.sequence_number,
                        expected=None,
                        actual=type(exc).__name__,
                        message="payload cannot be canonicalized",
                    )
                )

            try:
                expected_record_hash = compute_record_hash(
                    tenant_id=record.tenant_id,
                    sequence_number=record.sequence_number,
                    prev_record_hash=record.prev_record_hash,
                    event_type=record.event_type,
                    payload_digest=record.payload_digest,
                    recorded_at=record.recorded_at,
                )

                if record.record_hash != expected_record_hash:
                    failures.append(
                        cls._failure(
                            code="RECORD_HASH_MISMATCH",
                            tenant_id=tenant_id,
                            sequence_number=record.sequence_number,
                            expected=expected_record_hash,
                            actual=record.record_hash,
                            message="record hash does not match canonical record material",
                        )
                    )
            except Exception as exc:
                failures.append(
                    cls._failure(
                        code="RECORD_HASH_COMPUTATION_FAILED",
                        tenant_id=tenant_id,
                        sequence_number=record.sequence_number,
                        expected=None,
                        actual=type(exc).__name__,
                        message="record hash could not be recomputed",
                    )
                )

            records_verified += 1
            previous = record

        if expected_head is not None:
            if ordered_records[-1].sequence_number != expected_head.sequence_number:
                failures.append(
                    cls._failure(
                        code="CHECKPOINT_SEQUENCE_MISMATCH",
                        tenant_id=tenant_id,
                        sequence_number=ordered_records[-1].sequence_number,
                        expected=expected_head.sequence_number,
                        actual=ordered_records[-1].sequence_number,
                        message="final record does not reach the expected checkpoint sequence",
                    )
                )

            if ordered_records[-1].record_hash != expected_head.record_hash:
                failures.append(
                    cls._failure(
                        code="CHECKPOINT_HASH_MISMATCH",
                        tenant_id=tenant_id,
                        sequence_number=ordered_records[-1].sequence_number,
                        expected=expected_head.record_hash,
                        actual=ordered_records[-1].record_hash,
                        message="final record does not match the expected checkpoint hash",
                    )
                )

        if failures:
            incomplete_codes = {
                "CHECKPOINT_SEQUENCE_MISMATCH",
                "CHECKPOINT_HASH_MISMATCH",
            }

            if all(
                failure.code in incomplete_codes
                for failure in failures
            ):
                status = VerificationStatus.INCOMPLETE
            else:
                status = VerificationStatus.INVALID
        else:
            status = VerificationStatus.VALID

        return VerificationResult(
            status=status,
            tenant_id=tenant_id,
            records_verified=records_verified,
            first_failure=failures[0] if failures else None,
            failures=tuple(failures),
            head_sequence=head_sequence,
            head_hash=head_hash,
        )


__all__ = [
    "DOMAIN_SEPARATOR",
    "ZERO_HASH",
    "_encode_field",
    "canonicalize_payload",
    "compute_payload_digest",
    "compute_record_hash",
    "AuditRecord",
    "AuditCheckpoint",
    "VerificationStatus",
    "VerificationFailure",
    "VerificationResult",
    "ForensicAuditStore",
    "ForensicAuditVerifier",
]