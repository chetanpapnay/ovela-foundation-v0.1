from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.forensic_audit import (
    AuditCheckpoint,
    AuditRecord,
    ForensicAuditStore,
    ForensicAuditVerifier,
    VerificationStatus,
    compute_payload_digest,
    compute_record_hash,
)


@pytest.fixture
def sqlite_database():
    uri = f"file:forensic_audit_{uuid4().hex}?mode=memory&cache=shared"
    keeper = sqlite3.connect(
        uri,
        uri=True,
        check_same_thread=False,
    )

    try:
        yield uri
    finally:
        keeper.close()


@pytest.fixture
def store(sqlite_database):
    def connection_factory():
        return sqlite3.connect(
            sqlite_database,
            uri=True,
            check_same_thread=False,
        )

    return ForensicAuditStore(connection_factory)


@pytest.fixture
def tenant_id():
    return uuid4()


@pytest.fixture
def other_tenant_id():
    return uuid4()


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=123456)


def _build_chain(
    store: ForensicAuditStore,
    tenant_id,
    count: int = 5,
):
    now = _now()

    genesis = store.initialize_genesis(
        tenant_id=tenant_id,
        now=now,
    )

    records = [genesis]

    for sequence in range(1, count + 1):
        record = store.append_event(
            tenant_id=tenant_id,
            event_type=f"EVENT_{sequence}",
            payload={
                "sequence": sequence,
                "value": f"value-{sequence}",
            },
            now=now + timedelta(seconds=sequence),
        )
        records.append(record)

    return records


def _codes(result):
    return {failure.code for failure in result.failures}


def _failure_for_sequence(result, sequence_number):
    return [
        failure
        for failure in result.failures
        if failure.sequence_number == sequence_number
    ]


def test_valid_genesis_passes_verification(store, tenant_id):
    now = _now()

    genesis = store.initialize_genesis(
        tenant_id=tenant_id,
        now=now,
    )

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=[genesis],
    )

    assert result.status is VerificationStatus.VALID
    assert result.records_verified == 1
    assert result.first_failure is None
    assert result.failures == ()
    assert result.head_sequence == 0
    assert result.head_hash == genesis.record_hash
    assert genesis.sequence_number == 0
    assert genesis.prev_record_hash == b"\x00" * 32
    assert genesis.event_type == "GENESIS"


def test_genesis_tampering_is_detected(store, tenant_id):
    records = _build_chain(store, tenant_id, count=2)
    genesis = records[0]

    tampered_payload = genesis.payload_raw[:-1] + bytes(
        [genesis.payload_raw[-1] ^ 0x01]
    )

    tampered_genesis = replace(
        genesis,
        payload_raw=tampered_payload,
    )

    tampered_records = [tampered_genesis, records[1]]

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=tampered_records,
    )

    assert result.status is VerificationStatus.UNTRUSTED_GENESIS

    codes = _codes(result)

    assert codes & {
        "GENESIS_HASH_MISMATCH",
        "GENESIS_INVALID",
        "PAYLOAD_DIGEST_MISMATCH",
        "RECORD_HASH_MISMATCH",
    }

    assert result.first_failure is not None
    assert result.first_failure.sequence_number == 0


def test_genesis_hash_tampering_is_detected(store, tenant_id):
    records = _build_chain(store, tenant_id, count=1)
    genesis = records[0]

    tampered_hash = bytes(
        byte ^ 0xFF
        for byte in genesis.record_hash
    )

    tampered_genesis = replace(
        genesis,
        record_hash=tampered_hash,
    )

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=[tampered_genesis, records[1]],
    )

    assert result.status is VerificationStatus.UNTRUSTED_GENESIS
    assert result.first_failure is not None
    assert result.first_failure.sequence_number == 0
    assert _codes(result) & {
        "GENESIS_HASH_MISMATCH",
        "GENESIS_INVALID",
        "RECORD_HASH_MISMATCH",
    }


def test_normal_chain_0_to_3_is_valid(store, tenant_id):
    records = _build_chain(store, tenant_id, count=3)

    assert [record.sequence_number for record in records] == [
        0,
        1,
        2,
        3,
    ]

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=records,
    )

    assert result.status is VerificationStatus.VALID
    assert result.records_verified == 4
    assert result.first_failure is None
    assert result.failures == ()
    assert result.head_sequence == 3
    assert result.head_hash == records[-1].record_hash


def test_interior_record_deletion_detects_sequence_gap_and_broken_link(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=3)

    truncated = [
        records[0],
        records[1],
        records[3],
    ]

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=truncated,
    )

    assert result.status is VerificationStatus.INVALID

    failure_codes = _codes(result)

    assert failure_codes & {
        "SEQUENCE_GAP",
        "SEQUENCE_NOT_MONOTONIC",
    }

    assert failure_codes & {
        "PREVIOUS_HASH_MISMATCH",
        "HASH_LINK_MISMATCH",
    }

    sequence_two_failures = _failure_for_sequence(
        result,
        3,
    )

    assert sequence_two_failures


def test_duplicate_sequence_number_is_detected(store, tenant_id):
    records = _build_chain(store, tenant_id, count=3)

    duplicated_sequence_record = replace(
        records[2],
        sequence_number=1,
    )

    duplicated = [
        records[0],
        records[1],
        duplicated_sequence_record,
        records[3],
    ]

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=duplicated,
    )

    assert result.status is VerificationStatus.INVALID
    assert _codes(result) & {
        "SEQUENCE_DUPLICATE",
        "SEQUENCE_NOT_MONOTONIC",
    }

    assert result.first_failure is not None
    assert result.first_failure.sequence_number == 1


def test_historical_payload_one_byte_tampering_is_detected(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=3)

    target = records[2]

    tampered_payload = bytearray(target.payload_raw)
    tampered_payload[0] ^= 0x01

    tampered_target = replace(
        target,
        payload_raw=bytes(tampered_payload),
    )

    tampered_records = [
        records[0],
        records[1],
        tampered_target,
        records[3],
    ]

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=tampered_records,
    )

    assert result.status is VerificationStatus.INVALID

    failures = _failure_for_sequence(result, 2)

    assert failures

    assert any(
        failure.code == "PAYLOAD_DIGEST_MISMATCH"
        for failure in failures
    )


def test_recalculated_record_hash_without_downstream_update_breaks_child_link(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=3)

    target = records[1]

    recalculated_hash = compute_record_hash(
        tenant_id=target.tenant_id,
        sequence_number=target.sequence_number,
        prev_record_hash=target.prev_record_hash,
        event_type=target.event_type,
        payload_digest=target.payload_digest,
        recorded_at=target.recorded_at,
    )

    forged_hash = bytes(
        [recalculated_hash[0] ^ 0x01]
    ) + recalculated_hash[1:]

    forged_target = replace(
        target,
        record_hash=forged_hash,
    )

    forged_records = [
        records[0],
        forged_target,
        records[2],
        records[3],
    ]

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=forged_records,
    )

    assert result.status is VerificationStatus.INVALID

    child_failures = _failure_for_sequence(result, 2)

    assert child_failures

    assert any(
        failure.code in {
            "PREVIOUS_HASH_MISMATCH",
            "HASH_LINK_MISMATCH",
        }
        for failure in child_failures
    )


def test_cross_tenant_record_injection_is_detected(
    store,
    tenant_id,
    other_tenant_id,
):
    tenant_a_records = _build_chain(
        store,
        tenant_id,
        count=3,
    )

    tenant_b_records = _build_chain(
        store,
        other_tenant_id,
        count=1,
    )

    injected = replace(
        tenant_b_records[1],
        sequence_number=2,
    )

    injected_records = [
        tenant_a_records[0],
        tenant_a_records[1],
        injected,
        tenant_a_records[3],
    ]

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=injected_records,
    )

    assert result.status is VerificationStatus.INVALID

    failure_codes = _codes(result)

    assert failure_codes & {
        "CROSS_TENANT_RECORD",
        "TENANT_MISMATCH",
    }

    assert result.first_failure is not None
    assert result.first_failure.sequence_number == 2


def test_cross_tenant_genesis_injection_is_rejected(
    store,
    tenant_id,
    other_tenant_id,
):
    tenant_a_genesis = store.initialize_genesis(
        tenant_id=tenant_id,
        now=_now(),
    )

    tenant_b_genesis = store.initialize_genesis(
        tenant_id=other_tenant_id,
        now=_now() + timedelta(seconds=1),
    )

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=[
            tenant_b_genesis,
            tenant_a_genesis,
        ],
    )

    assert result.status is VerificationStatus.UNTRUSTED_GENESIS
    assert result.first_failure is not None
    assert result.first_failure.sequence_number == 0
    assert _codes(result) & {
        "CROSS_TENANT_RECORD",
        "TENANT_MISMATCH",
    }


def test_tail_truncation_against_checkpoint_is_detected(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=5)

    checkpoint = AuditCheckpoint(
        checkpoint_id=uuid4(),
        tenant_id=tenant_id,
        sequence_number=5,
        record_hash=records[5].record_hash,
        created_at=records[5].recorded_at,
    )

    attacker_view = records[:4]

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=attacker_view,
        expected_head=checkpoint,
    )

    assert result.status is VerificationStatus.INCOMPLETE

    failure_codes = _codes(result)

    assert failure_codes & {
        "TAIL_TRUNCATION",
        "HEAD_MISMATCH",
        "CHECKPOINT_SEQUENCE_MISMATCH",
    }

    assert failure_codes & {
        "TAIL_TRUNCATION",
        "HEAD_MISMATCH",
        "CHECKPOINT_HASH_MISMATCH",
    }

    assert result.head_sequence == 3
    assert result.head_hash == records[3].record_hash


def test_checkpoint_tenant_mismatch_is_rejected(
    store,
    tenant_id,
    other_tenant_id,
):
    records = _build_chain(store, tenant_id, count=2)

    checkpoint = AuditCheckpoint(
        checkpoint_id=uuid4(),
        tenant_id=other_tenant_id,
        sequence_number=2,
        record_hash=records[2].record_hash,
        created_at=records[2].recorded_at,
    )

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=records,
        expected_head=checkpoint,
    )

    assert result.status is VerificationStatus.INVALID
    assert _codes(result) & {
        "CHECKPOINT_TENANT_MISMATCH",
        "CROSS_TENANT_RECORD",
    }


def test_payload_digest_is_stable_for_exported_raw_payload(store, tenant_id):
    records = _build_chain(store, tenant_id, count=2)

    for record in records:
        assert compute_payload_digest(
            record.payload_raw
        ) == record.payload_digest


def test_offline_exported_records_verify_without_database_connection(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=5)

    exported_records = list(records)

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=exported_records,
    )

    assert result.status is VerificationStatus.VALID
    assert result.records_verified == 6
    assert result.head_sequence == 5
    assert result.head_hash == records[-1].record_hash


def test_verifier_does_not_require_database_store(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=3)

    del store

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=records,
    )

    assert result.status is VerificationStatus.VALID
    assert result.records_verified == 4


def test_store_genesis_initialization_is_idempotent(
    store,
    tenant_id,
):
    now = _now()

    first = store.initialize_genesis(
        tenant_id=tenant_id,
        now=now,
    )

    second = store.initialize_genesis(
        tenant_id=tenant_id,
        now=now + timedelta(seconds=5),
    )

    assert second == first

    records = store.get_records(tenant_id)

    assert len(records) == 1
    assert records[0] == first

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=records,
    )

    assert result.status is VerificationStatus.VALID


def test_append_event_requires_initialized_chain(
    store,
    tenant_id,
):
    with pytest.raises(RuntimeError):
        store.append_event(
            tenant_id=tenant_id,
            event_type="UNINITIALIZED_EVENT",
            payload={"value": 1},
            now=_now(),
        )


def test_concurrent_append_produces_contiguous_single_chain(
    store,
    tenant_id,
):
    store.initialize_genesis(
        tenant_id=tenant_id,
        now=_now(),
    )

    barrier = threading.Barrier(20)

    def append_one(index: int):
        barrier.wait()

        return store.append_event(
            tenant_id=tenant_id,
            event_type="CONCURRENT_EVENT",
            payload={
                "worker": index,
                "operation": "append",
            },
            now=_now() + timedelta(microseconds=index + 1),
        )

    records = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(append_one, index)
            for index in range(20)
        ]

        for future in as_completed(futures):
            records.append(future.result())

    records.sort(key=lambda record: record.sequence_number)

    assert len(records) == 20

    assert [
        record.sequence_number
        for record in records
    ] == list(range(1, 21))

    assert len({
        record.sequence_number
        for record in records
    }) == 20

    assert len({
        record.record_hash
        for record in records
    }) == 20

    assert records[0].prev_record_hash == (
        store.get_record(tenant_id, 0).record_hash
    )

    for previous, current in zip(records, records[1:]):
        assert current.sequence_number == previous.sequence_number + 1
        assert current.prev_record_hash == previous.record_hash

    exported_chain = store.get_records(tenant_id)

    assert [
        record.sequence_number
        for record in exported_chain
    ] == list(range(0, 21))

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=exported_chain,
    )

    assert result.status is VerificationStatus.VALID
    assert result.records_verified == 21
    assert result.first_failure is None
    assert result.failures == ()
    assert result.head_sequence == 20
    assert result.head_hash == exported_chain[-1].record_hash


def test_concurrent_append_does_not_create_forks(
    store,
    tenant_id,
):
    store.initialize_genesis(
        tenant_id=tenant_id,
        now=_now(),
    )

    barrier = threading.Barrier(20)

    def append_one(index: int):
        barrier.wait()

        return store.append_event(
            tenant_id=tenant_id,
            event_type=f"THREAD_{index}",
            payload={"thread": index},
            now=_now() + timedelta(microseconds=index + 1),
        )

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(append_one, index)
            for index in range(20)
        ]

        returned_records = [
            future.result()
            for future in as_completed(futures)
        ]

    assert len(returned_records) == 20

    returned_by_sequence = {
        record.sequence_number: record
        for record in returned_records
    }

    assert sorted(returned_by_sequence) == list(range(1, 21))

    for sequence in range(2, 21):
        current = returned_by_sequence[sequence]
        previous = returned_by_sequence[sequence - 1]

        assert current.prev_record_hash == previous.record_hash

    stored_records = store.get_records(tenant_id)

    assert len(stored_records) == 21

    for sequence, record in enumerate(stored_records):
        assert record.sequence_number == sequence

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=stored_records,
    )

    assert result.status is VerificationStatus.VALID
    assert result.failures == ()


def test_duplicate_record_hash_is_detected_by_storage(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=2)

    connection = store._connection_factory()

    try:
        with pytest.raises(sqlite3.IntegrityError):
            cursor = connection.cursor()
            try:
                record = records[1]

                cursor.execute(
                    """
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
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        str(record.tenant_id),
                        99,
                        str(uuid4()),
                        record.prev_record_hash,
                        record.event_type,
                        record.payload_digest,
                        record.payload_raw,
                        int(
                            record.recorded_at.timestamp() * 1_000_000
                        ),
                        record.record_hash,
                        record.protocol_version,
                    ),
                )
                connection.commit()
            finally:
                cursor.close()
    finally:
        connection.close()


def test_hash_link_tampering_is_pinned_to_child_sequence(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=4)

    forged_parent = replace(
        records[2],
        record_hash=bytes(
            [records[2].record_hash[0] ^ 0x80]
        ) + records[2].record_hash[1:],
    )

    forged_chain = [
        records[0],
        records[1],
        forged_parent,
        records[3],
        records[4],
    ]

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=forged_chain,
    )

    assert result.status is VerificationStatus.INVALID

    child_failures = _failure_for_sequence(result, 3)

    assert child_failures

    assert any(
        failure.code in {
            "PREVIOUS_HASH_MISMATCH",
            "HASH_LINK_MISMATCH",
        }
        for failure in child_failures
    )


def test_record_hash_recomputation_is_deterministic(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=3)

    for record in records:
        recomputed = compute_record_hash(
            tenant_id=record.tenant_id,
            sequence_number=record.sequence_number,
            prev_record_hash=record.prev_record_hash,
            event_type=record.event_type,
            payload_digest=record.payload_digest,
            recorded_at=record.recorded_at,
        )

        assert recomputed == record.record_hash


def test_payload_digest_tampering_without_payload_change_is_detected(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=2)

    target = records[1]

    forged_digest = bytes(
        [target.payload_digest[0] ^ 0x01]
    ) + target.payload_digest[1:]

    forged_record = replace(
        target,
        payload_digest=forged_digest,
    )

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=[
            records[0],
            forged_record,
            records[2],
        ],
    )

    assert result.status is VerificationStatus.INVALID

    failures = _failure_for_sequence(result, 1)

    assert failures

    assert any(
        failure.code == "PAYLOAD_DIGEST_MISMATCH"
        for failure in failures
    )


def test_record_tenant_tampering_is_detected(
    store,
    tenant_id,
    other_tenant_id,
):
    records = _build_chain(store, tenant_id, count=3)

    target = records[2]

    forged_record = replace(
        target,
        tenant_id=other_tenant_id,
    )

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=[
            records[0],
            records[1],
            forged_record,
            records[3],
        ],
    )

    assert result.status is VerificationStatus.INVALID

    failures = _failure_for_sequence(result, 2)

    assert failures

    assert any(
        failure.code in {
            "CROSS_TENANT_RECORD",
            "TENANT_MISMATCH",
        }
        for failure in failures
    )


def test_offline_verification_is_reproducible_across_multiple_runs(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=5)

    first = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=list(records),
    )

    second = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=list(records),
    )

    assert first == second
    assert first.status is VerificationStatus.VALID
    assert first.records_verified == 6


def test_expected_checkpoint_matching_exact_head_is_valid(
    store,
    tenant_id,
):
    records = _build_chain(store, tenant_id, count=5)

    checkpoint = AuditCheckpoint(
        checkpoint_id=uuid4(),
        tenant_id=tenant_id,
        sequence_number=5,
        record_hash=records[5].record_hash,
        created_at=records[5].recorded_at,
    )

    result = ForensicAuditVerifier.verify_chain(
        tenant_id=tenant_id,
        records=records,
        expected_head=checkpoint,
    )

    assert result.status is VerificationStatus.VALID
    assert result.first_failure is None
    assert result.failures == ()
    assert result.head_sequence == 5
    assert result.head_hash == records[5].record_hash