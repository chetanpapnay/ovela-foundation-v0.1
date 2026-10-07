"""Tests for ``app/rail_adapters.py`` (Milestone M8).

Every test runs against a real SQLite database file created under pytest's
``tmp_path``. The M6 ``DurableTransactionEngine`` and the M8
``RailEventReconciliationService`` each open one connection per DB operation,
so a plain ``:memory:`` database (private to a single connection) would not be
shared. A tmp-path file gives the same zero-setup, fast, fully isolated
behaviour. Tables are created dynamically by ``ensure_schema()``. Every
connection opened here is closed explicitly, so the suite is clean under
``python -W error -m pytest``.

Scenarios covered:

1. HMAC signature verification (valid, tampered, malformed/empty).
2. Pathological adapter modes (TIMEOUT / CONNECTION_RESET -> UNKNOWN,
   definitive reject -> REJECTED, queue acceptance -> PENDING) plus the
   fail-closed helpers and the M7 bridge.
3. Monetary binding and security invariants (amount / currency tampering is a
   ``RECONCILIATION_CONFLICT`` with zero state changes).
4. Webhook idempotency (five deliveries -> one transition, no extra side effects).
5. State transitions through the real M6 engine (SUBMITTED -> SETTLED/FAILED,
   UNKNOWN -> SETTLED/FAILED, terminal monotonicity).
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import hmac
import json
import sqlite3
import threading
from contextlib import closing
from dataclasses import FrozenInstanceError, dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import pytest

import app.rail_adapters as rail_module
from app.outbox_dispatcher import PaymentInstruction, RailDispatchStatus
from app.rail_adapters import (
    RESULT_CONFLICT,
    RESULT_DEFERRED,
    RESULT_DUPLICATE,
    RESULT_NO_STATE_CHANGE,
    RESULT_NOOP_TERMINAL,
    RESULT_PROCESSED,
    RESULT_QUARANTINED,
    RESULT_UNSUPPORTED_STATUS,
    WEBHOOK_SIGNATURE_HEADER,
    WEBHOOK_STATUS_CONFLICT,
    WEBHOOK_STATUS_DEFERRED,
    WEBHOOK_STATUS_PROCESSED,
    WEBHOOK_STATUS_QUARANTINED,
    WEBHOOK_STATUS_RECEIVED,
    MockBankRailAdapter,
    MockRailMode,
    PaymentRailAdapterBridge,
    ProviderLinkConflictError,
    RailEventReconciliationService,
    RailIdempotencyConflictError,
    RailInstruction,
    RailSubmissionResult,
    RailSubmissionStatus,
    ReconciliationConflictError,
    ReconciliationError,
    VerifiedWebhookEvidence,
    WebhookVerificationError,
    coerce_submission_result,
    compute_webhook_signature,
    safe_submit,
    verify_webhook_signature,
)
from app.transaction_engine import (
    ConcurrentModificationError,
    DurableTransactionEngine,
    InvalidStateTransitionError,
    TransactionExecutionState,
    TransactionNotFoundError,
)

S = TransactionExecutionState
NOW = datetime(2030, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
TENANT = UUID("11111111-1111-4111-8111-111111111111")
OTHER_TENANT = UUID("22222222-2222-4222-8222-222222222222")
SECRET = b"super-secret-webhook-key"
PROVIDER = "mockbank"

BODY = b'{"amount":"1000","currency":"USD"}'


# ---------------------------------------------------------------------------
# Test doubles and helpers
# ---------------------------------------------------------------------------


class FakeClock:
    """Mutable, timezone-aware clock."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kwargs: Any) -> None:
        self.now = self.now + timedelta(**kwargs)


@dataclass(frozen=True)
class FakeApprovalEvidence:
    """Duck-typed stand-in for ``ApprovalEvidence`` (the M6 engine only reads attributes)."""

    approval_id: str
    tenant_id: str
    action_id: str
    session_id: str
    subject_id: str
    destination_id: str
    amount: Any
    currency: str
    expires_at: datetime
    approved_at: datetime

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at

    def is_trusted(self) -> bool:
        return True


class AllowAllApprovalStore:
    """Approval store that always consumes successfully."""

    def consume(self, evidence: Any, now: datetime, tenant_id: Any = None, executor_id: Any = None) -> bool:
        return True


class EngineProxy:
    """Delegating engine wrapper that records ``transition_state`` calls."""

    def __init__(self, engine: DurableTransactionEngine) -> None:
        self.engine = engine
        self.transition_calls: List[Tuple[Tuple[Any, ...], Dict[str, Any]]] = []

    def get_execution(self, *args: Any, **kwargs: Any) -> Any:
        return self.engine.get_execution(*args, **kwargs)

    def get_intent(self, *args: Any, **kwargs: Any) -> Any:
        return self.engine.get_intent(*args, **kwargs)

    def transition_state(self, *args: Any, **kwargs: Any) -> Any:
        self.transition_calls.append((args, kwargs))
        return self.engine.transition_state(*args, **kwargs)


class FaultyEngine(EngineProxy):
    """Engine whose ``transition_state`` raises ``fault`` while it is set."""

    def __init__(self, engine: DurableTransactionEngine, fault: Optional[BaseException]) -> None:
        super().__init__(engine)
        self.fault = fault

    def transition_state(self, *args: Any, **kwargs: Any) -> Any:
        self.transition_calls.append((args, kwargs))
        if self.fault is not None:
            raise self.fault
        return self.engine.transition_state(*args, **kwargs)


class RacingEngine(EngineProxy):
    """A competing writer applies the transition first, then this caller loses the race."""

    def transition_state(self, *args: Any, **kwargs: Any) -> Any:
        self.transition_calls.append((args, kwargs))
        if len(self.transition_calls) == 1:
            self.engine.transition_state(*args, **kwargs)
            raise ConcurrentModificationError("lost race")
        return self.engine.transition_state(*args, **kwargs)


class AlwaysConflictingEngine(EngineProxy):
    """Every transition loses a race without changing anything."""

    def transition_state(self, *args: Any, **kwargs: Any) -> Any:
        self.transition_calls.append((args, kwargs))
        raise ConcurrentModificationError("perpetual contention")


def fetch_all(db_path: str, sql: str, params: Tuple[Any, ...] = ()) -> List[Tuple[Any, ...]]:
    with closing(sqlite3.connect(db_path)) as conn:
        cur = conn.cursor()
        try:
            cur.execute(sql, params)
            return cur.fetchall()
        finally:
            cur.close()


def execute_write(db_path: str, sql: str, params: Tuple[Any, ...] = ()) -> None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        try:
            cur.execute(sql, params)
        finally:
            cur.close()
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()


def count_rows(db_path: str, table: str, where: str = "") -> int:
    return int(fetch_all(db_path, f"SELECT COUNT(*) FROM {table} {where}")[0][0])


def snapshot(db_path: str) -> Dict[str, List[Tuple[Any, ...]]]:
    """Snapshot of every M6 table; used to prove an operation had zero side effects."""
    return {
        table: fetch_all(db_path, f"SELECT * FROM {table} ORDER BY 1")
        for table in (
            "payment_intents",
            "transaction_executions",
            "transaction_ledger_entries",
            "provider_outbox",
        )
    }


def event_rows(db_path: str) -> List[Tuple[Any, ...]]:
    return fetch_all(
        db_path,
        "SELECT idempotency_key, status, outcome FROM rail_webhook_events ORDER BY idempotency_key",
    )


PATHS: Dict[TransactionExecutionState, List[TransactionExecutionState]] = {
    S.CREATED: [],
    S.AUTHORIZED: [S.AUTHORIZED],
    S.APPROVED: [S.AUTHORIZED, S.APPROVED],
    S.RESERVED: [S.AUTHORIZED, S.APPROVED, S.RESERVED],
    S.SUBMITTED: [S.AUTHORIZED, S.APPROVED, S.RESERVED, S.SUBMITTED],
    S.UNKNOWN: [S.AUTHORIZED, S.APPROVED, S.RESERVED, S.UNKNOWN],
    S.SETTLED: [S.AUTHORIZED, S.APPROVED, S.RESERVED, S.SUBMITTED, S.SETTLED],
    S.FAILED: [S.FAILED],
}


def make_approval(intent: Any) -> FakeApprovalEvidence:
    return FakeApprovalEvidence(
        approval_id=intent.approval_id,
        tenant_id=intent.tenant_id,
        action_id=intent.action_id,
        session_id=intent.session_id,
        subject_id=intent.subject_id,
        destination_id=intent.destination_id,
        amount=intent.amount,
        currency=intent.currency,
        expires_at=NOW + timedelta(hours=1),
        approved_at=NOW - timedelta(minutes=5),
    )


def drive_to(engine: DurableTransactionEngine, intent: Any, state: TransactionExecutionState) -> Any:
    """Walk an execution from CREATED to ``state`` using only the public M6 engine API."""
    execution = engine.get_execution_for_intent(intent.payment_intent_id, intent.tenant_id)
    for step in PATHS[state]:
        if step is S.RESERVED:
            execution = engine.reserve_execution(
                intent.payment_intent_id,
                intent.tenant_id,
                make_approval(intent),
                AllowAllApprovalStore(),
                NOW,
                "executor-1",
            )
        else:
            execution = engine.transition_state(
                execution.transaction_execution_id, intent.tenant_id, step, now=NOW
            )
    return execution


def setup_execution(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    state: TransactionExecutionState,
    *,
    key: str = "a",
    amount: str = "1000",
    currency: str = "USD",
    tenant: UUID = TENANT,
    link: Optional[str] = "mbx-1",
) -> Tuple[Any, Any]:
    """Create an intent, drive its execution to ``state`` and link a provider execution id."""
    intent = engine.create_or_get_intent(
        tenant_id=str(tenant),
        action_id=f"action-{key}",
        session_id="session-1",
        subject_id="subject-1",
        amount=amount,
        currency=currency,
        destination_id="dest-1",
        idempotency_key=f"idem-{key}",
        security_context_id="secctx-1",
        approval_id=f"appr-{key}",
    )
    execution = drive_to(engine, intent, state)
    if link is not None:
        service.record_provider_execution(tenant, PROVIDER, link, execution.transaction_execution_id)
    return intent, execution


def rekey_execution(db_path: str, execution: Any) -> UUID:
    """Give an execution a UUID id so it can be correlated via ``transaction_execution_id``."""
    new_id = uuid4()
    execute_write(
        db_path,
        "UPDATE transaction_executions SET transaction_execution_id = ? "
        "WHERE transaction_execution_id = ?",
        (str(new_id), execution.transaction_execution_id),
    )
    return new_id


def make_evidence(
    adapter: MockBankRailAdapter,
    *,
    key: str = "wh-1",
    status: str = "SETTLED",
    amount: Any = "1000",
    currency: str = "USD",
    tenant: UUID = TENANT,
    provider_execution_id: Optional[str] = "mbx-1",
    transaction_execution_id: Optional[UUID] = None,
    event_type: str = "payment.update",
    provider_event_id: Optional[str] = None,
) -> VerifiedWebhookEvidence:
    """Build, sign and verify a webhook end to end through the mock adapter."""
    headers, raw_body = adapter.build_signed_webhook(
        tenant_id=tenant,
        idempotency_key=key,
        event_type=event_type,
        amount=amount,
        currency=currency,
        status=status,
        secret=SECRET,
        transaction_execution_id=transaction_execution_id,
        provider_execution_id=provider_execution_id,
        provider_event_id=provider_event_id,
    )
    return adapter.verify_webhook(headers, raw_body, SECRET)


def instruction(
    tx: str = "tx-1", amount: str = "1000", currency: str = "USD", dest: str = "dest-1"
) -> RailInstruction:
    return RailInstruction(
        transaction_id=tx, amount=Decimal(amount), currency=currency, destination_id=dest
    )


def make_result(status: RailSubmissionStatus, **overrides: Any) -> RailSubmissionResult:
    fields: Dict[str, Any] = dict(
        status=status,
        provider_execution_id=None,
        provider_reference=None,
        provider_code=None,
        provider_message=None,
        retryable=False,
        authoritative=True,
        observed_at=NOW,
    )
    fields.update(overrides)
    return RailSubmissionResult(**fields)


class StubRail:
    """Rail returning scripted outcomes; exceptions in the script are raised."""

    def __init__(self, *outcomes: Any) -> None:
        self.outcomes: List[Any] = list(outcomes)
        self.calls: List[Tuple[RailInstruction, str]] = []

    def submit(self, instruction: RailInstruction, idempotency_key: str) -> Any:
        self.calls.append((instruction, idempotency_key))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def run_concurrently(tasks: List[Callable[[], Any]]) -> List[Any]:
    """Run ``tasks`` in threads released together by a barrier; fail on any thread error."""
    barrier = threading.Barrier(len(tasks))
    results: List[Any] = [None] * len(tasks)
    errors: List[BaseException] = []

    def runner(index: int, task: Callable[[], Any]) -> None:
        try:
            barrier.wait(timeout=30)
            results[index] = task()
        except BaseException as exc:  # noqa: BLE001 - surfaced via assertion below
            errors.append(exc)

    threads = [
        threading.Thread(target=runner, args=(i, task), daemon=True) for i, task in enumerate(tasks)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert not any(thread.is_alive() for thread in threads), "worker thread did not finish"
    assert errors == []
    return results


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db_path(tmp_path: Any) -> str:
    return str(tmp_path / "rails.db")


@pytest.fixture
def connect(db_path: str) -> Callable[[], sqlite3.Connection]:
    def _connect() -> sqlite3.Connection:
        return sqlite3.connect(db_path, timeout=30)

    return _connect


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock(NOW)


@pytest.fixture
def adapter(clock: FakeClock) -> MockBankRailAdapter:
    return MockBankRailAdapter(clock=clock)


@pytest.fixture
def engine(connect: Callable[[], sqlite3.Connection], clock: FakeClock) -> DurableTransactionEngine:
    instance = DurableTransactionEngine(connect, dialect="sqlite", clock=clock)
    instance.ensure_schema()
    return instance


@pytest.fixture
def service(
    connect: Callable[[], sqlite3.Connection], engine: DurableTransactionEngine, clock: FakeClock
) -> RailEventReconciliationService:
    instance = RailEventReconciliationService(connect, engine, dialect="sqlite", clock=clock)
    instance.ensure_schema()
    return instance


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


def test_status_enums_are_str_enums() -> None:
    assert {s.value for s in RailSubmissionStatus} == {"ACCEPTED", "PENDING", "REJECTED", "UNKNOWN"}
    assert RailSubmissionStatus.UNKNOWN == "UNKNOWN"
    assert str(RailSubmissionStatus.REJECTED) == "REJECTED"
    assert isinstance(RailSubmissionStatus.PENDING, str)
    assert {m.value for m in MockRailMode} == {
        "NORMAL_ACCEPTED",
        "PENDING_QUEUE",
        "DEFINITIVE_REJECT",
        "RETRYABLE_ERROR",
        "TIMEOUT",
        "CONNECTION_RESET",
        "MALFORMED",
    }


def test_value_objects_are_frozen() -> None:
    result = make_result(RailSubmissionStatus.ACCEPTED)
    with pytest.raises(FrozenInstanceError):
        result.status = RailSubmissionStatus.REJECTED  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        instruction().amount = Decimal("1")  # type: ignore[misc]
    adapter = MockBankRailAdapter()
    evidence = make_evidence(adapter)
    with pytest.raises(FrozenInstanceError):
        evidence.amount = Decimal("1")  # type: ignore[misc]


# ---------------------------------------------------------------------------
# 1. HMAC signature verification
# ---------------------------------------------------------------------------


def good_signature(body: bytes = BODY, secret: bytes = SECRET) -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def verify(
    body: Any = BODY,
    signature: Any = None,
    secret: Any = SECRET,
    tenant: Any = TENANT,
    provider: Any = PROVIDER,
) -> bool:
    sig = good_signature() if signature is None else signature
    return verify_webhook_signature(tenant, provider, body, sig, secret)


def test_valid_signature_passes() -> None:
    assert verify() is True


def test_compute_signature_is_lowercase_hex_hmac_sha256_over_exact_bytes() -> None:
    signature = compute_webhook_signature(BODY, SECRET)
    assert signature == good_signature()
    assert len(signature) == 64
    assert signature == signature.lower()


@pytest.mark.parametrize(
    "variant",
    [
        lambda sig: sig.upper(),
        lambda sig: f"sha256={sig}",
        lambda sig: f"SHA256={sig}",
        lambda sig: f"  {sig}  ",
        lambda sig: base64.b64encode(bytes.fromhex(sig)).decode("ascii"),
    ],
    ids=["upper-hex", "prefixed", "prefixed-upper", "padded", "base64"],
)
def test_valid_signature_encodings_pass(variant: Callable[[str], str]) -> None:
    assert verify(signature=variant(good_signature())) is True


def test_bytearray_body_is_accepted() -> None:
    assert verify(body=bytearray(BODY)) is True


def test_signature_is_not_bound_to_tenant_or_provider_arguments() -> None:
    assert verify(tenant=OTHER_TENANT, provider="otherbank") is True


@pytest.mark.parametrize(
    "tampered",
    [
        b'{"amount":"10000","currency":"USD"}',
        b'{"amount":"1000","currency":"EUR"}',
        BODY + b" ",
        b" " + BODY,
        BODY[:-1],
        b"",
        json.dumps(json.loads(BODY)).encode("utf-8"),  # same JSON, different bytes
    ],
    ids=["amount", "currency", "trailing-space", "leading-space", "truncated", "empty", "reserialized"],
)
def test_tampered_payload_bytes_fail(tampered: bytes) -> None:
    assert verify(body=tampered, signature=good_signature(BODY)) is False


def test_wrong_secret_fails() -> None:
    assert verify(secret=b"another-secret") is False
    assert verify(signature=good_signature(BODY, b"another-secret")) is False


@pytest.mark.parametrize(
    "bad_signature",
    [
        "",
        "   ",
        "sha256=",
        "SHA256=   ",
        "not-hex-or-base64!",
        "zz" * 32,  # valid base64 alphabet, wrong decoded length
        "ab" * 16,  # hex but too short
        "ab" * 33,  # hex but too long
        "0" * 64,  # well-formed, wrong digest
        "g" * 64,  # not hex
        base64.b64encode(b"short").decode("ascii"),
        base64.b64encode(b"x" * 32).decode("ascii"),  # right length, wrong digest
        None,
        123,
        b"bytes-signature",
    ],
    ids=[
        "empty",
        "blank",
        "prefix-only",
        "prefix-blank",
        "garbage",
        "base64-wrong-length",
        "short-hex",
        "long-hex",
        "wrong-digest",
        "non-hex",
        "short-base64",
        "wrong-base64-digest",
        "none",
        "int",
        "bytes",
    ],
)
def test_malformed_or_empty_signature_fails(bad_signature: Any) -> None:
    assert verify_webhook_signature(TENANT, PROVIDER, BODY, bad_signature, SECRET) is False


@pytest.mark.parametrize(
    "kwargs",
    [
        {"secret": b""},
        {"secret": "not-bytes"},
        {"secret": None},
        {"body": "not-bytes"},
        {"body": None},
        {"tenant": "11111111-1111-4111-8111-111111111111"},
        {"tenant": None},
        {"provider": " "},
        {"provider": None},
    ],
    ids=[
        "empty-secret",
        "str-secret",
        "none-secret",
        "str-body",
        "none-body",
        "str-tenant",
        "none-tenant",
        "blank-provider",
        "none-provider",
    ],
)
def test_malformed_arguments_fail_closed(kwargs: Dict[str, Any]) -> None:
    assert verify(**kwargs) is False


def test_digest_comparison_is_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: List[Tuple[Any, Any]] = []
    original = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        calls.append((a, b))
        return original(a, b)

    monkeypatch.setattr(rail_module.hmac, "compare_digest", spy)
    assert verify() is True
    assert len(calls) == 1
    expected, provided = calls[0]
    assert isinstance(expected, bytes) and isinstance(provided, bytes)
    assert len(expected) == len(provided) == 32


def test_compute_signature_validates_arguments() -> None:
    with pytest.raises(TypeError):
        compute_webhook_signature("text", SECRET)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        compute_webhook_signature(BODY, b"")
    with pytest.raises(ValueError):
        compute_webhook_signature(BODY, "text")  # type: ignore[arg-type]


# -- adapter.verify_webhook -------------------------------------------------------------


def test_adapter_verify_webhook_returns_evidence_for_a_valid_signature(
    adapter: MockBankRailAdapter,
) -> None:
    tx = uuid4()
    headers, raw_body = adapter.build_signed_webhook(
        tenant_id=TENANT,
        idempotency_key="wh-1",
        event_type="payment.settled",
        amount="1000.00",
        currency="usd",
        status="SETTLED",
        secret=SECRET,
        transaction_execution_id=tx,
        provider_execution_id="mbx-1",
        provider_event_id="evt-1",
    )
    assert WEBHOOK_SIGNATURE_HEADER in headers
    evidence = adapter.verify_webhook(headers, raw_body, SECRET)
    assert isinstance(evidence.webhook_id, UUID)
    assert evidence.tenant_id == TENANT
    assert evidence.provider == PROVIDER
    assert evidence.idempotency_key == "wh-1"
    assert evidence.provider_event_id == "evt-1"
    assert evidence.event_type == "payment.settled"
    assert evidence.amount == Decimal("1000")
    assert evidence.currency == "USD"
    assert evidence.transaction_execution_id == tx
    assert evidence.provider_execution_id == "mbx-1"
    assert evidence.status == "SETTLED"
    assert evidence.received_at == NOW


def test_adapter_verify_webhook_header_name_is_case_insensitive(adapter: MockBankRailAdapter) -> None:
    headers, raw_body = adapter.build_signed_webhook(
        tenant_id=TENANT,
        idempotency_key="wh-1",
        event_type="e",
        amount="1",
        currency="USD",
        status="SETTLED",
        secret=SECRET,
    )
    lowered = {k.lower(): v for k, v in headers.items()}
    assert adapter.verify_webhook(lowered, raw_body, SECRET).idempotency_key == "wh-1"


def test_adapter_verify_webhook_rejects_tampered_body(adapter: MockBankRailAdapter) -> None:
    headers, raw_body = adapter.build_signed_webhook(
        tenant_id=TENANT,
        idempotency_key="wh-1",
        event_type="e",
        amount="1000",
        currency="USD",
        status="SETTLED",
        secret=SECRET,
    )
    tampered = raw_body.replace(b'"1000"', b'"10000"')
    assert tampered != raw_body
    with pytest.raises(WebhookVerificationError):
        adapter.verify_webhook(headers, tampered, SECRET)


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {WEBHOOK_SIGNATURE_HEADER: ""},
        {WEBHOOK_SIGNATURE_HEADER: "   "},
        {WEBHOOK_SIGNATURE_HEADER: "zz" * 32},
        {WEBHOOK_SIGNATURE_HEADER: "0" * 64},
        {"X-Other": "abc"},
    ],
    ids=["missing", "empty", "blank", "garbage", "wrong-digest", "wrong-header"],
)
def test_adapter_verify_webhook_rejects_missing_or_malformed_signature(
    adapter: MockBankRailAdapter, headers: Dict[str, str]
) -> None:
    with pytest.raises(WebhookVerificationError):
        adapter.verify_webhook(headers, BODY, SECRET)


def test_adapter_verify_webhook_rejects_wrong_secret_and_bad_arguments(
    adapter: MockBankRailAdapter,
) -> None:
    headers = adapter.sign_webhook(BODY, SECRET)
    with pytest.raises(WebhookVerificationError):
        adapter.verify_webhook(headers, BODY, b"other-secret")
    with pytest.raises(WebhookVerificationError):
        adapter.verify_webhook(headers, BODY, b"")
    with pytest.raises(WebhookVerificationError):
        adapter.verify_webhook("not-a-mapping", BODY, SECRET)  # type: ignore[arg-type]
    with pytest.raises(WebhookVerificationError):
        adapter.verify_webhook(headers, "text", SECRET)  # type: ignore[arg-type]


def valid_body(**overrides: Any) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "tenant_id": str(TENANT),
        "idempotency_key": "wh-1",
        "provider_event_id": None,
        "event_type": "payment.update",
        "amount": "1000",
        "currency": "USD",
        "transaction_execution_id": None,
        "provider_execution_id": "mbx-1",
        "status": "SETTLED",
    }
    body.update(overrides)
    return body


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff\xfe\x00",
        b"{not json",
        b"[1, 2, 3]",
        b'"just a string"',
        json.dumps(valid_body(tenant_id="not-a-uuid")).encode(),
        json.dumps(valid_body(tenant_id=None)).encode(),
        json.dumps(valid_body(transaction_execution_id="not-a-uuid")).encode(),
        json.dumps(valid_body(idempotency_key="")).encode(),
        json.dumps(valid_body(event_type=None)).encode(),
        json.dumps(valid_body(amount="0")).encode(),
        json.dumps(valid_body(amount="-5")).encode(),
        json.dumps(valid_body(amount="abc")).encode(),
        json.dumps(valid_body(amount=None)).encode(),
        json.dumps(valid_body(currency=" ")).encode(),
        json.dumps(valid_body(status="")).encode(),
        json.dumps(valid_body(provider_execution_id="  ")).encode(),
        json.dumps(valid_body(provider_event_id="  ")).encode(),
    ],
    ids=[
        "invalid-utf8",
        "invalid-json",
        "json-array",
        "json-string",
        "bad-tenant",
        "null-tenant",
        "bad-execution-id",
        "empty-idempotency-key",
        "null-event-type",
        "zero-amount",
        "negative-amount",
        "non-numeric-amount",
        "null-amount",
        "blank-currency",
        "empty-status",
        "blank-provider-execution-id",
        "blank-provider-event-id",
    ],
)
def test_adapter_verify_webhook_rejects_validly_signed_but_invalid_bodies(
    adapter: MockBankRailAdapter, raw: bytes
) -> None:
    headers = adapter.sign_webhook(raw, SECRET)
    with pytest.raises(WebhookVerificationError):
        adapter.verify_webhook(headers, raw, SECRET)


def test_build_signed_webhook_rejects_float_amounts(adapter: MockBankRailAdapter) -> None:
    with pytest.raises(ValueError):
        adapter.build_signed_webhook(
            tenant_id=TENANT,
            idempotency_key="wh-1",
            event_type="e",
            amount=1000.5,
            currency="USD",
            status="SETTLED",
            secret=SECRET,
        )


# ---------------------------------------------------------------------------
# 2. Adapter pathological failure modes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "mode,status,retryable,authoritative",
    [
        (MockRailMode.NORMAL_ACCEPTED, RailSubmissionStatus.ACCEPTED, False, True),
        (MockRailMode.PENDING_QUEUE, RailSubmissionStatus.PENDING, False, True),
        (MockRailMode.DEFINITIVE_REJECT, RailSubmissionStatus.REJECTED, False, True),
        (MockRailMode.RETRYABLE_ERROR, RailSubmissionStatus.UNKNOWN, True, False),
        (MockRailMode.TIMEOUT, RailSubmissionStatus.UNKNOWN, True, False),
        (MockRailMode.CONNECTION_RESET, RailSubmissionStatus.UNKNOWN, True, False),
    ],
    ids=["accepted", "pending", "reject", "retryable-error", "timeout", "connection-reset"],
)
def test_mode_to_status_mapping(
    clock: FakeClock,
    mode: MockRailMode,
    status: RailSubmissionStatus,
    retryable: bool,
    authoritative: bool,
) -> None:
    rail = MockBankRailAdapter(mode, clock=clock)
    result = rail.submit(instruction(), "idem-1")
    assert isinstance(result, RailSubmissionResult)
    assert result.status is status
    assert result.retryable is retryable
    assert result.authoritative is authoritative
    assert result.observed_at == NOW


@pytest.mark.parametrize(
    "mode,code",
    [(MockRailMode.TIMEOUT, "TIMEOUT"), (MockRailMode.CONNECTION_RESET, "CONNECTION_RESET")],
)
def test_timeout_and_connection_reset_map_strictly_to_unknown(
    clock: FakeClock, mode: MockRailMode, code: str
) -> None:
    rail = MockBankRailAdapter(mode, clock=clock)
    result = rail.submit(instruction(), "idem-1")
    assert result.status is RailSubmissionStatus.UNKNOWN
    assert result.retryable is True
    assert result.authoritative is False
    assert result.provider_code == code
    # Fail closed: never claims success or failure, so no provider identifiers either.
    assert result.provider_execution_id is None
    assert result.provider_reference is None


@pytest.mark.parametrize(
    "mode,exc_type",
    [
        (MockRailMode.TIMEOUT, TimeoutError),
        (MockRailMode.CONNECTION_RESET, ConnectionResetError),
    ],
)
def test_network_faults_can_raise_and_safe_submit_maps_them_to_unknown(
    clock: FakeClock, mode: MockRailMode, exc_type: type
) -> None:
    rail = MockBankRailAdapter(mode, clock=clock, raise_on_network_fault=True)
    with pytest.raises(exc_type):
        rail.submit(instruction(), "idem-1")

    result = safe_submit(rail, instruction(), "idem-1", clock=clock)
    assert result.status is RailSubmissionStatus.UNKNOWN
    assert result.retryable is True
    assert result.authoritative is False
    assert result.provider_code == f"ADAPTER_EXCEPTION:{exc_type.__name__}"
    assert result.observed_at == NOW


def test_definitive_reject_is_authoritative_and_not_retryable(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(MockRailMode.DEFINITIVE_REJECT, clock=clock, reject_code="ACCOUNT_CLOSED")
    result = rail.submit(instruction(), "idem-1")
    assert result.status is RailSubmissionStatus.REJECTED
    assert result.provider_code == "ACCOUNT_CLOSED"
    assert result.retryable is False
    assert result.authoritative is True
    assert result.provider_execution_id is None


def test_queue_acceptance_returns_pending_with_provider_identifiers(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(MockRailMode.PENDING_QUEUE, clock=clock)
    result = rail.submit(instruction(), "idem-1")
    assert result.status is RailSubmissionStatus.PENDING
    assert result.provider_code == "QUEUED"
    assert result.provider_execution_id is not None and result.provider_execution_id.startswith("mbx_")
    assert result.provider_reference is not None and result.provider_reference.startswith("ref_")


def test_accepted_ids_are_deterministic_per_idempotency_key(clock: FakeClock) -> None:
    one = MockBankRailAdapter(clock=clock).submit(instruction(), "idem-1")
    two = MockBankRailAdapter(clock=clock).submit(instruction(), "idem-1")
    other = MockBankRailAdapter(clock=clock).submit(instruction(), "idem-2")
    assert one.provider_execution_id == two.provider_execution_id
    assert one.provider_execution_id != other.provider_execution_id


def test_malformed_mode_returns_a_non_result_and_is_coerced_to_unknown(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(MockRailMode.MALFORMED, clock=clock)
    raw = rail.submit(instruction(), "idem-1")
    assert not isinstance(raw, RailSubmissionResult)

    result = safe_submit(rail, instruction(), "idem-1", clock=clock)
    assert result.status is RailSubmissionStatus.UNKNOWN
    assert result.provider_code == "MALFORMED_ADAPTER_RESULT"
    assert result.retryable is True and result.authoritative is False


def test_replay_with_same_key_returns_the_stored_outcome(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(MockRailMode.NORMAL_ACCEPTED, clock=clock)
    first = rail.submit(instruction(), "idem-1")
    clock.advance(minutes=5)
    again = rail.submit(instruction(), "idem-1")
    assert again == first
    assert again.observed_at == NOW


def test_definitive_reject_is_remembered_for_replays(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(MockRailMode.DEFINITIVE_REJECT, clock=clock)
    first = rail.submit(instruction(), "idem-1")
    rail.set_mode(MockRailMode.NORMAL_ACCEPTED)
    assert rail.submit(instruction(), "idem-1") == first
    assert first.status is RailSubmissionStatus.REJECTED


def test_reusing_a_key_with_a_different_instruction_conflicts(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(clock=clock)
    rail.submit(instruction(), "idem-1")
    for changed in (
        instruction(amount="1001"),
        instruction(currency="EUR"),
        instruction(dest="dest-evil"),
        instruction(tx="tx-2"),
    ):
        with pytest.raises(RailIdempotencyConflictError):
            rail.submit(changed, "idem-1")


def test_equivalent_instruction_representations_do_not_conflict(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(clock=clock)
    first = rail.submit(instruction(amount="1000"), "idem-1")
    assert rail.submit(instruction(amount="1000.00", currency="usd"), "idem-1") == first


def test_unknown_outcomes_are_not_remembered_so_a_retry_can_succeed(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(MockRailMode.TIMEOUT, clock=clock)
    assert rail.submit(instruction(), "idem-1").status is RailSubmissionStatus.UNKNOWN
    rail.set_mode(MockRailMode.NORMAL_ACCEPTED)
    assert rail.submit(instruction(), "idem-1").status is RailSubmissionStatus.ACCEPTED


@pytest.mark.parametrize("mode", [MockRailMode.TIMEOUT, MockRailMode.CONNECTION_RESET])
def test_process_before_fault_models_a_lost_response(clock: FakeClock, mode: MockRailMode) -> None:
    """The provider took the payment, but the caller only saw a fault (hence UNKNOWN, never FAILED)."""
    rail = MockBankRailAdapter(mode, clock=clock, process_before_fault=True)
    first = rail.submit(instruction(), "idem-1")
    assert first.status is RailSubmissionStatus.UNKNOWN

    rail.set_mode(MockRailMode.NORMAL_ACCEPTED)
    resubmitted = rail.submit(instruction(), "idem-1")
    assert resubmitted.status is RailSubmissionStatus.ACCEPTED
    assert resubmitted.provider_execution_id is not None
    assert len(rail.calls) == 2


def test_queued_modes_are_consumed_in_order_then_base_mode_resumes(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(MockRailMode.NORMAL_ACCEPTED, clock=clock)
    rail.queue_modes(MockRailMode.TIMEOUT, MockRailMode.DEFINITIVE_REJECT)
    statuses = [rail.submit(instruction(), f"idem-{i}").status for i in range(3)]
    assert statuses == [
        RailSubmissionStatus.UNKNOWN,
        RailSubmissionStatus.REJECTED,
        RailSubmissionStatus.ACCEPTED,
    ]
    assert [mode for _i, _k, mode in rail.calls] == [
        MockRailMode.TIMEOUT,
        MockRailMode.DEFINITIVE_REJECT,
        MockRailMode.NORMAL_ACCEPTED,
    ]


def test_submit_and_constructor_validation(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(clock=clock)
    with pytest.raises(TypeError):
        rail.submit("not-an-instruction", "idem-1")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        rail.submit(instruction(), " ")
    with pytest.raises(ValueError):
        rail.submit(
            RailInstruction(transaction_id="t", amount=1.5, currency="USD", destination_id="d"),  # type: ignore[arg-type]
            "idem-1",
        )
    with pytest.raises(ValueError):
        MockBankRailAdapter("NOT_A_MODE")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        MockBankRailAdapter(provider_name=" ")
    with pytest.raises(ValueError):
        rail.set_mode("NOT_A_MODE")  # type: ignore[arg-type]


# -- fail-closed helpers and the M7 bridge ------------------------------------------------


def test_coerce_returns_well_formed_results_unchanged(clock: FakeClock) -> None:
    result = make_result(RailSubmissionStatus.ACCEPTED)
    assert coerce_submission_result(result, clock=clock) is result


@pytest.mark.parametrize(
    "raw",
    [
        None,
        "ACCEPTED",
        {"status": "ACCEPTED"},
        make_result(RailSubmissionStatus.ACCEPTED, observed_at=datetime(2030, 1, 1)),
        make_result(RailSubmissionStatus.ACCEPTED, retryable="no"),  # type: ignore[arg-type]
        make_result(RailSubmissionStatus.ACCEPTED, authoritative=1),  # type: ignore[arg-type]
        make_result("ACCEPTED"),  # type: ignore[arg-type]
    ],
    ids=["none", "str", "dict", "naive-time", "non-bool-retryable", "non-bool-authoritative", "plain-str-status"],
)
def test_coerce_maps_malformed_output_to_unknown(clock: FakeClock, raw: Any) -> None:
    result = coerce_submission_result(raw, clock=clock)
    assert result.status is RailSubmissionStatus.UNKNOWN
    assert result.provider_code == "MALFORMED_ADAPTER_RESULT"
    assert result.retryable is True
    assert result.authoritative is False
    assert result.observed_at == NOW


@pytest.mark.parametrize(
    "exc",
    [
        TimeoutError("t"),
        ConnectionResetError("r"),
        BrokenPipeError("b"),
        RuntimeError("x"),
        Exception("generic"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_safe_submit_never_raises(clock: FakeClock, exc: Exception) -> None:
    result = safe_submit(StubRail(exc), instruction(), "idem-1", clock=clock)
    assert result.status is RailSubmissionStatus.UNKNOWN
    assert result.provider_code == f"ADAPTER_EXCEPTION:{type(exc).__name__}"
    assert result.retryable is True and result.authoritative is False


@pytest.mark.parametrize(
    "result,expected_status,expected_code",
    [
        (
            make_result(RailSubmissionStatus.ACCEPTED, provider_reference="ref-1"),
            RailDispatchStatus.SUBMITTED,
            None,
        ),
        (
            make_result(RailSubmissionStatus.PENDING, provider_execution_id="mbx-9"),
            RailDispatchStatus.SUBMITTED,
            None,
        ),
        (
            make_result(RailSubmissionStatus.REJECTED, provider_code="INSUFFICIENT_FUNDS"),
            RailDispatchStatus.FAILED,
            "INSUFFICIENT_FUNDS",
        ),
        (make_result(RailSubmissionStatus.REJECTED), RailDispatchStatus.FAILED, "REJECTED"),
        (
            make_result(RailSubmissionStatus.REJECTED, retryable=True, provider_code="BUSY"),
            RailDispatchStatus.UNKNOWN,
            "BUSY",
        ),
        (
            make_result(RailSubmissionStatus.REJECTED, authoritative=False, provider_code="MAYBE"),
            RailDispatchStatus.UNKNOWN,
            "MAYBE",
        ),
        (
            make_result(RailSubmissionStatus.ACCEPTED, authoritative=False),
            RailDispatchStatus.UNKNOWN,
            "UNKNOWN",
        ),
        (
            make_result(
                RailSubmissionStatus.UNKNOWN, retryable=True, authoritative=False, provider_code="TIMEOUT"
            ),
            RailDispatchStatus.UNKNOWN,
            "TIMEOUT",
        ),
        (
            make_result(RailSubmissionStatus.UNKNOWN, retryable=True, authoritative=False),
            RailDispatchStatus.UNKNOWN,
            "UNKNOWN",
        ),
        ("garbage", RailDispatchStatus.UNKNOWN, "MALFORMED_ADAPTER_RESULT"),
        (RuntimeError("boom"), RailDispatchStatus.UNKNOWN, "ADAPTER_EXCEPTION:RuntimeError"),
        (TimeoutError("slow"), RailDispatchStatus.UNKNOWN, "ADAPTER_EXCEPTION:TimeoutError"),
    ],
    ids=[
        "accepted",
        "pending",
        "reject",
        "reject-no-code",
        "retryable-reject",
        "non-authoritative-reject",
        "non-authoritative-accept",
        "timeout-unknown",
        "unknown-no-code",
        "malformed",
        "exception",
        "timeout-exception",
    ],
)
def test_bridge_maps_rail_results_to_m7_dispatch_results_fail_closed(
    clock: FakeClock, result: Any, expected_status: RailDispatchStatus, expected_code: Optional[str]
) -> None:
    rail = StubRail(result)
    bridge = PaymentRailAdapterBridge(rail, provider=PROVIDER, clock=clock)
    dispatch = bridge.submit_payment(
        PaymentInstruction(
            transaction_id="tx-1", amount=Decimal("1000"), currency="USD", destination_id="dest-1"
        ),
        idempotency_key="idem-bridge",
    )
    assert dispatch.status is expected_status
    assert dispatch.failure_code == expected_code
    assert dispatch.provider == PROVIDER
    assert rail.calls[0][1] == "idem-bridge"
    assert rail.calls[0][0] == instruction("tx-1")


def test_bridge_end_to_end_with_mock_modes(clock: FakeClock) -> None:
    rail = MockBankRailAdapter(clock=clock)
    bridge = PaymentRailAdapterBridge(rail, provider=PROVIDER, clock=clock)
    pi = PaymentInstruction(
        transaction_id="tx-1", amount=Decimal("1000"), currency="USD", destination_id="dest-1"
    )
    expectations = [
        (MockRailMode.NORMAL_ACCEPTED, RailDispatchStatus.SUBMITTED),
        (MockRailMode.PENDING_QUEUE, RailDispatchStatus.SUBMITTED),
        (MockRailMode.DEFINITIVE_REJECT, RailDispatchStatus.FAILED),
        (MockRailMode.RETRYABLE_ERROR, RailDispatchStatus.UNKNOWN),
        (MockRailMode.TIMEOUT, RailDispatchStatus.UNKNOWN),
        (MockRailMode.CONNECTION_RESET, RailDispatchStatus.UNKNOWN),
        (MockRailMode.MALFORMED, RailDispatchStatus.UNKNOWN),
    ]
    for index, (mode, expected) in enumerate(expectations):
        rail.set_mode(mode)
        assert bridge.submit_payment(pi, idempotency_key=f"idem-{index}").status is expected


def test_bridge_rejects_objects_without_submit() -> None:
    with pytest.raises(TypeError):
        PaymentRailAdapterBridge(object())  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        PaymentRailAdapterBridge(None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Service construction, schema and provider links
# ---------------------------------------------------------------------------


def test_service_constructor_rejects_bad_arguments(
    connect: Callable[[], sqlite3.Connection], engine: DurableTransactionEngine
) -> None:
    with pytest.raises(TypeError):
        RailEventReconciliationService("not-callable", engine)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        RailEventReconciliationService(connect, object())
    with pytest.raises(TypeError):
        RailEventReconciliationService(connect, None)
    with pytest.raises(ValueError):
        RailEventReconciliationService(connect, engine, dialect="mysql")


def test_ensure_schema_is_idempotent(service: RailEventReconciliationService, db_path: str) -> None:
    service.ensure_schema()
    service.ensure_schema()
    names = {row[0] for row in fetch_all(db_path, "SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"rail_webhook_events", "rail_provider_executions"} <= names


def insert_event(db_path: str, key: str, provider_event_id: Optional[str]) -> None:
    execute_write(
        db_path,
        "INSERT INTO rail_webhook_events (webhook_id, tenant_id, provider, idempotency_key, "
        "provider_event_id, event_type, amount, currency, transaction_execution_id, "
        "provider_execution_id, provider_status, status, outcome, received_at, processed_at) "
        "VALUES (?, ?, ?, ?, ?, 'e', '1', 'USD', NULL, NULL, 'SETTLED', 'RECEIVED', NULL, 'now', NULL)",
        (str(uuid4()), str(TENANT), PROVIDER, key, provider_event_id),
    )


def test_database_enforces_webhook_uniqueness(
    service: RailEventReconciliationService, db_path: str
) -> None:
    insert_event(db_path, "k1", "evt-1")
    with pytest.raises(sqlite3.IntegrityError):
        insert_event(db_path, "k1", "evt-other")  # same (tenant, provider, idempotency_key)
    with pytest.raises(sqlite3.IntegrityError):
        insert_event(db_path, "k2", "evt-1")  # same (tenant, provider, provider_event_id)
    insert_event(db_path, "k3", None)
    insert_event(db_path, "k4", None)  # NULL provider_event_id never collides
    assert count_rows(db_path, "rail_webhook_events") == 3


def test_provider_link_is_idempotent_and_conflicts_are_rejected(
    service: RailEventReconciliationService, db_path: str
) -> None:
    service.record_provider_execution(TENANT, PROVIDER, "mbx-1", "exec-1")
    service.record_provider_execution(TENANT, PROVIDER, "mbx-1", "exec-1")
    service.record_provider_execution(str(TENANT), PROVIDER, "mbx-1", "exec-1")
    assert count_rows(db_path, "rail_provider_executions") == 1
    with pytest.raises(ProviderLinkConflictError):
        service.record_provider_execution(TENANT, PROVIDER, "mbx-1", "exec-2")
    assert fetch_all(db_path, "SELECT transaction_execution_id FROM rail_provider_executions") == [
        ("exec-1",)
    ]


def test_provider_links_are_scoped_by_tenant_and_provider(
    service: RailEventReconciliationService, db_path: str
) -> None:
    service.record_provider_execution(TENANT, PROVIDER, "mbx-1", "exec-1")
    service.record_provider_execution(OTHER_TENANT, PROVIDER, "mbx-1", "exec-2")
    service.record_provider_execution(TENANT, "otherbank", "mbx-1", "exec-3")
    assert count_rows(db_path, "rail_provider_executions") == 3


def test_provider_link_validates_input(service: RailEventReconciliationService, db_path: str) -> None:
    with pytest.raises(ValueError):
        service.record_provider_execution(" ", PROVIDER, "mbx-1", "exec-1")
    with pytest.raises(ValueError):
        service.record_provider_execution(TENANT, " ", "mbx-1", "exec-1")
    with pytest.raises(ValueError):
        service.record_provider_execution(TENANT, PROVIDER, " ", "exec-1")
    with pytest.raises(ValueError):
        service.record_provider_execution(TENANT, PROVIDER, "mbx-1", " ")
    assert count_rows(db_path, "rail_provider_executions") == 0


def test_ingest_rejects_malformed_evidence_before_any_write(
    service: RailEventReconciliationService, adapter: MockBankRailAdapter, db_path: str
) -> None:
    good = make_evidence(adapter)
    with pytest.raises(TypeError):
        service.ingest_and_reconcile("nope")  # type: ignore[arg-type]
    bad_variants = [
        dataclasses.replace(good, received_at=datetime(2030, 1, 1)),
        dataclasses.replace(good, amount=Decimal("0")),
        dataclasses.replace(good, amount=1.5),  # type: ignore[arg-type]
        dataclasses.replace(good, currency=" "),
        dataclasses.replace(good, idempotency_key=" "),
        dataclasses.replace(good, status=" "),
        dataclasses.replace(good, tenant_id="x"),  # type: ignore[arg-type]
        dataclasses.replace(good, webhook_id="x"),  # type: ignore[arg-type]
        dataclasses.replace(good, provider=" "),
        dataclasses.replace(good, event_type=" "),
        dataclasses.replace(good, provider_event_id=" "),
        dataclasses.replace(good, provider_execution_id=" "),
        dataclasses.replace(good, transaction_execution_id="x"),  # type: ignore[arg-type]
    ]
    for bad in bad_variants:
        with pytest.raises(ValueError):
            service.ingest_and_reconcile(bad)
    assert count_rows(db_path, "rail_webhook_events") == 0


# ---------------------------------------------------------------------------
# 5. State transitions via the M6 engine
# ---------------------------------------------------------------------------


def test_submitted_to_settled_on_valid_settled_webhook(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    intent, before = setup_execution(engine, service, S.SUBMITTED)
    assert before.state is S.SUBMITTED

    outcome = service.ingest_and_reconcile(
        make_evidence(adapter, key="wh-1", status="SETTLED", event_type="payment.settled")
    )

    assert outcome == (True, RESULT_PROCESSED)
    after = engine.get_execution(before.transaction_execution_id, str(TENANT))
    assert after.state is S.SETTLED
    assert after.version == before.version + 1
    assert after.settled_at == NOW
    assert after.submitted_at == before.submitted_at
    record = service.get_webhook_record(TENANT, PROVIDER, "wh-1")
    assert record is not None
    assert record.status == WEBHOOK_STATUS_PROCESSED
    assert record.outcome == RESULT_PROCESSED
    assert record.processed_at == NOW
    assert record.amount == Decimal("1000")
    assert record.currency == "USD"
    assert engine.get_intent(intent.payment_intent_id, str(TENANT)).amount == Decimal("1000")


@pytest.mark.parametrize(
    "provider_status",
    ["SETTLED", "settled", "COMPLETED", "SUCCEEDED", "SUCCESS", "PAID", " paid "],
)
def test_every_settled_status_alias_settles(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    provider_status: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    assert service.ingest_and_reconcile(make_evidence(adapter, status=provider_status)) == (
        True,
        RESULT_PROCESSED,
    )
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)).state is S.SETTLED


def test_submitted_to_failed_on_valid_rejection_webhook(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)

    outcome = service.ingest_and_reconcile(
        make_evidence(adapter, key="wh-rej", status="REJECTED", event_type="payment.rejected")
    )

    assert outcome == (True, RESULT_PROCESSED)
    after = engine.get_execution(before.transaction_execution_id, str(TENANT))
    assert after.state is S.FAILED
    assert after.version == before.version + 1
    assert after.failed_at == NOW
    assert after.failure_reason == "WEBHOOK:payment.rejected:REJECTED"
    assert after.settled_at is None


@pytest.mark.parametrize(
    "provider_status", ["FAILED", "REJECTED", "RETURNED", "CANCELLED", "CANCELED", "REVERSED", "failed"]
)
def test_every_failed_status_alias_fails(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    provider_status: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    assert service.ingest_and_reconcile(make_evidence(adapter, status=provider_status)) == (
        True,
        RESULT_PROCESSED,
    )
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)).state is S.FAILED


def test_unknown_to_settled_on_delayed_authoritative_webhook(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
) -> None:
    _intent, before = setup_execution(engine, service, S.UNKNOWN)
    assert before.state is S.UNKNOWN

    # Without reconciliation the engine itself refuses the transition...
    with pytest.raises(InvalidStateTransitionError):
        engine.transition_state(before.transaction_execution_id, str(TENANT), S.SETTLED, now=NOW)

    # ...verified provider evidence is the reconciliation.
    outcome = service.ingest_and_reconcile(make_evidence(adapter, key="wh-late", status="SETTLED"))

    assert outcome == (True, RESULT_PROCESSED)
    after = engine.get_execution(before.transaction_execution_id, str(TENANT))
    assert after.state is S.SETTLED
    assert after.version == before.version + 1
    assert after.unknown_at == before.unknown_at


def test_unknown_to_failed_on_delayed_authoritative_webhook(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
) -> None:
    _intent, before = setup_execution(engine, service, S.UNKNOWN)
    assert service.ingest_and_reconcile(make_evidence(adapter, status="REJECTED")) == (
        True,
        RESULT_PROCESSED,
    )
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)).state is S.FAILED


def test_service_passes_expected_version_and_reconciled_flag_to_the_engine(
    engine: DurableTransactionEngine,
    connect: Callable[[], sqlite3.Connection],
    clock: FakeClock,
    adapter: MockBankRailAdapter,
    service: RailEventReconciliationService,
) -> None:
    _i1, submitted_exec = setup_execution(engine, service, S.SUBMITTED, key="s", link="mbx-s")
    _i2, unknown_exec = setup_execution(engine, service, S.UNKNOWN, key="u", link="mbx-u")
    proxy = EngineProxy(engine)
    svc = RailEventReconciliationService(connect, proxy, clock=clock)

    svc.ingest_and_reconcile(make_evidence(adapter, key="wh-s", provider_execution_id="mbx-s"))
    svc.ingest_and_reconcile(make_evidence(adapter, key="wh-u", provider_execution_id="mbx-u"))

    assert len(proxy.transition_calls) == 2
    (args_s, kwargs_s), (args_u, kwargs_u) = proxy.transition_calls
    assert args_s == (submitted_exec.transaction_execution_id, str(TENANT), S.SETTLED)
    assert kwargs_s == {"now": NOW, "expected_version": submitted_exec.version, "reconciled": False}
    assert args_u == (unknown_exec.transaction_execution_id, str(TENANT), S.SETTLED)
    assert kwargs_u == {"now": NOW, "expected_version": unknown_exec.version, "reconciled": True}


def test_correlation_by_explicit_transaction_execution_id(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, execution = setup_execution(engine, service, S.SUBMITTED, link=None)
    new_id = rekey_execution(db_path, execution)

    outcome = service.ingest_and_reconcile(
        make_evidence(adapter, provider_execution_id=None, transaction_execution_id=new_id)
    )

    assert outcome == (True, RESULT_PROCESSED)
    assert engine.get_execution(str(new_id), str(TENANT)).state is S.SETTLED


def test_explicit_id_and_provider_link_that_agree_correlate(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, execution = setup_execution(engine, service, S.SUBMITTED, link=None)
    new_id = rekey_execution(db_path, execution)
    service.record_provider_execution(TENANT, PROVIDER, "mbx-1", new_id)

    outcome = service.ingest_and_reconcile(
        make_evidence(adapter, provider_execution_id="mbx-1", transaction_execution_id=new_id)
    )
    assert outcome == (True, RESULT_PROCESSED)
    assert engine.get_execution(str(new_id), str(TENANT)).state is S.SETTLED


def test_disagreeing_explicit_id_and_provider_link_is_a_conflict(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    setup_execution(engine, service, S.SUBMITTED, link="mbx-1")
    before = snapshot(db_path)

    outcome = service.ingest_and_reconcile(
        make_evidence(adapter, provider_execution_id="mbx-1", transaction_execution_id=uuid4())
    )

    assert outcome == (False, RESULT_CONFLICT)
    assert snapshot(db_path) == before


def test_progress_webhooks_do_not_change_state(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    snap = snapshot(db_path)
    for index, status in enumerate(["PENDING", "PROCESSING", "ACCEPTED", "SUBMITTED", "IN_PROGRESS"]):
        outcome = service.ingest_and_reconcile(make_evidence(adapter, key=f"wh-p{index}", status=status))
        assert outcome == (True, RESULT_NO_STATE_CHANGE)
    assert snapshot(db_path) == snap
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)) == before

    # A later terminal webhook still settles normally.
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-final")) == (True, RESULT_PROCESSED)


def test_unsupported_status_is_quarantined_without_changes(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    setup_execution(engine, service, S.SUBMITTED)
    before = snapshot(db_path)
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-x", status="MYSTERY")) == (
        False,
        RESULT_UNSUPPORTED_STATUS,
    )
    assert snapshot(db_path) == before
    record = service.get_webhook_record(TENANT, PROVIDER, "wh-x")
    assert record is not None and record.status == WEBHOOK_STATUS_QUARANTINED


def test_mock_adapter_pending_then_webhook_settles_end_to_end(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    clock: FakeClock,
) -> None:
    rail = MockBankRailAdapter(MockRailMode.PENDING_QUEUE, clock=clock)
    intent, execution = setup_execution(engine, service, S.SUBMITTED, link=None)

    submission = rail.submit(
        RailInstruction(
            transaction_id=execution.transaction_execution_id,
            amount=intent.amount,
            currency=intent.currency,
            destination_id=intent.destination_id,
        ),
        intent.idempotency_key,
    )
    assert submission.status is RailSubmissionStatus.PENDING
    assert submission.provider_execution_id is not None
    service.record_provider_execution(
        TENANT, PROVIDER, submission.provider_execution_id, execution.transaction_execution_id
    )

    pending = make_evidence(
        rail, key="wh-pending", status="PENDING", provider_execution_id=submission.provider_execution_id
    )
    assert service.ingest_and_reconcile(pending) == (True, RESULT_NO_STATE_CHANGE)
    assert engine.get_execution(execution.transaction_execution_id, str(TENANT)).state is S.SUBMITTED

    settled = make_evidence(
        rail, key="wh-settled", status="SETTLED", provider_execution_id=submission.provider_execution_id
    )
    assert service.ingest_and_reconcile(settled) == (True, RESULT_PROCESSED)
    assert engine.get_execution(execution.transaction_execution_id, str(TENANT)).state is S.SETTLED


# -- terminal monotonicity -----------------------------------------------------------------------


def test_duplicate_settled_webhook_with_a_new_key_is_a_safe_noop(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-1")) == (True, RESULT_PROCESSED)
    settled = engine.get_execution(before.transaction_execution_id, str(TENANT))
    snap = snapshot(db_path)

    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-2")) == (True, RESULT_NOOP_TERMINAL)

    assert snapshot(db_path) == snap
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)) == settled


@pytest.mark.parametrize("terminal", [S.SETTLED, S.FAILED], ids=["settled", "failed"])
@pytest.mark.parametrize(
    "webhook_status", ["SETTLED", "REJECTED"], ids=["settled-webhook", "rejected-webhook"]
)
def test_terminal_states_never_change_in_response_to_any_terminal_webhook(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
    terminal: TransactionExecutionState,
    webhook_status: str,
) -> None:
    _intent, execution = setup_execution(engine, service, terminal)
    assert execution.state is terminal
    snap = snapshot(db_path)

    outcome = service.ingest_and_reconcile(make_evidence(adapter, status=webhook_status))

    assert outcome == (True, RESULT_NOOP_TERMINAL)
    assert snapshot(db_path) == snap
    assert engine.get_execution(execution.transaction_execution_id, str(TENANT)) == execution


def test_settled_cannot_regress_to_submitted_or_failed(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-ok")) == (True, RESULT_PROCESSED)
    settled = engine.get_execution(before.transaction_execution_id, str(TENANT))
    snap = snapshot(db_path)

    # A late progress event and a contradictory failure never move the state.
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-late", status="SUBMITTED")) == (
        True,
        RESULT_NO_STATE_CHANGE,
    )
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-fail", status="FAILED")) == (
        True,
        RESULT_NOOP_TERMINAL,
    )
    assert snapshot(db_path) == snap
    current = engine.get_execution(before.transaction_execution_id, str(TENANT))
    assert current == settled
    assert current.state is S.SETTLED
    assert current.failed_at is None

    # The engine independently refuses any mutation of a terminal execution.
    for target in (S.SUBMITTED, S.FAILED, S.UNKNOWN, S.SETTLED):
        with pytest.raises(InvalidStateTransitionError):
            engine.transition_state(
                before.transaction_execution_id, str(TENANT), target, now=NOW, reconciled=True
            )
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)) == settled


def test_losing_a_race_to_another_writer_resolves_as_a_terminal_noop(
    engine: DurableTransactionEngine,
    connect: Callable[[], sqlite3.Connection],
    clock: FakeClock,
    adapter: MockBankRailAdapter,
    service: RailEventReconciliationService,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    racing = RacingEngine(engine)
    svc = RailEventReconciliationService(connect, racing, clock=clock)

    assert svc.ingest_and_reconcile(make_evidence(adapter)) == (True, RESULT_NOOP_TERMINAL)

    after = engine.get_execution(before.transaction_execution_id, str(TENANT))
    assert after.state is S.SETTLED
    assert after.version == before.version + 1  # exactly one transition was applied
    assert len(racing.transition_calls) == 1


def test_perpetual_contention_raises_and_leaves_the_webhook_for_redelivery(
    engine: DurableTransactionEngine,
    connect: Callable[[], sqlite3.Connection],
    clock: FakeClock,
    adapter: MockBankRailAdapter,
    service: RailEventReconciliationService,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    contended = AlwaysConflictingEngine(engine)
    svc = RailEventReconciliationService(connect, contended, clock=clock)

    with pytest.raises(ReconciliationError):
        svc.ingest_and_reconcile(make_evidence(adapter, key="wh-1"))

    assert len(contended.transition_calls) == 3
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)) == before
    record = service.get_webhook_record(TENANT, PROVIDER, "wh-1")
    assert record is not None and record.status == WEBHOOK_STATUS_RECEIVED
    # Redelivery through a healthy service finishes the job.
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-1")) == (True, RESULT_PROCESSED)


def test_engine_infrastructure_failure_leaves_webhook_received_and_redelivery_resumes(
    engine: DurableTransactionEngine,
    connect: Callable[[], sqlite3.Connection],
    clock: FakeClock,
    adapter: MockBankRailAdapter,
    service: RailEventReconciliationService,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    faulty = FaultyEngine(engine, RuntimeError("db down"))
    svc = RailEventReconciliationService(connect, faulty, clock=clock)
    evidence = make_evidence(adapter, key="wh-1")

    with pytest.raises(ReconciliationError) as excinfo:
        svc.ingest_and_reconcile(evidence)

    assert isinstance(excinfo.value.__cause__, RuntimeError)
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)) == before
    record = service.get_webhook_record(TENANT, PROVIDER, "wh-1")
    assert record is not None
    assert record.status == WEBHOOK_STATUS_RECEIVED
    assert record.processed_at is None

    faulty.fault = None
    assert svc.ingest_and_reconcile(evidence) == (True, RESULT_PROCESSED)
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)).state is S.SETTLED
    assert count_rows(db_path, "rail_webhook_events") == 1


# ---------------------------------------------------------------------------
# 3. Monetary binding and security invariants
# ---------------------------------------------------------------------------


def test_amount_inflation_is_rejected_as_conflict_with_zero_state_changes(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    intent, before = setup_execution(engine, service, S.SUBMITTED, amount="1000")
    snap = snapshot(db_path)

    # Expected 1,000; the webhook claims 10,000.
    evidence = make_evidence(adapter, key="wh-evil", amount="10000")
    assert evidence.amount == Decimal("10000")
    outcome = service.ingest_and_reconcile(evidence)

    assert outcome == (False, RESULT_CONFLICT)
    assert snapshot(db_path) == snap
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)) == before
    assert engine.get_intent(intent.payment_intent_id, str(TENANT)).amount == Decimal("1000")
    record = service.get_webhook_record(TENANT, PROVIDER, "wh-evil")
    assert record is not None
    assert record.status == WEBHOOK_STATUS_CONFLICT
    assert record.outcome == RESULT_CONFLICT
    assert record.processed_at is None
    assert count_rows(db_path, "transaction_ledger_entries") == 1  # the M6 reservation only


@pytest.mark.parametrize("webhook_amount", ["10000", "999.99", "1000.01", "1", "100"])
@pytest.mark.parametrize("webhook_status", ["SETTLED", "REJECTED"])
def test_any_amount_mismatch_is_a_conflict_for_settle_and_fail_alike(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
    webhook_amount: str,
    webhook_status: str,
) -> None:
    setup_execution(engine, service, S.SUBMITTED)
    snap = snapshot(db_path)
    outcome = service.ingest_and_reconcile(
        make_evidence(adapter, amount=webhook_amount, status=webhook_status)
    )
    assert outcome == (False, RESULT_CONFLICT)
    assert snapshot(db_path) == snap


def test_mismatched_currency_is_rejected_with_zero_state_changes(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED, currency="USD")
    snap = snapshot(db_path)

    outcome = service.ingest_and_reconcile(make_evidence(adapter, key="wh-eur", currency="EUR"))

    assert outcome == (False, RESULT_CONFLICT)
    assert snapshot(db_path) == snap
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)) == before
    record = service.get_webhook_record(TENANT, PROVIDER, "wh-eur")
    assert record is not None and record.status == WEBHOOK_STATUS_CONFLICT


def test_equivalent_amount_and_currency_spellings_are_accepted(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED, amount="1000", currency="USD")
    outcome = service.ingest_and_reconcile(make_evidence(adapter, amount="1000.00", currency="usd"))
    assert outcome == (True, RESULT_PROCESSED)
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)).state is S.SETTLED


def test_a_conflicting_webhook_stays_conflicted_on_redelivery_and_does_not_block_a_valid_one(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    evil = make_evidence(adapter, key="wh-evil", amount="10000")
    assert service.ingest_and_reconcile(evil) == (False, RESULT_CONFLICT)
    snap = snapshot(db_path)

    # Redelivery (even with a corrected body) cannot launder a conflicted idempotency key.
    for _ in range(3):
        assert service.ingest_and_reconcile(evil) == (False, RESULT_CONFLICT)
        assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-evil")) == (
            False,
            RESULT_CONFLICT,
        )
    assert snapshot(db_path) == snap
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)) == before

    # A genuine webhook under a fresh key still reconciles.
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-good")) == (True, RESULT_PROCESSED)
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)).state is S.SETTLED


def test_raise_on_conflict_raises_after_flagging_and_mutates_nothing(
    engine: DurableTransactionEngine,
    connect: Callable[[], sqlite3.Connection],
    clock: FakeClock,
    adapter: MockBankRailAdapter,
    service: RailEventReconciliationService,
    db_path: str,
) -> None:
    setup_execution(engine, service, S.SUBMITTED)
    strict = RailEventReconciliationService(connect, engine, clock=clock, raise_on_conflict=True)
    snap = snapshot(db_path)

    with pytest.raises(ReconciliationConflictError):
        strict.ingest_and_reconcile(make_evidence(adapter, key="wh-evil", amount="10000"))

    assert snapshot(db_path) == snap
    record = strict.get_webhook_record(TENANT, PROVIDER, "wh-evil")
    assert record is not None and record.status == WEBHOOK_STATUS_CONFLICT


def test_webhook_cannot_reach_another_tenants_execution(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, execution = setup_execution(engine, service, S.SUBMITTED, link="mbx-1")
    new_id = rekey_execution(db_path, execution)
    service.record_provider_execution(TENANT, PROVIDER, "mbx-shared", new_id)
    snap = snapshot(db_path)

    # Explicit execution id belonging to tenant A, presented by tenant B.
    assert service.ingest_and_reconcile(
        make_evidence(
            adapter,
            key="wh-x1",
            tenant=OTHER_TENANT,
            provider_execution_id=None,
            transaction_execution_id=new_id,
        )
    ) == (False, RESULT_QUARANTINED)
    # Provider execution id linked only under tenant A.
    assert service.ingest_and_reconcile(
        make_evidence(adapter, key="wh-x2", tenant=OTHER_TENANT, provider_execution_id="mbx-shared")
    ) == (False, RESULT_QUARANTINED)

    assert snapshot(db_path) == snap
    assert engine.get_execution(str(new_id), str(TENANT)).state is S.SUBMITTED
    with pytest.raises(TransactionNotFoundError):
        engine.get_execution(str(new_id), str(OTHER_TENANT))


def test_uncorrelated_webhooks_are_quarantined_not_applied(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    setup_execution(engine, service, S.SUBMITTED)
    snap = snapshot(db_path)

    no_ids = make_evidence(adapter, key="wh-none", provider_execution_id=None)
    unknown_link = make_evidence(adapter, key="wh-unlinked", provider_execution_id="mbx-nope")
    unknown_uuid = make_evidence(
        adapter, key="wh-ghost", provider_execution_id=None, transaction_execution_id=uuid4()
    )
    for evidence in (no_ids, unknown_link, unknown_uuid):
        assert service.ingest_and_reconcile(evidence) == (False, RESULT_QUARANTINED)

    assert snapshot(db_path) == snap
    statuses = {row[0]: row[1] for row in event_rows(db_path)}
    assert statuses == {
        "wh-none": WEBHOOK_STATUS_QUARANTINED,
        "wh-unlinked": WEBHOOK_STATUS_QUARANTINED,
        "wh-ghost": WEBHOOK_STATUS_QUARANTINED,
    }


def test_quarantined_webhook_is_reevaluated_once_the_link_exists(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, execution = setup_execution(engine, service, S.SUBMITTED, link=None)
    evidence = make_evidence(adapter, key="wh-late-link", provider_execution_id="mbx-late")

    assert service.ingest_and_reconcile(evidence) == (False, RESULT_QUARANTINED)
    service.record_provider_execution(TENANT, PROVIDER, "mbx-late", execution.transaction_execution_id)
    assert service.ingest_and_reconcile(evidence) == (True, RESULT_PROCESSED)

    assert engine.get_execution(execution.transaction_execution_id, str(TENANT)).state is S.SETTLED
    record = service.get_webhook_record(TENANT, PROVIDER, "wh-late-link")
    assert record is not None and record.status == WEBHOOK_STATUS_PROCESSED
    assert count_rows(db_path, "rail_webhook_events") == 1


@pytest.mark.parametrize(
    "state", [S.CREATED, S.AUTHORIZED, S.APPROVED, S.RESERVED], ids=lambda s: s.value
)
def test_webhooks_before_submission_are_deferred_not_guessed(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
    state: TransactionExecutionState,
) -> None:
    _intent, before = setup_execution(engine, service, state)
    snap = snapshot(db_path)

    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-early")) == (
        False,
        RESULT_DEFERRED,
    )

    assert snapshot(db_path) == snap
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)) == before
    record = service.get_webhook_record(TENANT, PROVIDER, "wh-early")
    assert record is not None and record.status == WEBHOOK_STATUS_DEFERRED


def test_deferred_webhook_is_applied_on_redelivery_after_submission(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
) -> None:
    _intent, reserved = setup_execution(engine, service, S.RESERVED)
    evidence = make_evidence(adapter, key="wh-early")
    assert service.ingest_and_reconcile(evidence) == (False, RESULT_DEFERRED)

    engine.transition_state(reserved.transaction_execution_id, str(TENANT), S.SUBMITTED, now=NOW)
    assert service.ingest_and_reconcile(evidence) == (True, RESULT_PROCESSED)
    assert engine.get_execution(reserved.transaction_execution_id, str(TENANT)).state is S.SETTLED


# ---------------------------------------------------------------------------
# 4. Webhook idempotency
# ---------------------------------------------------------------------------


def test_five_deliveries_produce_exactly_one_transition_and_no_extra_side_effects(
    engine: DurableTransactionEngine,
    connect: Callable[[], sqlite3.Connection],
    clock: FakeClock,
    adapter: MockBankRailAdapter,
    service: RailEventReconciliationService,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    proxy = EngineProxy(engine)
    svc = RailEventReconciliationService(connect, proxy, clock=clock)
    ledger_before = fetch_all(db_path, "SELECT * FROM transaction_ledger_entries ORDER BY 1")
    outbox_before = fetch_all(db_path, "SELECT * FROM provider_outbox ORDER BY 1")

    # Each delivery is independently signed and verified, so each carries a fresh webhook_id.
    results = [
        svc.ingest_and_reconcile(make_evidence(adapter, key="wh-dup", event_type="payment.settled"))
        for _ in range(5)
    ]

    assert results[0] == (True, RESULT_PROCESSED)
    assert results[1:] == [(True, RESULT_DUPLICATE)] * 4
    assert len(proxy.transition_calls) == 1  # exactly one state transition attempted
    after = engine.get_execution(before.transaction_execution_id, str(TENANT))
    assert after.state is S.SETTLED
    assert after.version == before.version + 1
    assert count_rows(db_path, "rail_webhook_events") == 1
    assert fetch_all(db_path, "SELECT * FROM transaction_ledger_entries ORDER BY 1") == ledger_before
    assert fetch_all(db_path, "SELECT * FROM provider_outbox ORDER BY 1") == outbox_before
    assert count_rows(db_path, "transaction_ledger_entries") == 1
    assert event_rows(db_path) == [("wh-dup", WEBHOOK_STATUS_PROCESSED, RESULT_PROCESSED)]


def test_redelivering_the_same_evidence_object_is_idempotent(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    evidence = make_evidence(adapter, key="wh-same")
    results = [service.ingest_and_reconcile(evidence) for _ in range(5)]
    assert results == [(True, RESULT_PROCESSED)] + [(True, RESULT_DUPLICATE)] * 4
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)).version == before.version + 1
    assert count_rows(db_path, "rail_webhook_events") == 1


def test_duplicate_delivery_leaves_the_stored_record_untouched(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    clock: FakeClock,
    db_path: str,
) -> None:
    setup_execution(engine, service, S.SUBMITTED)
    service.ingest_and_reconcile(make_evidence(adapter, key="wh-1"))
    record_before = fetch_all(db_path, "SELECT * FROM rail_webhook_events")
    snap = snapshot(db_path)

    clock.advance(hours=3)
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-1")) == (True, RESULT_DUPLICATE)

    assert fetch_all(db_path, "SELECT * FROM rail_webhook_events") == record_before
    assert snapshot(db_path) == snap


def test_a_processed_idempotency_key_cannot_be_reused_with_different_content(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    service.ingest_and_reconcile(make_evidence(adapter, key="wh-1", status="SETTLED"))
    settled = engine.get_execution(before.transaction_execution_id, str(TENANT))

    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-1", status="REJECTED")) == (
        True,
        RESULT_DUPLICATE,
    )
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-1", amount="10000")) == (
        True,
        RESULT_DUPLICATE,
    )
    assert engine.get_execution(before.transaction_execution_id, str(TENANT)) == settled
    assert count_rows(db_path, "rail_webhook_events") == 1


def test_same_provider_event_id_under_a_new_idempotency_key_is_a_duplicate(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    first = make_evidence(adapter, key="wh-a", provider_event_id="evt-42")
    second = make_evidence(adapter, key="wh-b", provider_event_id="evt-42", status="FAILED")

    assert service.ingest_and_reconcile(first) == (True, RESULT_PROCESSED)
    assert service.ingest_and_reconcile(second) == (True, RESULT_DUPLICATE)

    assert engine.get_execution(before.transaction_execution_id, str(TENANT)).state is S.SETTLED
    assert count_rows(db_path, "rail_webhook_events") == 1
    assert service.get_webhook_record(TENANT, PROVIDER, "wh-b") is None


def test_idempotency_is_scoped_by_tenant(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _a, exec_a = setup_execution(engine, service, S.SUBMITTED, key="a", tenant=TENANT, link="mbx-1")
    _b, exec_b = setup_execution(
        engine, service, S.SUBMITTED, key="b", tenant=OTHER_TENANT, link="mbx-1"
    )

    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-same", tenant=TENANT)) == (
        True,
        RESULT_PROCESSED,
    )
    assert service.ingest_and_reconcile(make_evidence(adapter, key="wh-same", tenant=OTHER_TENANT)) == (
        True,
        RESULT_PROCESSED,
    )

    assert engine.get_execution(exec_a.transaction_execution_id, str(TENANT)).state is S.SETTLED
    assert engine.get_execution(exec_b.transaction_execution_id, str(OTHER_TENANT)).state is S.SETTLED
    assert count_rows(db_path, "rail_webhook_events") == 2


def test_idempotency_is_scoped_by_provider(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    clock: FakeClock,
    db_path: str,
) -> None:
    _intent, execution = setup_execution(engine, service, S.SUBMITTED, link=None)
    for provider in ("bank-one", "bank-two"):
        service.record_provider_execution(TENANT, provider, "mbx-1", execution.transaction_execution_id)

    first = make_evidence(MockBankRailAdapter(provider_name="bank-one", clock=clock), key="wh-same")
    second = make_evidence(MockBankRailAdapter(provider_name="bank-two", clock=clock), key="wh-same")
    assert first.provider == "bank-one" and second.provider == "bank-two"

    assert service.ingest_and_reconcile(first) == (True, RESULT_PROCESSED)
    assert service.ingest_and_reconcile(second) == (True, RESULT_NOOP_TERMINAL)
    assert count_rows(db_path, "rail_webhook_events") == 2


def test_concurrent_duplicate_deliveries_apply_exactly_one_transition(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    db_path: str,
) -> None:
    _intent, before = setup_execution(engine, service, S.SUBMITTED)
    ledger_before = fetch_all(db_path, "SELECT * FROM transaction_ledger_entries ORDER BY 1")
    evidence = make_evidence(adapter, key="wh-race")

    results = run_concurrently([lambda: service.ingest_and_reconcile(evidence) for _ in range(6)])

    codes = [code for ok, code in results]
    assert all(ok for ok, _code in results)
    assert codes.count(RESULT_PROCESSED) == 1
    assert set(codes) <= {RESULT_PROCESSED, RESULT_NOOP_TERMINAL, RESULT_DUPLICATE}
    after = engine.get_execution(before.transaction_execution_id, str(TENANT))
    assert after.state is S.SETTLED
    assert after.version == before.version + 1
    assert count_rows(db_path, "rail_webhook_events") == 1
    record = service.get_webhook_record(TENANT, PROVIDER, "wh-race")
    assert record is not None and record.status == WEBHOOK_STATUS_PROCESSED
    assert fetch_all(db_path, "SELECT * FROM transaction_ledger_entries ORDER BY 1") == ledger_before


# ---------------------------------------------------------------------------
# Dialects and connection hygiene
# ---------------------------------------------------------------------------


class _FakeCursor:
    def __init__(self, log: List[str]) -> None:
        self._log = log
        self.rowcount = 0

    def execute(self, sql: str, params: Tuple[Any, ...] = ()) -> None:
        self._log.append(sql)

    def fetchone(self) -> None:
        return None

    def fetchall(self) -> List[Any]:
        return []

    def close(self) -> None:
        return None


class _FakeConnection:
    def __init__(self, log: List[str]) -> None:
        self._log = log
        self.commits = 0
        self.closed = False

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self._log)

    def commit(self) -> None:
        self.commits += 1

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def test_postgres_dialect_uses_format_placeholders(engine: DurableTransactionEngine, clock: FakeClock) -> None:
    log: List[str] = []
    conns: List[_FakeConnection] = []

    def factory() -> _FakeConnection:
        conn = _FakeConnection(log)
        conns.append(conn)
        return conn

    svc = RailEventReconciliationService(factory, engine, dialect="postgres", clock=clock)
    assert svc.get_webhook_record(TENANT, PROVIDER, "wh-1") is None
    assert len(log) == 1
    assert "%s" in log[0] and "?" not in log[0]
    assert [c.commits for c in conns] == [1]
    assert all(c.closed for c in conns)


def test_every_connection_is_closed_on_success_and_failure(
    engine: DurableTransactionEngine,
    service: RailEventReconciliationService,
    adapter: MockBankRailAdapter,
    clock: FakeClock,
    db_path: str,
) -> None:
    opened: List["_Spy"] = []

    class _Spy:
        def __init__(self) -> None:
            self._conn = sqlite3.connect(db_path, timeout=30)
            self.closed = False
            opened.append(self)

        def cursor(self) -> sqlite3.Cursor:
            return self._conn.cursor()

        def commit(self) -> None:
            self._conn.commit()

        def rollback(self) -> None:
            self._conn.rollback()

        def close(self) -> None:
            self.closed = True
            self._conn.close()

    setup_execution(engine, service, S.SUBMITTED)
    spy_service = RailEventReconciliationService(_Spy, engine, clock=clock)  # type: ignore[arg-type]
    spy_service.ensure_schema()
    assert spy_service.ingest_and_reconcile(make_evidence(adapter, key="wh-ok")) == (True, RESULT_PROCESSED)
    assert spy_service.ingest_and_reconcile(make_evidence(adapter, key="wh-ok")) == (True, RESULT_DUPLICATE)
    assert spy_service.ingest_and_reconcile(make_evidence(adapter, key="wh-bad", amount="5")) == (
        False,
        RESULT_CONFLICT,
    )
    with pytest.raises(ProviderLinkConflictError):
        spy_service.record_provider_execution(TENANT, PROVIDER, "mbx-1", "some-other-execution")
    assert spy_service.get_webhook_record(TENANT, PROVIDER, "missing") is None

    assert opened, "factory was never used"
    assert all(spy.closed for spy in opened)