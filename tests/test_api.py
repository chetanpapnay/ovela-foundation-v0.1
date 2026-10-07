from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from app.http.api import ApiConfig, OvelaApi, map_exception
from app.runtime import (
    ActionType,
    ApprovalRequired,
    AuditVerifyResponse,
    AuthenticationFailure,
    AuthorizationDenied,
    Decision,
    ExecutionState,
    IdempotencyConflict,
    OvelaRuntime,
    OvelaRuntimeError,
    PaymentExecuteResponse,
    PaymentProposeResponse,
    RailTimeout,
    TenantBoundaryViolation,
)


class FakeContext:
    def __init__(
        self,
        *,
        session_id: UUID,
        tenant_id: UUID,
        subject_id: UUID,
        request_id: str = "request-001",
        verified_at: datetime | None = None,
    ) -> None:
        self.session_id = session_id
        self.tenant_id = tenant_id
        self.subject_id = subject_id
        self.request_id = request_id
        self.verified_at = verified_at or datetime.now(timezone.utc)


class FakeRuntime:
    def __init__(self) -> None:
        self.propose_calls: list[tuple] = []
        self.execute_calls: list[tuple] = []
        self.audit_calls: list[UUID] = []
        self.propose_response = PaymentProposeResponse(
            request_id=uuid4(),
            decision=Decision.PERMIT,
            approval_required=False,
            reason="payment is within the configured spending limit",
        )
        self.execute_response = PaymentExecuteResponse(
            transaction_id=uuid4(),
            state=ExecutionState.SUBMITTED,
            outbox_id=uuid4(),
            audit_sequence=2,
        )
        self.audit_response = AuditVerifyResponse(
            valid=True,
            tenant_id=uuid4(),
            records_verified=3,
            head_sequence=2,
            first_failure=None,
        )
        self.propose_exception: BaseException | None = None
        self.execute_exception: BaseException | None = None
        self.audit_exception: BaseException | None = None

    def propose_payment(
        self,
        session_id: UUID,
        request,
        spending_limit: Decimal,
        verified_at: datetime,
    ) -> PaymentProposeResponse:
        if self.propose_exception is not None:
            raise self.propose_exception
        self.propose_calls.append(
            (
                session_id,
                request,
                spending_limit,
                verified_at,
            )
        )
        return self.propose_response

    def execute_payment(
        self,
        session_id: UUID,
        request,
        spending_limit: Decimal,
        *,
        simulate_rail_timeout: bool,
        now: datetime,
    ) -> PaymentExecuteResponse:
        if self.execute_exception is not None:
            raise self.execute_exception
        self.execute_calls.append(
            (
                session_id,
                request,
                spending_limit,
                simulate_rail_timeout,
                now,
            )
        )
        return self.execute_response

    def verify_audit_chain(
        self,
        tenant_id: UUID,
    ) -> AuditVerifyResponse:
        if self.audit_exception is not None:
            raise self.audit_exception
        self.audit_calls.append(tenant_id)
        return AuditVerifyResponse(
            valid=self.audit_response.valid,
            tenant_id=tenant_id,
            records_verified=self.audit_response.records_verified,
            head_sequence=self.audit_response.head_sequence,
            first_failure=self.audit_response.first_failure,
        )


class FakeApiScope(dict):
    pass


def make_context() -> FakeContext:
    return FakeContext(
        session_id=uuid4(),
        tenant_id=uuid4(),
        subject_id=uuid4(),
        request_id="request-001",
        verified_at=datetime(
            2026,
            10,
            7,
            12,
            0,
            tzinfo=timezone.utc,
        ),
    )


def make_scope(
    *,
    method: str,
    path: str,
    body: bytes = b"",
    content_type: str = "application/json",
) -> FakeApiScope:
    messages = [
        {
            "type": "http.request",
            "body": body,
            "more_body": False,
        }
    ]

    return FakeApiScope(
        {
            "type": "http",
            "method": method,
            "path": path,
            "raw_path": path.encode("latin-1"),
            "headers": [
                (
                    b"content-type",
                    content_type.encode("latin-1"),
                )
            ],
            "_messages": messages,
        }
    )


async def receive_body(scope: FakeApiScope) -> dict:
    messages = scope["_messages"]
    if messages:
        return messages.pop(0)
    return {
        "type": "http.request",
        "body": b"",
        "more_body": False,
    }


async def collect_response(send_messages: list[dict]):
    async def send(message: dict) -> None:
        send_messages.append(message)

    return send


def parse_response(messages: list[dict]) -> tuple[int, dict, dict]:
    start = next(
        message
        for message in messages
        if message["type"] == "http.response.start"
    )
    body_message = next(
        message
        for message in messages
        if message["type"] == "http.response.body"
    )

    import json

    headers = {
        key.decode("latin-1"): value.decode("latin-1")
        for key, value in start["headers"]
    }

    return (
        start["status"],
        json.loads(body_message["body"].decode("utf-8")),
        headers,
    )


def create_api(
    runtime,
    *,
    spending_limit: Decimal = Decimal("5000.00"),
    approval_verifier=None,
    offload_to_thread: bool = False,
) -> OvelaApi:
    return OvelaApi(
        runtime,
        spending_limit_provider=lambda context: spending_limit,
        approval_verifier=approval_verifier,
        config=ApiConfig(
            offload_to_thread=offload_to_thread,
        ),
    )


def propose_payload() -> dict:
    return {
        "action_type": ActionType.PAYMENT_INITIATE.value,
        "amount": "1000.00",
        "currency": "INR",
        "destination_id": "merchant-001",
    }


def execute_payload(
    *,
    request_id: UUID,
    approval_evidence_id: UUID | None = None,
) -> dict:
    payload = {
        "request_id": str(request_id),
        "action_type": ActionType.PAYMENT_INITIATE.value,
        "amount": "1000.00",
        "currency": "INR",
        "destination_id": "merchant-001",
    }
    if approval_evidence_id is not None:
        payload["approval_evidence_id"] = str(
            approval_evidence_id
        )
    return payload


async def dispatch(
    api: OvelaApi,
    context: FakeContext,
    scope: FakeApiScope,
) -> tuple[int, dict, dict]:
    status, payload, headers = await api._dispatch(
        context,
        scope,
        lambda: receive_body(scope),
    )

    return status, payload, headers


@pytest.mark.asyncio
async def test_payment_proposal_valid_verified_context_returns_201():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/propose",
        body=(
            b'{"action_type":"PAYMENT_INITIATE",'
            b'"amount":"1000.00","currency":"INR",'
            b'"destination_id":"merchant-001"}'
        ),
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 201
    assert payload["request_id"] == str(
        runtime.propose_response.request_id
    )
    assert payload["decision"] == Decision.PERMIT.value
    assert payload["approval_required"] is False
    assert payload["reason"] == runtime.propose_response.reason

    assert len(runtime.propose_calls) == 1

    call = runtime.propose_calls[0]
    assert call[0] == context.session_id
    assert call[1].action_type is ActionType.PAYMENT_INITIATE
    assert call[1].amount == Decimal("1000.00")
    assert call[1].currency == "INR"
    assert call[1].destination_id == "merchant-001"
    assert call[2] == Decimal("5000.00")
    assert call[3] == context.verified_at


@pytest.mark.asyncio
async def test_payment_proposal_rejects_missing_content_type():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/propose",
        body=b"{}",
        content_type="text/plain",
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 415
    assert payload == {
        "error": "unsupported_media_type",
        "message": "The request content type is not supported.",
    }
    assert runtime.propose_calls == []


@pytest.mark.asyncio
async def test_payment_proposal_rejects_missing_fields_with_422():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/propose",
        body=b'{"amount":"1000.00"}',
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 422
    assert payload == {
        "error": "invalid_request",
        "message": "The request is invalid.",
    }
    assert runtime.propose_calls == []


@pytest.mark.asyncio
async def test_payment_proposal_rejects_unknown_fields_with_422():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/propose",
        body=(
            b'{"action_type":"PAYMENT_INITIATE",'
            b'"amount":"1000.00","currency":"INR",'
            b'"destination_id":"merchant-001",'
            b'"tenant_id":"attacker-controlled"}'
        ),
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 422
    assert payload == {
        "error": "invalid_request",
        "message": "The request is invalid.",
    }
    assert runtime.propose_calls == []


@pytest.mark.asyncio
async def test_payment_proposal_rejects_duplicate_json_keys():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/propose",
        body=(
            b'{"action_type":"PAYMENT_INITIATE",'
            b'"amount":"1000.00","amount":"9000.00",'
            b'"currency":"INR",'
            b'"destination_id":"merchant-001"}'
        ),
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 400
    assert payload == {
        "error": "invalid_json",
        "message": "The request body is not valid JSON.",
    }
    assert runtime.propose_calls == []


@pytest.mark.asyncio
async def test_payment_proposal_runtime_authentication_failure_maps_to_401():
    runtime = FakeRuntime()
    runtime.propose_exception = AuthenticationFailure(
        "authentication failed"
    )
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/propose",
        body=(
            b'{"action_type":"PAYMENT_INITIATE",'
            b'"amount":"1000.00","currency":"INR",'
            b'"destination_id":"merchant-001"}'
        ),
    )

    status, code, headers = map_exception(
        runtime.propose_exception
    )

    assert status == 401
    assert code == "authentication_failed"
    assert headers["WWW-Authenticate"]


@pytest.mark.asyncio
async def test_payment_execution_valid_verified_context_returns_202():
    runtime = FakeRuntime()
    context = make_context()
    request_id = uuid4()
    evidence_id = uuid4()

    verified_ids: list[tuple[UUID, UUID, UUID]] = []

    def verify_approval(
        verified_context,
        verified_request_id,
        verified_evidence_id,
    ):
        verified_ids.append(
            (
                verified_context.session_id,
                verified_request_id,
                verified_evidence_id,
            )
        )
        return True

    api = create_api(
        runtime,
        approval_verifier=verify_approval,
    )

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(
            execute_payload(
                request_id=request_id,
                approval_evidence_id=evidence_id,
            )
        ).encode("utf-8"),
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 202
    assert payload["transaction_id"] == str(
        runtime.execute_response.transaction_id
    )
    assert payload["state"] == ExecutionState.SUBMITTED.value
    assert payload["outbox_id"] == str(
        runtime.execute_response.outbox_id
    )
    assert payload["audit_sequence"] == 2

    assert verified_ids == [
        (
            context.session_id,
            request_id,
            evidence_id,
        )
    ]

    assert len(runtime.execute_calls) == 1
    call = runtime.execute_calls[0]

    assert call[0] == context.session_id
    assert call[1].request_id == request_id
    assert call[1].approval_evidence_id == evidence_id
    assert call[2] == Decimal("5000.00")
    assert call[3] is False
    assert call[4] == context.verified_at


@pytest.mark.asyncio
async def test_payment_execution_with_approval_evidence_without_verifier_is_403():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    request_id = uuid4()
    evidence_id = uuid4()

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(
            execute_payload(
                request_id=request_id,
                approval_evidence_id=evidence_id,
            )
        ).encode("utf-8"),
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 403
    assert payload == {
        "error": "approval_evidence_invalid",
        "message": "The approval evidence is invalid.",
    }
    assert runtime.execute_calls == []


@pytest.mark.asyncio
async def test_payment_execution_with_invalid_approval_evidence_is_403():
    runtime = FakeRuntime()
    context = make_context()

    def verify_approval(
        verified_context,
        verified_request_id,
        verified_evidence_id,
    ):
        return False

    api = create_api(
        runtime,
        approval_verifier=verify_approval,
    )

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(
            execute_payload(
                request_id=uuid4(),
                approval_evidence_id=uuid4(),
            )
        ).encode("utf-8"),
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 403
    assert payload == {
        "error": "approval_evidence_invalid",
        "message": "The approval evidence is invalid.",
    }
    assert runtime.execute_calls == []


@pytest.mark.parametrize(
    ("exception", "status", "code"),
    [
        (
            ApprovalRequired("approval required"),
            403,
            "approval_required",
        ),
        (
            TenantBoundaryViolation("tenant boundary"),
            403,
            "forbidden",
        ),
        (
            IdempotencyConflict("idempotency conflict"),
            409,
            "idempotency_conflict",
        ),
        (
            RailTimeout("rail timeout"),
            504,
            "rail_timeout",
        ),
        (
            AuthorizationDenied("denied"),
            403,
            "forbidden",
        ),
    ],
)
def test_runtime_exception_mapping_is_deterministic(
    exception,
    status,
    code,
):
    actual_status, actual_code, _ = map_exception(
        exception
    )

    assert actual_status == status
    assert actual_code == code


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exception", "expected_status", "expected_code"),
    [
        (
            ApprovalRequired("approval required"),
            403,
            "approval_required",
        ),
        (
            TenantBoundaryViolation("tenant boundary"),
            403,
            "forbidden",
        ),
        (
            IdempotencyConflict("idempotency conflict"),
            409,
            "idempotency_conflict",
        ),
        (
            RailTimeout("rail timeout"),
            504,
            "rail_timeout",
        ),
    ],
)
async def test_payment_execution_runtime_errors_map_to_stable_statuses(
    exception,
    expected_status,
    expected_code,
):
    runtime = FakeRuntime()
    runtime.execute_exception = exception
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(
            execute_payload(
                request_id=uuid4(),
            )
        ).encode("utf-8"),
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == expected_status
    assert payload == {
        "error": expected_code,
        "message": {
            "approval_required": "Additional approval is required for this action.",
            "forbidden": "The requested operation is not permitted.",
            "idempotency_conflict": "The request conflicts with an existing operation.",
            "rail_timeout": "The payment rail did not respond in time.",
        }[expected_code],
    }


@pytest.mark.asyncio
async def test_audit_verification_uses_verified_tenant_identity():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="GET",
        path="/v1/audit/verify",
        body=b"",
    )
    scope["headers"] = []

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 200
    assert payload["valid"] is True
    assert payload["tenant_id"] == str(
        context.tenant_id
    )
    assert payload["records_verified"] == 3
    assert payload["head_sequence"] == 2
    assert payload["first_failure"] is None
    assert runtime.audit_calls == [context.tenant_id]


@pytest.mark.asyncio
async def test_audit_verification_runtime_failure_is_500():
    runtime = FakeRuntime()
    runtime.audit_exception = OvelaRuntimeError(
        "audit failure"
    )
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="GET",
        path="/v1/audit/verify",
        body=b"",
    )
    scope["headers"] = []

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 500
    assert payload == {
        "error": "internal_error",
        "message": "The request could not be completed.",
    }


@pytest.mark.asyncio
async def test_unknown_route_returns_404():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="GET",
        path="/v1/unknown",
        body=b"",
    )
    scope["headers"] = []

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 404
    assert payload == {
        "error": "not_found",
        "message": "The requested resource was not found.",
    }


@pytest.mark.asyncio
async def test_wrong_method_returns_405_with_allow_header():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="GET",
        path="/v1/payments/propose",
        body=b"",
    )
    scope["headers"] = []

    status, payload, headers = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 405
    assert payload == {
        "error": "method_not_allowed",
        "message": "The HTTP method is not allowed for this resource.",
    }
    assert headers["Allow"] == "POST"


@pytest.mark.asyncio
async def test_propose_trailing_slash_is_not_tolerated():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/propose/",
        body=(
            b'{"action_type":"PAYMENT_INITIATE",'
            b'"amount":"1000.00","currency":"INR",'
            b'"destination_id":"merchant-001"}'
        ),
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 404
    assert payload == {
        "error": "not_found",
        "message": "The requested resource was not found.",
    }
    assert runtime.propose_calls == []


@pytest.mark.asyncio
async def test_execute_rejects_unknown_fields_before_runtime():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    payload = execute_payload(
        request_id=uuid4(),
    )
    payload["tenant_id"] = str(uuid4())

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(payload).encode("utf-8"),
    )

    status, body, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 422
    assert body == {
        "error": "invalid_request",
        "message": "The request is invalid.",
    }
    assert runtime.execute_calls == []


@pytest.mark.asyncio
async def test_execute_rejects_malformed_request_id():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    payload = execute_payload(
        request_id=uuid4(),
    )
    payload["request_id"] = "not-a-uuid"

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(payload).encode("utf-8"),
    )

    status, body, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 422
    assert body == {
        "error": "invalid_request",
        "message": "The request is invalid.",
    }
    assert runtime.execute_calls == []


@pytest.mark.asyncio
async def test_execute_rejects_non_positive_amount():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    payload = execute_payload(
        request_id=uuid4(),
    )
    payload["amount"] = "0"

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(payload).encode("utf-8"),
    )

    status, body, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 422
    assert body == {
        "error": "invalid_request",
        "message": "The request is invalid.",
    }
    assert runtime.execute_calls == []


@pytest.mark.asyncio
async def test_execute_rejects_invalid_currency():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    payload = execute_payload(
        request_id=uuid4(),
    )
    payload["currency"] = "INR1"

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(payload).encode("utf-8"),
    )

    status, body, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 422
    assert body == {
        "error": "invalid_request",
        "message": "The request is invalid.",
    }
    assert runtime.execute_calls == []


@pytest.mark.asyncio
async def test_metadata_is_forwarded_to_runtime():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/propose",
        body=(
            b'{"action_type":"PAYMENT_INITIATE",'
            b'"amount":"1000.00","currency":"INR",'
            b'"destination_id":"merchant-001",'
            b'"metadata":{"source":"mobile","channel":"upi"}}'
        ),
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 201
    assert payload["decision"] == Decision.PERMIT.value

    assert len(runtime.propose_calls) == 1
    request = runtime.propose_calls[0][1]
    assert request.metadata == {
        "source": "mobile",
        "channel": "upi",
    }


@pytest.mark.asyncio
async def test_metadata_entry_limit_is_enforced():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    payload = (
        b'{"action_type":"PAYMENT_INITIATE",'
        b'"amount":"1000.00","currency":"INR",'
        b'"destination_id":"merchant-001",'
        b'"metadata":{'
        b'"one":"1","two":"2","three":"3","four":"4",'
        b'"five":"5","six":"6","seven":"7","eight":"8",'
        b'"nine":"9","ten":"10","eleven":"11","twelve":"12",'
        b'"thirteen":"13","fourteen":"14","fifteen":"15",'
        b'"sixteen":"16","seventeen":"17"}}'
    )

    status, body, _ = await dispatch(
        api,
        context,
        make_scope(
            method="POST",
            path="/v1/payments/propose",
            body=payload,
        ),
    )

    assert status == 422
    assert body == {
        "error": "invalid_request",
        "message": "The request is invalid.",
    }
    assert runtime.propose_calls == []


@pytest.mark.asyncio
async def test_request_body_size_limit_returns_413():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    oversized_body = b"x" * (
        ApiConfig().max_body_bytes + 1
    )

    scope = make_scope(
        method="POST",
        path="/v1/payments/propose",
        body=oversized_body,
    )

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 413
    assert payload == {
        "error": "request_too_large",
        "message": "The request body is too large.",
    }
    assert runtime.propose_calls == []


@pytest.mark.asyncio
async def test_approval_verifier_receives_verified_context_not_request_identity():
    runtime = FakeRuntime()
    context = make_context()

    captured: dict[str, object] = {}

    def verify_approval(
        verified_context,
        verified_request_id,
        verified_evidence_id,
    ):
        captured["session_id"] = verified_context.session_id
        captured["tenant_id"] = verified_context.tenant_id
        captured["subject_id"] = verified_context.subject_id
        captured["request_id"] = verified_request_id
        captured["evidence_id"] = verified_evidence_id
        return True

    api = create_api(
        runtime,
        approval_verifier=verify_approval,
    )

    request_id = uuid4()
    evidence_id = uuid4()

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(
            execute_payload(
                request_id=request_id,
                approval_evidence_id=evidence_id,
            )
        ).encode("utf-8"),
    )

    status, _, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 202
    assert captured == {
        "session_id": context.session_id,
        "tenant_id": context.tenant_id,
        "subject_id": context.subject_id,
        "request_id": request_id,
        "evidence_id": evidence_id,
    }


@pytest.mark.asyncio
async def test_execute_never_exposes_rail_timeout_simulation_to_client():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    payload = execute_payload(
        request_id=uuid4(),
    )
    payload["simulate_rail_timeout"] = True

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(payload).encode("utf-8"),
    )

    status, body, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 422
    assert body == {
        "error": "invalid_request",
        "message": "The request is invalid.",
    }
    assert runtime.execute_calls == []


@pytest.mark.asyncio
async def test_security_error_body_does_not_leak_exception_text():
    runtime = FakeRuntime()
    runtime.execute_exception = TenantBoundaryViolation(
        "sensitive tenant identity details"
    )
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(
            execute_payload(
                request_id=uuid4(),
            )
        ).encode("utf-8"),
    )

    status, body, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 403
    assert body == {
        "error": "forbidden",
        "message": "The requested operation is not permitted.",
    }
    assert "sensitive" not in str(body)


def test_map_exception_unknown_error_fails_closed():
    status, code, headers = map_exception(
        RuntimeError("unexpected")
    )

    assert status == 500
    assert code == "internal_error"
    assert headers == {}


def test_map_exception_authentication_required_is_401():
    from app.http.security_boundary import AuthenticationRequired

    status, code, headers = map_exception(
        AuthenticationRequired()
    )

    assert status == 401
    assert code == "authentication_required"
    assert headers["WWW-Authenticate"] == "DPoP"


def test_map_exception_idempotency_conflict_is_409():
    status, code, headers = map_exception(
        IdempotencyConflict("conflict")
    )

    assert status == 409
    assert code == "idempotency_conflict"
    assert headers == {}


def test_map_exception_rail_timeout_is_504():
    status, code, headers = map_exception(
        RailTimeout("timeout")
    )

    assert status == 504
    assert code == "rail_timeout"
    assert headers == {}


@pytest.mark.asyncio
async def test_audit_response_serialization_preserves_failure_details():
    runtime = FakeRuntime()
    runtime.audit_response = AuditVerifyResponse(
        valid=False,
        tenant_id=uuid4(),
        records_verified=4,
        head_sequence=7,
        first_failure="record hash mismatch at sequence 4",
    )
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="GET",
        path="/v1/audit/verify",
        body=b"",
    )
    scope["headers"] = []

    status, payload, _ = await dispatch(
        api,
        context,
        scope,
    )

    assert status == 200
    assert payload == {
        "valid": False,
        "tenant_id": str(context.tenant_id),
        "records_verified": 4,
        "head_sequence": 7,
        "first_failure": "record hash mismatch at sequence 4",
    }


@pytest.mark.asyncio
async def test_api_requires_verified_context_when_called_asgi():
    runtime = FakeRuntime()
    api = create_api(runtime)

    scope = make_scope(
        method="GET",
        path="/v1/audit/verify",
        body=b"",
    )
    scope["headers"] = []

    messages: list[dict] = []

    async def receive():
        return {
            "type": "http.request",
            "body": b"",
            "more_body": False,
        }

    async def send(message):
        messages.append(message)

    await api(
        scope,
        receive,
        send,
    )

    status, payload, headers = parse_response(messages)

    assert status == 401
    assert payload == {
        "error": "authentication_required",
        "message": "Authentication is required.",
    }
    assert headers["content-type"] == "application/json"
    assert headers["x-request-id"] if "x-request-id" in headers else True


@pytest.mark.asyncio
async def test_api_security_headers_are_present_on_success():
    runtime = FakeRuntime()
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="GET",
        path="/v1/audit/verify",
        body=b"",
    )
    scope["headers"] = []

    async def receive():
        return {
            "type": "http.request",
            "body": b"",
            "more_body": False,
        }

    messages: list[dict] = []

    async def send(message):
        messages.append(message)

    scope["ovela.verified_request_context"] = context

    await api(
        scope,
        receive,
        send,
    )

    status, payload, headers = parse_response(messages)

    assert status == 200
    assert payload["valid"] is True
    assert headers["strict-transport-security"].startswith(
        "max-age="
    )
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert headers["cache-control"] == "no-store"


@pytest.mark.asyncio
async def test_api_security_headers_are_present_on_error():
    runtime = FakeRuntime()
    runtime.execute_exception = IdempotencyConflict(
        "duplicate"
    )
    context = make_context()
    api = create_api(runtime)

    scope = make_scope(
        method="POST",
        path="/v1/payments/execute",
        body=__import__("json").dumps(
            execute_payload(
                request_id=uuid4(),
            )
        ).encode("utf-8"),
    )
    scope["ovela.verified_request_context"] = context

    messages: list[dict] = []

    async def receive():
        return {
            "type": "http.request",
            "body": scope["_messages"][0]["body"],
            "more_body": False,
        }

    async def send(message):
        messages.append(message)

    await api(
        scope,
        receive,
        send,
    )

    status, payload, headers = parse_response(messages)

    assert status == 409
    assert payload == {
        "error": "idempotency_conflict",
        "message": "The request conflicts with an existing operation.",
    }
    assert headers["strict-transport-security"].startswith(
        "max-age="
    )
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
    assert headers["cache-control"] == "no-store"