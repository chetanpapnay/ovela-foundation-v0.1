from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import uuid4

import pytest

from app.approval_evidence import (
    ApprovalEvidence,
    ApprovalEvidenceConsumed,
    ApprovalEvidenceExpired,
    ApprovalEvidenceInvalid,
    ApprovalEvidenceRegistry,
    _issue_internal_approval_evidence,
)


def _transaction_values():
    approved_at = datetime.now(timezone.utc)

    return {
        "action_id": uuid4(),
        "session_id": uuid4(),
        "subject_id": uuid4(),
        "destination_id": "DEST-PRIMARY-001",
        "amount": Decimal("1250.00"),
        "currency": "INR",
        "approved_at": approved_at,
        "expires_at": approved_at + timedelta(minutes=5),
    }


def test_trusted_approval_can_be_consumed_once():
    values = _transaction_values()
    approval = _issue_internal_approval_evidence(**values)
    registry = ApprovalEvidenceRegistry()

    registry.consume(
        approval,
        now=values["approved_at"] + timedelta(seconds=1),
    )

    assert registry.is_consumed(approval.approval_id)


def test_second_consumption_is_rejected():
    values = _transaction_values()
    approval = _issue_internal_approval_evidence(**values)
    registry = ApprovalEvidenceRegistry()
    now = values["approved_at"] + timedelta(seconds=1)

    registry.consume(approval, now=now)

    with pytest.raises(ApprovalEvidenceConsumed):
        registry.consume(approval, now=now)


def test_untrusted_approval_cannot_be_consumed():
    values = _transaction_values()
    values["approval_id"] = uuid4()

    approval = ApprovalEvidence(**values)
    registry = ApprovalEvidenceRegistry()

    with pytest.raises(ApprovalEvidenceInvalid):
        registry.consume(
            approval,
            now=values["approved_at"] + timedelta(seconds=1),
        )

    assert not registry.is_consumed(approval.approval_id)


def test_expired_approval_cannot_be_consumed():
    values = _transaction_values()
    approval = _issue_internal_approval_evidence(**values)
    registry = ApprovalEvidenceRegistry()
    expired_now = values["expires_at"] + timedelta(microseconds=1)

    with pytest.raises(ApprovalEvidenceExpired):
        registry.consume(approval, now=expired_now)

    assert not registry.is_consumed(approval.approval_id)


def test_failed_validation_does_not_mark_approval_consumed():
    values = _transaction_values()
    approval = _issue_internal_approval_evidence(**values)
    registry = ApprovalEvidenceRegistry()

    with pytest.raises(ApprovalEvidenceExpired):
        registry.consume(
            approval,
            now=values["expires_at"] + timedelta(seconds=1),
        )

    assert not registry.is_consumed(approval.approval_id)


def test_wrong_object_type_is_rejected():
    registry = ApprovalEvidenceRegistry()

    with pytest.raises(ApprovalEvidenceInvalid):
        registry.consume(
            object(),
            now=datetime.now(timezone.utc),
        )


def test_is_consumed_returns_false_before_consumption():
    values = _transaction_values()
    approval = _issue_internal_approval_evidence(**values)
    registry = ApprovalEvidenceRegistry()

    assert not registry.is_consumed(approval.approval_id)


def test_is_consumed_returns_false_for_unknown_approval():
    registry = ApprovalEvidenceRegistry()

    assert not registry.is_consumed(uuid4())


def test_different_approvals_can_be_consumed_independently():
    first_values = _transaction_values()
    second_values = _transaction_values()

    first = _issue_internal_approval_evidence(**first_values)
    second = _issue_internal_approval_evidence(**second_values)

    registry = ApprovalEvidenceRegistry()

    now = max(
        first_values["approved_at"],
        second_values["approved_at"],
    ) + timedelta(seconds=1)

    registry.consume(first, now=now)
    registry.consume(second, now=now)

    assert registry.is_consumed(first.approval_id)
    assert registry.is_consumed(second.approval_id)


def test_concurrent_consumption_has_exactly_one_winner():
    values = _transaction_values()
    approval = _issue_internal_approval_evidence(**values)
    registry = ApprovalEvidenceRegistry()
    now = values["approved_at"] + timedelta(seconds=1)

    def attempt():
        try:
            registry.consume(approval, now=now)
            return "consumed"
        except ApprovalEvidenceConsumed:
            return "rejected"
        except Exception as exc:
            return type(exc).__name__

    with ThreadPoolExecutor(max_workers=16) as executor:
        results = list(
            executor.map(
                lambda _: attempt(),
                range(32),
            )
        )

    assert results.count("consumed") == 1
    assert results.count("rejected") == 31
    assert registry.is_consumed(approval.approval_id)