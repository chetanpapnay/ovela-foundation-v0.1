from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from uuid import UUID, uuid4

import pytest

from app.approval_evidence import (
    ApprovalEvidence,
    ApprovalEvidenceExpired,
    ApprovalEvidenceInvalid,
    TrustedApprovalEvidenceIssuer,
    _ApprovalIssuerCapability,
    _issue_internal_approval_evidence,
)


def _transaction_values():
    now = datetime.now(timezone.utc)

    return {
        "action_id": uuid4(),
        "session_id": uuid4(),
        "subject_id": uuid4(),
        "destination_id": "DESTINATION-001",
        "amount": Decimal("1250.50"),
        "currency": "INR",
        "approved_at": now,
        "expires_at": now + timedelta(minutes=5),
    }


def test_directly_constructed_approval_evidence_is_not_trusted():
    values = _transaction_values()

    evidence = ApprovalEvidence(
        approval_id=uuid4(),
        **values,
    )

    assert evidence.is_trusted() is False

    with pytest.raises(ApprovalEvidenceInvalid):
        evidence.require_trusted()


def test_internal_issuer_creates_trusted_approval_evidence():
    values = _transaction_values()

    evidence = _issue_internal_approval_evidence(**values)

    assert evidence.is_trusted() is True

    evidence.require_trusted()


def test_fake_issuer_capability_cannot_create_trusted_evidence():
    values = _transaction_values()

    fake_capability = _ApprovalIssuerCapability(
        nonce=uuid4(),
    )

    with pytest.raises(PermissionError):
        TrustedApprovalEvidenceIssuer.issue(
            capability=fake_capability,
            **values,
        )


def test_approval_evidence_matches_exact_transaction():
    values = _transaction_values()

    evidence = _issue_internal_approval_evidence(**values)

    assert evidence.matches_transaction(
        action_id=values["action_id"],
        session_id=values["session_id"],
        subject_id=values["subject_id"],
        destination_id=values["destination_id"],
        amount=values["amount"],
        currency=values["currency"],
    ) is True


@pytest.mark.parametrize(
    "field, replacement",
    [
        ("action_id", uuid4()),
        ("session_id", uuid4()),
        ("subject_id", uuid4()),
        ("destination_id", "DESTINATION-002"),
        ("amount", Decimal("1250.51")),
        ("currency", "USD"),
    ],
)
def test_approval_evidence_rejects_transaction_mutation(
    field,
    replacement,
):
    values = _transaction_values()

    evidence = _issue_internal_approval_evidence(**values)

    candidate = dict(values)
    candidate[field] = replacement

    assert evidence.matches_transaction(
        action_id=candidate["action_id"],
        session_id=candidate["session_id"],
        subject_id=candidate["subject_id"],
        destination_id=candidate["destination_id"],
        amount=candidate["amount"],
        currency=candidate["currency"],
    ) is False


def test_expired_approval_evidence_is_rejected():
    values = _transaction_values()

    now = datetime.now(timezone.utc)

    values["approved_at"] = now - timedelta(minutes=10)
    values["expires_at"] = now - timedelta(minutes=5)

    evidence = _issue_internal_approval_evidence(**values)

    assert evidence.is_expired(now) is True

    with pytest.raises(ApprovalEvidenceExpired):
        evidence.require_valid_at(now)


def test_unexpired_approval_evidence_is_accepted():
    values = _transaction_values()

    now = datetime.now(timezone.utc)

    evidence = _issue_internal_approval_evidence(**values)

    assert evidence.is_expired(now) is False

    evidence.require_valid_at(now)


@pytest.mark.parametrize(
    "amount",
    [
        Decimal("0"),
        Decimal("-1"),
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("-Infinity"),
    ],
)
def test_invalid_amount_is_rejected(amount):
    values = _transaction_values()
    values["amount"] = amount

    with pytest.raises(ApprovalEvidenceInvalid):
        _issue_internal_approval_evidence(**values)


@pytest.mark.parametrize(
    "currency",
    [
        "inr",
        "InR",
        "IN",
        "INRR",
        "123",
        "",
    ],
)
def test_invalid_currency_is_rejected(currency):
    values = _transaction_values()
    values["currency"] = currency

    with pytest.raises(ApprovalEvidenceInvalid):
        _issue_internal_approval_evidence(**values)


def test_blank_destination_is_rejected():
    values = _transaction_values()
    values["destination_id"] = "   "

    with pytest.raises(ApprovalEvidenceInvalid):
        _issue_internal_approval_evidence(**values)


def test_expiration_must_be_after_approval():
    values = _transaction_values()

    values["expires_at"] = values["approved_at"]

    with pytest.raises(ApprovalEvidenceInvalid):
        _issue_internal_approval_evidence(**values)


def test_naive_approval_timestamp_is_rejected():
    values = _transaction_values()

    values["approved_at"] = datetime.now()

    with pytest.raises(ApprovalEvidenceInvalid):
        _issue_internal_approval_evidence(**values)


def test_naive_expiration_timestamp_is_rejected():
    values = _transaction_values()

    values["expires_at"] = datetime.now() + timedelta(minutes=5)

    with pytest.raises(ApprovalEvidenceInvalid):
        _issue_internal_approval_evidence(**values)


def test_wrong_types_are_rejected():
    values = _transaction_values()

    values["action_id"] = "not-a-uuid"

    with pytest.raises(TypeError):
        _issue_internal_approval_evidence(**values)


def test_approval_evidence_is_immutable():
    values = _transaction_values()

    evidence = _issue_internal_approval_evidence(**values)

    with pytest.raises(AttributeError):
        evidence.destination_id = "ATTACKER-DESTINATION"