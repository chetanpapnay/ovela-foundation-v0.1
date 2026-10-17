from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import pytest

from app.financial_account_context import (
    FinancialAccountContext,
    FinancialAccountContextExpired,
    FinancialAccountContextInvalid,
    TrustedFinancialAccountContextIssuer,
    _FinancialAccountContextIssuerCapability,
    _issue_internal_financial_account_context,
)


def _make_valid_context(
    *,
    account_id: UUID | None = None,
    subject_id: UUID | None = None,
    session_id: UUID | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> FinancialAccountContext:
    now = datetime.now(timezone.utc)
    return _issue_internal_financial_account_context(
        account_id=account_id or uuid4(),
        subject_id=subject_id or uuid4(),
        session_id=session_id or uuid4(),
        issued_at=issued_at or now - timedelta(minutes=1),
        expires_at=expires_at or now + timedelta(minutes=10),
    )


def test_valid_context_passes_validation():
    ctx = _make_valid_context()
    now = datetime.now(timezone.utc)
    assert ctx.is_trusted() is True
    ctx.require_trusted()
    assert ctx.is_expired(now) is False
    ctx.require_valid_at(now)


def test_direct_construction_is_never_trusted():
    now = datetime.now(timezone.utc)
    ctx = FinancialAccountContext(
        account_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    assert ctx.is_trusted() is False
    with pytest.raises(FinancialAccountContextInvalid, match="financial account context is not trusted"):
        ctx.require_trusted()
    with pytest.raises(FinancialAccountContextInvalid, match="financial account context is not trusted"):
        ctx.require_valid_at(now)


def test_invalid_issuer_capability_fails():
    fake_cap = _FinancialAccountContextIssuerCapability(object())
    now = datetime.now(timezone.utc)
    with pytest.raises(FinancialAccountContextInvalid):
        TrustedFinancialAccountContextIssuer.issue(
            capability=fake_cap,
            account_id=uuid4(),
            subject_id=uuid4(),
            session_id=uuid4(),
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )


def test_expiry_must_be_later_than_issued_at():
    now = datetime.now(timezone.utc)
    with pytest.raises(FinancialAccountContextInvalid):
        _issue_internal_financial_account_context(
            account_id=uuid4(),
            subject_id=uuid4(),
            session_id=uuid4(),
            issued_at=now,
            expires_at=now - timedelta(seconds=1),
        )


def test_naive_datetimes_are_rejected():
    now_naive = datetime.now()
    now_utc = datetime.now(timezone.utc)
    with pytest.raises(FinancialAccountContextInvalid):
        _issue_internal_financial_account_context(
            account_id=uuid4(),
            subject_id=uuid4(),
            session_id=uuid4(),
            issued_at=now_naive,
            expires_at=now_utc + timedelta(minutes=5),
        )
    with pytest.raises(FinancialAccountContextInvalid):
        _issue_internal_financial_account_context(
            account_id=uuid4(),
            subject_id=uuid4(),
            session_id=uuid4(),
            issued_at=now_utc,
            expires_at=now_naive,
        )


def test_context_expiry_is_checked_in_utc():
    ctx = _issue_internal_financial_account_context(
        account_id=uuid4(),
        subject_id=uuid4(),
        session_id=uuid4(),
        issued_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
        expires_at=datetime(2026, 1, 1, 12, 5, tzinfo=timezone.utc),
    )
    # 18:00 at +05:00 is 13:00 UTC (past 12:05 UTC)
    now_expired = datetime(2026, 1, 1, 18, 0, tzinfo=timezone(timedelta(hours=5)))
    assert ctx.is_expired(now_expired) is True

    # 16:00 at +05:00 is 11:00 UTC (before 12:05 UTC)
    now_valid = datetime(2026, 1, 1, 16, 0, tzinfo=timezone(timedelta(hours=5)))
    assert ctx.is_expired(now_valid) is False


def test_expired_context_fails_validation():
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    ctx = _make_valid_context(
        issued_at=past - timedelta(minutes=10),
        expires_at=past,
    )
    now = datetime.now(timezone.utc)
    assert ctx.is_expired(now) is True
    with pytest.raises(FinancialAccountContextExpired):
        ctx.require_valid_at(now)
