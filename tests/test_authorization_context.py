from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from app.authorization_context import (
    AuthorizationContext,
    AuthorizationContextError,
    AuthorizationContextExpired,
    AuthorizationContextInvalid,
    AuthorizationState,
    TrustedAuthorizationContextIssuer,
)


UTC = timezone.utc


def _times() -> tuple[datetime, datetime]:
    issued_at = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
    expires_at = issued_at + timedelta(minutes=5)
    return issued_at, expires_at


def _context(
    *,
    state: AuthorizationState = AuthorizationState.AUTHENTICATED,
) -> AuthorizationContext:
    issued_at, expires_at = _times()

    return AuthorizationContext(
        context_id=uuid4(),
        session_id=uuid4(),
        subject_id=uuid4(),
        state=state,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def test_authorization_state_values_are_explicit() -> None:
    assert AuthorizationState.UNVERIFIED.value == "UNVERIFIED"
    assert AuthorizationState.AUTHENTICATED.value == "AUTHENTICATED"
    assert AuthorizationState.STEP_UP_VERIFIED.value == "STEP_UP_VERIFIED"


def test_authorization_context_accepts_valid_values() -> None:
    context = _context()

    assert context.state is AuthorizationState.AUTHENTICATED
    assert context.permits_authenticated() is True
    assert context.permits_step_up() is False


def test_step_up_context_permits_authenticated_and_step_up() -> None:
    context = _context(
        state=AuthorizationState.STEP_UP_VERIFIED,
    )

    assert context.permits_authenticated() is True
    assert context.permits_step_up() is True


def test_unverified_context_permits_neither_authenticated_nor_step_up() -> None:
    context = _context(
        state=AuthorizationState.UNVERIFIED,
    )

    assert context.permits_authenticated() is False
    assert context.permits_step_up() is False


def test_context_requires_uuid_identifiers() -> None:
    issued_at, expires_at = _times()

    with pytest.raises(TypeError, match="context_id must be a UUID"):
        AuthorizationContext(
            context_id="not-a-uuid",  # type: ignore[arg-type]
            session_id=uuid4(),
            subject_id=uuid4(),
            state=AuthorizationState.AUTHENTICATED,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_context_rejects_invalid_session_id_type() -> None:
    issued_at, expires_at = _times()

    with pytest.raises(TypeError, match="session_id must be a UUID"):
        AuthorizationContext(
            context_id=uuid4(),
            session_id="not-a-uuid",  # type: ignore[arg-type]
            subject_id=uuid4(),
            state=AuthorizationState.AUTHENTICATED,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_context_rejects_invalid_subject_id_type() -> None:
    issued_at, expires_at = _times()

    with pytest.raises(TypeError, match="subject_id must be a UUID"):
        AuthorizationContext(
            context_id=uuid4(),
            session_id=uuid4(),
            subject_id="not-a-uuid",  # type: ignore[arg-type]
            state=AuthorizationState.AUTHENTICATED,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_context_rejects_invalid_state_type() -> None:
    issued_at, expires_at = _times()

    with pytest.raises(TypeError, match="state must be an AuthorizationState"):
        AuthorizationContext(
            context_id=uuid4(),
            session_id=uuid4(),
            subject_id=uuid4(),
            state="AUTHENTICATED",  # type: ignore[arg-type]
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_context_requires_timezone_aware_issued_at() -> None:
    issued_at = datetime(2026, 10, 6, 12, 0)
    expires_at = datetime(2026, 10, 6, 12, 5, tzinfo=UTC)

    with pytest.raises(
        AuthorizationContextInvalid,
        match="issued_at must be timezone-aware",
    ):
        AuthorizationContext(
            context_id=uuid4(),
            session_id=uuid4(),
            subject_id=uuid4(),
            state=AuthorizationState.AUTHENTICATED,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_context_requires_timezone_aware_expires_at() -> None:
    issued_at = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)
    expires_at = datetime(2026, 10, 6, 12, 5)

    with pytest.raises(
        AuthorizationContextInvalid,
        match="expires_at must be timezone-aware",
    ):
        AuthorizationContext(
            context_id=uuid4(),
            session_id=uuid4(),
            subject_id=uuid4(),
            state=AuthorizationState.AUTHENTICATED,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_context_rejects_expiration_before_issue_time() -> None:
    issued_at, _ = _times()
    expires_at = issued_at - timedelta(seconds=1)

    with pytest.raises(
        AuthorizationContextInvalid,
        match="expires_at must be later than issued_at",
    ):
        AuthorizationContext(
            context_id=uuid4(),
            session_id=uuid4(),
            subject_id=uuid4(),
            state=AuthorizationState.AUTHENTICATED,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_context_rejects_expiration_equal_to_issue_time() -> None:
    issued_at, _ = _times()

    with pytest.raises(
        AuthorizationContextInvalid,
        match="expires_at must be later than issued_at",
    ):
        AuthorizationContext(
            context_id=uuid4(),
            session_id=uuid4(),
            subject_id=uuid4(),
            state=AuthorizationState.AUTHENTICATED,
            issued_at=issued_at,
            expires_at=issued_at,
        )


def test_context_is_not_expired_before_expiration() -> None:
    context = _context()

    now = context.issued_at + timedelta(minutes=4)

    assert context.is_expired(now) is False
    context.require_valid_at(now)


def test_context_is_expired_at_exact_expiration() -> None:
    context = _context()

    assert context.is_expired(context.expires_at) is True

    with pytest.raises(
        AuthorizationContextExpired,
        match="authorization context has expired",
    ):
        context.require_valid_at(context.expires_at)


def test_context_is_expired_after_expiration() -> None:
    context = _context()

    now = context.expires_at + timedelta(seconds=1)

    assert context.is_expired(now) is True

    with pytest.raises(
        AuthorizationContextExpired,
        match="authorization context has expired",
    ):
        context.require_valid_at(now)


def test_is_expired_requires_timezone_aware_time() -> None:
    context = _context()

    with pytest.raises(
        AuthorizationContextInvalid,
        match="now must be timezone-aware",
    ):
        context.is_expired(datetime(2026, 10, 6, 12, 1))


def test_is_expired_rejects_non_datetime() -> None:
    context = _context()

    with pytest.raises(TypeError, match="now must be a datetime"):
        context.is_expired("2026-10-06T12:01:00Z")  # type: ignore[arg-type]


def test_issuer_rejects_missing_capability() -> None:
    issued_at, expires_at = _times()

    with pytest.raises(
        PermissionError,
        match="trusted issuer capability is required",
    ):
        TrustedAuthorizationContextIssuer.issue(
            capability=None,  # type: ignore[arg-type]
            session_id=uuid4(),
            subject_id=uuid4(),
            state=AuthorizationState.AUTHENTICATED,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_issuer_rejects_arbitrary_object_as_capability() -> None:
    issued_at, expires_at = _times()

    with pytest.raises(
        PermissionError,
        match="trusted issuer capability is required",
    ):
        TrustedAuthorizationContextIssuer.issue(
            capability=object(),  # type: ignore[arg-type]
            session_id=uuid4(),
            subject_id=uuid4(),
            state=AuthorizationState.AUTHENTICATED,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_issuer_rejects_forged_capability_instance() -> None:
    from app.authorization_context import _IssuerCapability

    issued_at, expires_at = _times()

    forged_capability = _IssuerCapability(nonce=uuid4())

    with pytest.raises(
        PermissionError,
        match="invalid trusted issuer capability",
    ):
        TrustedAuthorizationContextIssuer.issue(
            capability=forged_capability,
            session_id=uuid4(),
            subject_id=uuid4(),
            state=AuthorizationState.AUTHENTICATED,
            issued_at=issued_at,
            expires_at=expires_at,
        )


def test_authorization_context_is_immutable() -> None:
    context = _context()

    with pytest.raises(AttributeError):
        context.state = AuthorizationState.STEP_UP_VERIFIED  # type: ignore[misc]


def test_authorization_context_is_distinct_per_issued_context() -> None:
    first = _context()
    second = _context()

    assert first.context_id != second.context_id
    assert first.session_id != second.session_id
    assert first.subject_id != second.subject_id


def test_base_authorization_context_error_is_security_domain_error() -> None:
    assert issubclass(
        AuthorizationContextExpired,
        AuthorizationContextError,
    )
    assert issubclass(
        AuthorizationContextInvalid,
        AuthorizationContextError,
    )